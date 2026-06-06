import type {
  ActivityHistory,
  AgentConfig,
  AgentRun,
  AuditRecent,
  BeadsIssue,
  ChatMessage,
  ConfigPayload,
  EngagementHistoryItem,
  EngagementReport,
  EngagementStatus,
  GoalState,
  HitlPayload,
  IntelSearchResult,
  KnowledgeSearchResult,
  PlaybookRunResult,
  PlaybookSummary,
  SkillSummary,
  TargetDetail,
  TargetSummary,
  NotesWorkspace,
  RuntimeStatus,
  ScheduledJob,
  SetupStatus,
  SlashCommand,
  Subagent,
  ToolEvent,
  WorkflowRunResult,
  WorkflowSummary,
} from "./types";

type RequestOptions = Omit<RequestInit, "body"> & {
  body?: unknown;
};

// A2A 1.0 streams proto-JSON frames: each `result` carries exactly one of the
// `task` / `statusUpdate` / `artifactUpdate` wrappers. Proto-JSON omits the
// part `kind` discriminator — text parts have `.text`, data parts have `.data`
// plus `.metadata.mimeType` — and uses `TASK_STATE_*` enum strings for state.
type A2APart = {
  text?: string;
  data?: unknown;
  metadata?: { mimeType?: string };
};

type A2AFrame = {
  jsonrpc?: string;
  id?: string;
  result?: {
    task?: {
      id?: string;
      contextId?: string;
      status?: { state?: string };
      artifacts?: Array<{ parts?: A2APart[] }>;
    };
    statusUpdate?: {
      taskId?: string;
      contextId?: string;
      status?: { state?: string; message?: { parts?: A2APart[] } };
    };
    artifactUpdate?: {
      taskId?: string;
      artifact?: { parts?: A2APart[] };
      append?: boolean;
      lastChunk?: boolean;
    };
  };
  error?: {
    message?: string;
  };
};

// Terminal task states — when a status-update arrives in one of these, the turn
// is over (mirrors the v0.3 `final` flag the SDK no longer sends per-frame).
const A2A_TERMINAL_STATES = new Set([
  "TASK_STATE_COMPLETED",
  "TASK_STATE_FAILED",
  "TASK_STATE_CANCELLED",
  "TASK_STATE_CANCELED",
  "TASK_STATE_REJECTED",
]);

/** "TASK_STATE_WORKING" → "working" for human-facing status text. */
function humanizeState(state?: string): string {
  return (state || "").replace(/^TASK_STATE_/, "").toLowerCase();
}

const OPERATOR_KEY_STORAGE = "protopen.operatorKey";

/** Thrown when an operator API call returns 401 — drives the login gate. */
export class UnauthorizedError extends Error {
  constructor() {
    super("Unauthorized");
    this.name = "UnauthorizedError";
  }
}

export function getOperatorKey(): string {
  if (typeof window === "undefined") return "";
  try {
    return window.localStorage.getItem(OPERATOR_KEY_STORAGE) || "";
  } catch {
    return "";
  }
}

export function setOperatorKey(key: string): void {
  if (typeof window === "undefined") return;
  try {
    if (key) window.localStorage.setItem(OPERATOR_KEY_STORAGE, key);
    else window.localStorage.removeItem(OPERATOR_KEY_STORAGE);
  } catch {
    /* ignore */
  }
}

function defaultApiBase() {
  if (typeof window === "undefined") return "";
  let savedBase = "";
  try {
    savedBase =
      window.localStorage.getItem("protopen.apiBase") ||
      window.localStorage.getItem("protoagent.apiBase") ||
      "";
  } catch {
    savedBase = "";
  }
  if (savedBase) return savedBase.replace(/\/$/, "");

  const { hostname, protocol } = window.location;
  if (protocol === "tauri:" || protocol === "file:" || hostname === "tauri.localhost") {
    return "http://127.0.0.1:7870";
  }
  return "";
}

export function apiUrl(path: string) {
  if (/^https?:\/\//.test(path)) return path;
  const base = defaultApiBase();
  return base ? `${base}${path.startsWith("/") ? path : `/${path}`}` : path;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers = new Headers(options.headers);
  const operatorKey = getOperatorKey();
  if (operatorKey) headers.set("x-api-key", operatorKey);
  let body: BodyInit | undefined;
  if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(options.body);
  }

  const response = await fetch(apiUrl(path), {
    ...options,
    headers,
    body,
  });

  if (!response.ok) {
    if (response.status === 401) throw new UnauthorizedError();
    let detail = `${response.status} ${response.statusText}`;
    try {
      const payload = (await response.json()) as { detail?: string };
      detail = payload.detail || detail;
    } catch {
      detail = await response.text();
    }
    throw new Error(detail || "request failed");
  }

  return (await response.json()) as T;
}

function textFromParts(parts?: A2APart[]) {
  return (parts || [])
    .filter((part) => part.text)
    .map((part) => part.text)
    .join("");
}

// Shared with the backend (a2a_handler.py TOOL_CALL_MIME).
const TOOL_CALL_MIME = "application/vnd.protolabs.tool-call-v1+json";

/**
 * Pull a structured tool event off a frame's parts and map the A2A 1.0 wire
 * payload ({toolCallId, name, phase: "started"|"completed", args, result}) onto
 * the frontend ToolEvent ({id, name, phase: "start"|"end", input, output}).
 */
function toolEventFromParts(parts?: A2APart[]): ToolEvent | null {
  const part = (parts || []).find(
    (p) => p.metadata?.mimeType === TOOL_CALL_MIME && p.data,
  );
  if (!part) return null;
  const d = part.data as {
    toolCallId?: string;
    name?: string;
    phase?: string;
    args?: string;
    result?: string;
  };
  return {
    id: d.toolCallId || "",
    name: d.name || "",
    phase: d.phase === "started" ? "start" : "end",
    input: d.args,
    output: d.result,
  };
}

// Shared with the backend (a2a_executor.py HITL_MIME). An input-required frame
// carries the form/approval/question payload on a part with this mime type.
const HITL_MIME = "application/vnd.protolabs.hitl-v1+json";

/** Pull the HITL form/approval/question payload off an input-required frame's
 *  parts. Returns null when no hitl-v1 DataPart is present (older agents fall
 *  back to the frame's text). */
function hitlFromParts(parts?: A2APart[]): HitlPayload | null {
  const part = (parts || []).find((p) => p.metadata?.mimeType === HITL_MIME && p.data);
  return part ? ((part.data as HitlPayload) ?? null) : null;
}

function textFromTerminalTask(task?: NonNullable<A2AFrame["result"]>["task"]) {
  return (task?.artifacts || [])
    .flatMap((artifact) => artifact.parts || [])
    .filter((part) => part.text)
    .map((part) => part.text)
    .join("");
}

// Watchdog for a stream that goes silent. NOTE: a slow reasoning turn legitimately
// produces NO frame for a while — tool calls finish, then the model spends 60–120s+
// generating the final report before the artifact frame arrives. So this must be
// generous (a too-tight value killed the stream mid-generation → blank message),
// and on firing we fall back to a buffered read rather than failing the turn.
const SSE_IDLE_TIMEOUT_MS = 180_000;

/** Parse every complete blank-line-delimited SSE event out of `buffer`; returns
 *  the unparsed remainder. Shared by the streaming and buffered-fallback paths.
 *
 *  The event boundary's line ending VARIES: the a2a-sdk emits CRLF
 *  (`\r\n\r\n`); the SSE spec also allows LF (`\n\n`) or CR (`\r\r`). Scanning
 *  for `\n\n` only — what we used to do — never matched the CRLF stream, so the
 *  browser parsed zero frames and chat rendered a blank bubble (the agent had
 *  replied). Match any blank-line boundary, and split data lines on any line
 *  ending. Ported from protoAgent #563. */
function drainSseBuffer(buffer: string, onFrame: (frame: A2AFrame) => void): string {
  const BOUNDARY = /\r\n\r\n|\n\n|\r\r/;
  let match = BOUNDARY.exec(buffer);
  while (match) {
    const rawEvent = buffer.slice(0, match.index);
    buffer = buffer.slice(match.index + match[0].length);
    match = BOUNDARY.exec(buffer);

    const data = rawEvent
      .split(/\r\n|\r|\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .join("\n");
    if (!data) continue;
    onFrame(JSON.parse(data) as A2AFrame);
  }
  return buffer;
}

async function consumeBuffered(response: Response, onFrame: (frame: A2AFrame) => void): Promise<void> {
  // Await the whole body, then parse every frame at once. Loses token-by-token
  // streaming but always renders the turn — the fallback for environments/turns
  // where the readable stream yields nothing incrementally (proxy/Tailscale
  // buffering, a reader that completes empty, or the watchdog firing before the
  // first frame on a slow reasoning turn). Ported from protoAgent #499.
  const text = await response.text();
  drainSseBuffer(text.endsWith("\n\n") ? text : `${text}\n\n`, onFrame);
}

async function consumeSse(
  response: Response,
  onFrame: (frame: A2AFrame) => void,
  idleTimeoutMs: number = SSE_IDLE_TIMEOUT_MS,
): Promise<void> {
  // Clone up front so we can fall back to a buffered read of the full body when
  // incremental streaming surfaces nothing — the cause of a blank assistant
  // message (the agent replied, but the SSE never rendered a frame). The clone
  // keeps its own body once we lock the original via getReader().
  let fallback: Response | null = null;
  try {
    fallback = response.clone();
  } catch {
    fallback = null;
  }

  const reader = response.body?.getReader();
  if (!reader) return consumeBuffered(fallback ?? response, onFrame);

  const decoder = new TextDecoder();
  let buffer = "";
  let streamed = false;

  try {
    while (true) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const idle = new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`stream stalled — no data for ${Math.round(idleTimeoutMs / 1000)}s`)),
          idleTimeoutMs,
        );
      });
      const readPromise = reader.read();
      // If the idle watchdog wins the race, this read is orphaned and may later
      // reject (once we cancel the reader). Mark it handled to avoid an
      // unhandled-rejection warning.
      void readPromise.catch(() => {});
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        chunk = await Promise.race([readPromise, idle]);
      } finally {
        if (timer) clearTimeout(timer);
      }

      const { value, done } = chunk;
      if (done) break;
      streamed = true;
      buffer += decoder.decode(value, { stream: true });
      buffer = drainSseBuffer(buffer, onFrame);
    }
  } catch (err) {
    // The reader threw or the idle watchdog fired. This includes the common,
    // non-fatal case of a slow reasoning turn going quiet between the last tool
    // and the final report (a >watchdog gap). Don't lose the turn: if we have a
    // clone, read the full body buffered — it resolves when the turn completes
    // and carries every frame (incl. the final artifact). Re-emitting already-
    // seen frames is idempotent (tool cards keyed by id; text replaces). Only a
    // fallback-less failure is fatal.
    await reader.cancel().catch(() => {});
    if (!fallback) throw err;
    return consumeBuffered(fallback, onFrame);
  }

  // Release the original reader, then — if it completed without surfacing any
  // frame — render via the buffered fallback so the turn isn't silently lost.
  await reader.cancel().catch(() => {});
  if (!streamed && fallback) {
    return consumeBuffered(fallback, onFrame);
  }
}

export const api = {
  runtimeStatus() {
    return request<RuntimeStatus>("/api/runtime/status");
  },

  chatCommands() {
    return request<{ commands: SlashCommand[] }>("/api/chat/commands");
  },

  activity() {
    return request<ActivityHistory>("/api/activity");
  },

  workflows() {
    return request<{ workflows: WorkflowSummary[] }>("/api/workflows");
  },

  runWorkflow(name: string, inputs: Record<string, unknown>) {
    return request<WorkflowRunResult>(`/api/workflows/${encodeURIComponent(name)}/run`, {
      method: "POST",
      body: { inputs },
    });
  },

  goals() {
    return request<{ enabled: boolean; goals: GoalState[] }>("/api/goals");
  },

  clearGoal(sessionId: string) {
    return request<{ cleared: boolean }>(`/api/goal/${encodeURIComponent(sessionId)}`, { method: "DELETE" });
  },

  playbooks() {
    return request<{ count: number; playbooks: PlaybookSummary[] }>("/api/playbooks");
  },

  runPlaybook(name: string, variables: Record<string, string>) {
    return request<PlaybookRunResult>(`/api/playbooks/${encodeURIComponent(name)}/run`, {
      method: "POST",
      body: { variables },
    });
  },

  setupStatus() {
    return request<SetupStatus>("/api/config/setup-status");
  },

  config() {
    return request<ConfigPayload>("/api/config");
  },

  soulPreset(name: string) {
    return request<{ name: string; content: string }>(`/api/config/presets/${encodeURIComponent(name)}`);
  },

  models(apiBase: string, apiKey: string) {
    return request<{ models: string[]; error: string }>("/api/config/models", {
      method: "POST",
      body: { api_base: apiBase, api_key: apiKey },
    });
  },

  finishSetup(config: Partial<AgentConfig>, soul: string) {
    return request<{ ok: boolean; message: string }>("/api/config/setup", {
      method: "POST",
      body: { config, soul },
    });
  },

  subagents() {
    return request<{ subagents: Subagent[] }>("/api/subagents");
  },

  engagement() {
    return request<EngagementStatus>("/api/engagement");
  },

  engagementReport() {
    return request<EngagementReport>("/api/engagement/report");
  },

  generateEngagementReport() {
    return request<EngagementReport>("/api/engagement/report", { method: "POST" });
  },

  knowledgeSearch(query: string, options: { k?: number; table?: string } = {}) {
    const params = new URLSearchParams({ q: query });
    if (options.k) params.set("k", String(options.k));
    if (options.table) params.set("table", options.table);
    return request<KnowledgeSearchResult>(`/api/knowledge/search?${params}`);
  },

  targets(options: { q?: string; deviceType?: string; limit?: number } = {}) {
    const params = new URLSearchParams();
    if (options.q) params.set("q", options.q);
    if (options.deviceType) params.set("device_type", options.deviceType);
    if (options.limit) params.set("limit", String(options.limit));
    const qs = params.toString();
    return request<{ query: string; count: number; targets: TargetSummary[] }>(
      `/api/targets${qs ? `?${qs}` : ""}`,
    );
  },

  target(hostId: number) {
    return request<TargetDetail>(`/api/targets/${encodeURIComponent(String(hostId))}`);
  },

  skills(query = "") {
    const qs = query ? `?q=${encodeURIComponent(query)}` : "";
    return request<{ enabled: boolean; count: number; skills: SkillSummary[] }>(`/api/skills${qs}`);
  },

  engagementsHistory() {
    return request<{ count: number; engagements: EngagementHistoryItem[] }>("/api/engagements");
  },

  intelSearch(query: string, options: { k?: number } = {}) {
    const params = new URLSearchParams({ q: query });
    if (options.k) params.set("k", String(options.k));
    return request<IntelSearchResult>(`/api/intel/search?${params}`);
  },

  schedulerJobs() {
    return request<{ jobs: ScheduledJob[]; backend: string }>("/api/scheduler/jobs");
  },

  addSchedule(body: { prompt: string; schedule: string; job_id?: string }) {
    return request<{ job: ScheduledJob }>("/api/scheduler/jobs", { method: "POST", body });
  },

  cancelSchedule(jobId: string) {
    return request<{ canceled: boolean }>(`/api/scheduler/jobs/${encodeURIComponent(jobId)}`, { method: "DELETE" });
  },

  auditRecent(options: { n?: number; sessionId?: string } = {}) {
    const params = new URLSearchParams();
    if (options.n) params.set("n", String(options.n));
    if (options.sessionId) params.set("session_id", options.sessionId);
    const qs = params.toString();
    return request<AuditRecent>(`/api/audit/recent${qs ? `?${qs}` : ""}`);
  },

  runSubagent(body: {
    session_id: string;
    type: string;
    description: string;
    prompt: string;
    emit_skill: boolean;
  }) {
    return request<{ ok: boolean; session_id: string; output: string }>("/api/subagents/run", {
      method: "POST",
      body,
    });
  },

  runSubagentBatch(body: {
    session_id: string;
    tasks: Array<{
      type?: string;
      subagent_type?: string;
      description: string;
      prompt: string;
      emit_skill: boolean;
    }>;
  }) {
    return request<{ ok: boolean; session_id: string; output: string }>("/api/subagents/batch", {
      method: "POST",
      body,
    });
  },

  launchAgent(body: { session_id: string; type: string; description: string; prompt: string; emit_skill: boolean }) {
    return request<{ task_id: string }>("/api/agents/launch", { method: "POST", body });
  },

  listAgents() {
    return request<{ agents: AgentRun[] }>("/api/agents");
  },

  cancelAgent(id: string) {
    return request<{ cancelled: boolean }>(`/api/agents/${encodeURIComponent(id)}/cancel`, { method: "POST" });
  },

  chat(message: string, sessionId: string) {
    return request<{ response: string; messages: ChatMessage[] }>("/api/chat", {
      method: "POST",
      body: { message, session_id: sessionId },
    });
  },

  async streamChat(
    message: string,
    sessionId: string,
    handlers: {
      signal?: AbortSignal;
      onTaskId?: (taskId: string) => void;
      onStatus?: (status: string) => void;
      onText?: (text: string, append: boolean) => void;
      onToolCall?: (evt: ToolEvent) => void;
      onInputRequired?: (payload: HitlPayload) => void;
      onDone?: () => void;
    } = {},
  ) {
    const rpcId = `web-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const messageId = `msg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    // A2A 1.0 native JSON-RPC: the `A2A-Version` header selects the 1.0 handler
    // (absent ⇒ the SDK assumes v0.3 and rejects us), the method is the proto
    // RPC name, and `contextId` lives inside the message (= our session id, so
    // the agent's checkpointer threads multi-turn memory).
    const streamHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "text/event-stream",
      "A2A-Version": "1.0",
    };
    const operatorKey = getOperatorKey();
    if (operatorKey) streamHeaders["x-api-key"] = operatorKey;
    const response = await fetch(apiUrl("/a2a"), {
      method: "POST",
      headers: streamHeaders,
      signal: handlers.signal,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: rpcId,
        method: "SendStreamingMessage",
        params: {
          message: {
            messageId,
            contextId: sessionId,
            role: "ROLE_USER",
            parts: [{ text: message }],
            // The console can answer a HITL pause, so opt into interactivity:
            // the agent's request_user_input / request_approval may park the turn
            // as input-required. Headless/API callers omit this and stay autonomous.
            metadata: { "protolabs.interactive": true },
          },
        },
      }),
    });

    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }

    await consumeSse(response, (frame) => {
      if (frame.error?.message) throw new Error(frame.error.message);
      const result = frame.result;
      if (!result) return;

      // First frame: the freshly-created task (state SUBMITTED).
      if (result.task?.id) {
        handlers.onTaskId?.(result.task.id);
        const terminalText = textFromTerminalTask(result.task);
        if (terminalText) handlers.onText?.(terminalText, false);
      }

      // Status updates carry working/terminal state, status text, and the
      // structured tool-call DataParts that drive the live tool cards.
      if (result.statusUpdate) {
        const su = result.statusUpdate;
        const state = su.status?.state || "";
        const messageText = textFromParts(su.status?.message?.parts);
        handlers.onStatus?.(messageText || humanizeState(state));
        const toolEvent = toolEventFromParts(su.status?.message?.parts);
        if (toolEvent) handlers.onToolCall?.(toolEvent);
        // HITL pause: the turn parked awaiting the operator (TASK_STATE_INPUT_REQUIRED).
        // Surface the form/approval/question so the console can render it and
        // resume; non-terminal, so the stream closes here without onDone.
        if (state === "TASK_STATE_INPUT_REQUIRED") {
          handlers.onInputRequired?.(hitlFromParts(su.status?.message?.parts) || { question: messageText });
        }
        if (A2A_TERMINAL_STATES.has(state)) handlers.onDone?.();
      }

      // Artifact updates stream the assistant's text output. `append` is false
      // on the first chunk (replace) and true on continuations (concatenate).
      if (result.artifactUpdate) {
        const au = result.artifactUpdate;
        const text = textFromParts(au.artifact?.parts);
        if (text) handlers.onText?.(text, au.append === true);
        if (au.lastChunk) handlers.onDone?.();
      }
    });
  },

  cancelTask(taskId: string) {
    return request<{ result?: unknown; error?: unknown }>("/a2a", {
      method: "POST",
      headers: { "A2A-Version": "1.0" },
      body: {
        jsonrpc: "2.0",
        id: `cancel-${Date.now()}`,
        method: "CancelTask",
        params: { id: taskId },
      },
    });
  },

  getNotes(projectPath: string) {
    const params = new URLSearchParams({ project_path: projectPath });
    return request<{ workspace: NotesWorkspace }>(`/api/notes/workspace?${params}`);
  },

  saveNotes(projectPath: string, workspace: NotesWorkspace) {
    return request<{ ok: boolean }>("/api/notes/workspace", {
      method: "POST",
      body: { project_path: projectPath, workspace },
    });
  },

  beadsStatus(projectPath: string) {
    const params = new URLSearchParams({ project_path: projectPath });
    return request<{ initialized: boolean }>(`/api/beads/status?${params}`);
  },

  initBeads(projectPath: string) {
    return request<{ initialized: boolean; already_initialized?: boolean }>("/api/beads/init", {
      method: "POST",
      body: { project_path: projectPath },
    });
  },

  beadsIssues(projectPath: string) {
    const params = new URLSearchParams({ project_path: projectPath });
    return request<{ issues: BeadsIssue[] }>(`/api/beads/issues?${params}`);
  },

  createIssue(
    projectPath: string,
    issue: {
      title: string;
      type?: string;
      priority?: number;
      description?: string;
      assignee?: string;
    },
  ) {
    return request<{ issue: BeadsIssue }>("/api/beads/issues", {
      method: "POST",
      body: { project_path: projectPath, ...issue },
    });
  },

  updateIssue(
    projectPath: string,
    issueId: string,
    update: {
      title?: string;
      description?: string;
      status?: string;
      priority?: number;
      type?: string;
      assignee?: string;
    },
  ) {
    return request<{ issue: BeadsIssue }>(`/api/beads/issues/${encodeURIComponent(issueId)}`, {
      method: "PATCH",
      body: { project_path: projectPath, ...update },
    });
  },

  closeIssue(projectPath: string, issueId: string, reason?: string) {
    return request<{ issue: BeadsIssue }>(`/api/beads/issues/${encodeURIComponent(issueId)}/close`, {
      method: "POST",
      body: { project_path: projectPath, reason },
    });
  },

  deleteIssue(projectPath: string, issueId: string) {
    const params = new URLSearchParams({ project_path: projectPath });
    return request<{ deleted?: string; project_path?: string }>(
      `/api/beads/issues/${encodeURIComponent(issueId)}?${params}`,
      { method: "DELETE" },
    );
  },
};
