export type RuntimeStatus = {
  setup_complete: boolean;
  graph_loaded: boolean;
  model: null | {
    provider: string;
    name: string;
    api_base: string;
    api_key_configured: boolean;
    temperature: number | null;
    max_tokens: number | null;
    max_iterations: number | null;
  };
  identity: null | {
    name: string;
    operator: string;
  };
  middleware: Record<string, boolean>;
  knowledge: {
    enabled: boolean;
    configured_path: string | null;
    resolved_path: string | null;
    top_k?: number | null;
  };
  scheduler: {
    enabled: boolean;
    backend: string;
  };
  goal: {
    enabled: boolean;
    controller_loaded: boolean;
    max_iterations?: number | null;
  };
  cache_warmer: {
    enabled: boolean;
    loaded: boolean;
    interval_seconds?: number | null;
  };
  skills?: {
    enabled: boolean;
    count: number;
  };
};

export type Subagent = {
  name: string;
  description: string;
  enabled: boolean;
  tools: string[];
  default_tools: string[];
  max_turns: number;
  default_max_turns: number;
  allow_skill_emission: boolean;
};

export type EngagementFinding = {
  severity: string;
  category: string;
  title: string;
  detail?: string;
  timestamp?: string;
};

export type EngagementReport = {
  available: boolean;
  name: string;
  path: string;
  markdown: string;
};

export type EngagementStatus = {
  active: boolean;
  name: string;
  scope: string;
  mode: string;
  phase: string;
  started_at?: string;
  finding_counts: Record<string, number>;
  total_findings: number;
  findings: EngagementFinding[];
};

/** Knowledge-store tables exposed as search filters — mirrors
 * operator_api/knowledge.py KNOWLEDGE_TABLES (frontend source of truth). */
export const KNOWLEDGE_TABLES = [
  "cves",
  "exploits",
  "advisories",
  "threat_intel",
  "topics",
  "digests",
] as const;

export type KnowledgeHit = {
  table: string;
  source_id: string;
  preview: string;
  score: number;
};

export type KnowledgeSearchResult = {
  query: string;
  table: string | null;
  count: number;
  hits: KnowledgeHit[];
};

export type AgentRun = {
  id: string;
  type: string;
  description: string;
  status: "running" | "done" | "error" | "cancelled";
  started_at: string;
  ended_at: string;
  duration_ms: number;
  output: string;
  error: string;
};

export type ScheduledJob = {
  id: string;
  prompt: string;
  schedule: string;
  next_fire?: string | null;
  last_fire?: string | null;
  agent_name?: string;
  enabled?: boolean;
  created_at?: string;
};

export type AuditEntry = {
  ts: string;
  session_id: string;
  tool: string;
  success: boolean;
  duration_ms: number;
  result_summary: string;
  trace_id: string;
  args: Record<string, unknown>;
};

export type AuditRecent = {
  count: number;
  entries: AuditEntry[];
  summary: { total: number; successes: number; failures: number };
};

export type ToolCall = {
  id: string;
  name: string;
  input?: string;
  output?: string;
  status: "running" | "done" | "error";
  /** Client wall-clock when the start frame arrived (ms epoch). */
  startedAt?: number;
  /** Elapsed start→end, stamped client-side when the end frame arrives. */
  durationMs?: number;
  /** id of the enclosing `task` tool, if this call ran inside a subagent. */
  parentId?: string;
};

/** Wire shape of a single tool event streamed over the A2A tool-call DataPart. */
export type ToolEvent = {
  id: string;
  name: string;
  phase: "start" | "end";
  input?: string;
  output?: string;
};

export type ChatMessage = {
  id?: string;
  role: "user" | "assistant" | "system";
  content: string;
  toolCalls?: ToolCall[];
  createdAt?: number;
  status?: "streaming" | "done" | "error";
};

export type SlashCommand = {
  name: string;
  description: string;
  usage: string;
};

// HITL (human-in-the-loop) request surfaced when a turn pauses as input-required.
// The backend (a2a_executor.py) parks the task in TASK_STATE_INPUT_REQUIRED and
// rides the payload on a `hitl-v1` DataPart — a form (request_user_input), an
// Approve/Deny gate (run_command), or a free-text question (ask_human). The
// console renders it and resumes by sending the response as a follow-up on the
// same session.
//
// A form's `steps` are a flat list of fields — one field per step,
// `{id, label, type, ...}` — per protoPen's contract (see test_a2a_handler.py:
// `steps: [{id, label, type}]`). NOT protoAgent's JSON-schema-per-step shape.
export type HitlFormStep = {
  id: string;
  label?: string;
  type?: string; // "string" | "number" | "integer" | "boolean" | "textarea"
  enum?: unknown[];
  required?: boolean;
  description?: string;
  default?: unknown;
};

export type HitlPayload = {
  kind?: "form" | "approval" | "question";
  title?: string;
  description?: string;
  steps?: HitlFormStep[]; // form shape — one field per step
  question?: string; // free-text (ask_human) shape
  detail?: string; // approval shape — the command/action being approved
};

export type NotesWorkspace = {
  version: number;
  workspaceVersion: number;
  activeTabId: string;
  tabOrder: string[];
  tabs: Record<
    string,
    {
      id: string;
      name: string;
      content: string;
      permissions: {
        agentRead: boolean;
        agentWrite: boolean;
      };
      metadata: Record<string, unknown>;
    }
  >;
};

export type BeadsIssue = {
  id: string;
  title: string;
  status?: string;
  description?: string;
  priority?: number | string;
  issue_type?: string;
  type?: string;
  assignee?: string;
};

export type AgentConfig = {
  model: {
    provider: string;
    name: string;
    api_base: string;
    api_key?: string;
    temperature: number;
    max_tokens: number;
    max_iterations: number;
  };
  subagents: {
    researcher: {
      enabled: boolean;
      tools: string[];
      max_turns: number;
    };
  };
  middleware: {
    knowledge: boolean;
    audit: boolean;
    memory: boolean;
    scheduler: boolean;
  };
  knowledge: {
    db_path: string;
    embed_model: string;
    top_k: number;
  };
  identity: {
    name: string;
    operator: string;
  };
  auth: {
    token: string;
  };
  runtime: {
    autostart_on_boot: boolean;
  };
};

export type ConfigPayload = {
  config: AgentConfig;
  soul: string;
};

export type SetupStatus = {
  setup_complete: boolean;
  presets: string[];
};

// Durable Activity thread (ADR 0003) — agent-initiated turns land here.
export type ActivityMessage = { role: "user" | "assistant"; content: string };

export type ActivityHistory = {
  context_id: string;
  messages: ActivityMessage[];
};

// Targets & Intel surface — browse captured hosts, engagements, search intel.
export type TargetSummary = {
  id: number;
  ip: string;
  mac: string;
  hostname: string;
  os: string;
  vendor: string;
  device_type: string;
  tags: string[];
  first_seen: string;
  last_seen: string;
  port_count: number;
  open_ports: string[];
  finding_count: number;
};

export type TargetPort = {
  port: number;
  protocol: string;
  state: string;
  service: string;
  banner: string;
  last_seen: string;
};

export type TargetFinding = {
  tool: string;
  category: string;
  severity: string;
  title: string;
  value: string;
  first_seen: string;
};

export type TargetCredential = {
  username: string;
  hash_type: string;
  cracked: boolean;
  has_secret: boolean;
  source: string;
  first_seen: string;
};

export type TargetDetail = TargetSummary & {
  notes: string;
  ports: TargetPort[];
  findings: TargetFinding[];
  credentials: TargetCredential[];
};

export type EngagementHistoryItem = {
  name: string;
  scope: string;
  mode: string;
  started_at: string;
  ended_at: string;
  finding_count: number;
  finding_counts: Record<string, number>;
  active: boolean;
};

export type IntelHit = {
  kind: string;
  source: string;
  id: string;
  title: string;
  target: string;
  preview: string;
  score: number;
};

export type IntelSearchResult = {
  query: string;
  count: number;
  hits: IntelHit[];
};

// Goals — the autonomy layer (loop the agent toward a verifier).
export type GoalState = {
  session_id: string;
  condition: string;
  verifier: Record<string, unknown>;
  status: string; // active | achieved | exhausted | unachievable
  iteration: number;
  max_iterations: number;
  last_reason: string;
  checklist?: string;
};

// Skills — retrieved methodology memory (SKILL.md + agent-emitted).
export type SkillSummary = {
  name: string;
  description: string;
  tools: string[];
  source: string; // "disk" | "emitted"
};

// Playbooks — declarative tool-chain recipes (playbooks/library/*.yaml).
export type PlaybookStepInfo = { name: string; tool: string; action: string };

export type PlaybookSummary = {
  name: string;
  description: string;
  tags: string[];
  mode: "passive" | "active" | "redteam";
  requires_engagement: boolean;
  variables: Record<string, string>;
  steps: PlaybookStepInfo[];
};

export type PlaybookRunStep = {
  name: string;
  tool: string;
  action: string;
  params: Record<string, unknown>;
  status: string;
  output: string;
  error: string;
};

export type PlaybookRunResult = {
  name: string;
  description: string;
  progress: string;
  completed: boolean;
  failed: boolean;
  steps: PlaybookRunStep[];
};

// Declarative subagent workflows (ADR 0002).
export type WorkflowSummary = {
  name: string;
  description: string;
  inputs: { name: string; required: boolean; default?: unknown }[];
  steps: { id: string; subagent: string; depends_on: string[] }[];
};

export type WorkflowRunResult = {
  output: string;
  steps: Record<string, string>;
  failed: string[];
};
