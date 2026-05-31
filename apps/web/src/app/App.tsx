import {
  Activity as ActivityIcon,
  Bot,
  Boxes,
  CalendarClock,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  Database,
  FileText,
  Gauge,
  Loader2,
  MessageSquare,
  Network,
  Play,
  Plus,
  RefreshCw,
  Save,
  ScrollText,
  Search,
  Settings2,
  Sparkles,
  Square,
  Trash2,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { ActivitySurface } from "../activity/ActivitySurface";
import { ChatSurface } from "../chat/ChatSurface";
import { api, getOperatorKey, setOperatorKey, UnauthorizedError } from "../lib/api";
import { onConnectionChange, onServerEvent } from "../lib/events";
import { KNOWLEDGE_TABLES } from "../lib/types";
import type {
  AgentRun,
  AuditEntry,
  BeadsIssue,
  ScheduledJob,
  EngagementReport,
  EngagementStatus,
  KnowledgeHit,
  NotesWorkspace,
  RuntimeStatus,
  Subagent,
} from "../lib/types";
import { SetupWizard } from "../setup/SetupWizard";

type Surface = "chat" | "activity" | "knowledge" | "subagents" | "runtime" | "audit" | "schedule";
type AuditFilter = "all" | "ok" | "failed";
type RightPanel = "notes" | "beads" | "engagement";
type SubagentMode = "single" | "batch";
type StatusTone = "success" | "warning" | "error" | "muted";

type BatchTask = {
  id: string;
  type: string;
  description: string;
  prompt: string;
};

type IssueDraft = {
  title: string;
  description: string;
  type: string;
  priority: number;
};

const sessionId = "operator-default";
const emptyIssueDraft: IssueDraft = {
  title: "",
  description: "",
  type: "task",
  priority: 2,
};

const issueStatusOrder = ["in_progress", "open", "blocked", "deferred", "closed"];

function createBatchTask(type = "researcher"): BatchTask {
  return {
    id: `batch-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    type,
    description: "",
    prompt: "",
  };
}

function createNoteTab() {
  const now = Date.now();
  const id = `note-${now}-${Math.random().toString(36).slice(2, 8)}`;
  return {
    id,
    name: "Notes",
    content: "",
    permissions: { agentRead: true, agentWrite: true },
    metadata: {
      createdAt: now,
      updatedAt: now,
      wordCount: 0,
      characterCount: 0,
    },
  };
}

function useLocalStorageState(key: string, fallback: string, legacyKeys: string[] = []) {
  const [value, setValue] = useState(() => {
    try {
      const current = window.localStorage.getItem(key);
      if (current) return current;
      for (const legacyKey of legacyKeys) {
        const legacy = window.localStorage.getItem(legacyKey);
        if (legacy) return legacy;
      }
      return fallback;
    } catch {
      return fallback;
    }
  });

  useEffect(() => {
    try {
      window.localStorage.setItem(key, value);
    } catch {
      // localStorage can be unavailable in hardened browser contexts.
    }
  }, [key, value]);

  return [value, setValue] as const;
}

function formatBool(value: boolean) {
  return value ? "on" : "off";
}

function agentStatusTone(status: string): StatusTone {
  if (status === "done") return "success";
  if (status === "error") return "error";
  if (status === "running") return "warning";
  return "muted";
}

function formatAuditTime(ts: string) {
  if (!ts) return "—";
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return ts;
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function statusTone(ok?: boolean) {
  if (ok === undefined) return "muted";
  return ok ? "success" : "error";
}

function issueStatus(issue: BeadsIssue) {
  return issue.status || "open";
}

function issueType(issue: BeadsIssue) {
  return issue.issue_type || issue.type || "task";
}

function issueStatusLabel(status: string) {
  return status.replace(/_/g, " ");
}

function issueStatusTone(status: string): StatusTone {
  if (status === "closed") return "success";
  if (status === "blocked") return "error";
  if (status === "in_progress" || status === "deferred") return "warning";
  return "muted";
}

function priorityLabel(priority: BeadsIssue["priority"]) {
  if (priority === undefined || priority === null || priority === "") return "P-";
  const value = String(priority);
  return value.toUpperCase().startsWith("P") ? value.toUpperCase() : `P${value}`;
}

function groupIssues(issues: BeadsIssue[]) {
  const buckets = new Map<string, BeadsIssue[]>();
  for (const issue of issues) {
    const status = issueStatus(issue);
    const bucket = buckets.get(status);
    if (bucket) {
      bucket.push(issue);
    } else {
      buckets.set(status, [issue]);
    }
  }

  const ordered = issueStatusOrder.filter((status) => buckets.has(status));
  const rest = [...buckets.keys()].filter((status) => !issueStatusOrder.includes(status)).sort();
  return [...ordered, ...rest].map((status) => ({
    status,
    issues: buckets.get(status) || [],
  }));
}

export function App() {
  const [surface, setSurface] = useState<Surface>("chat");
  const [rightPanel, setRightPanel] = useState<RightPanel>("notes");
  const [live, setLive] = useState(false);
  const [activityUnread, setActivityUnread] = useState(0);

  // Open the server→client event stream (ADR 0003) and track its connection
  // state for the "live" indicator. Surfaces subscribe to named events.
  useEffect(() => onConnectionChange(setLive), []);

  // Unread badge on the Activity rail button: count agent-initiated messages
  // that arrive while the operator isn't looking at the Activity surface.
  useEffect(
    () =>
      onServerEvent("activity.message", () => {
        setSurface((s) => {
          if (s !== "activity") setActivityUnread((n) => n + 1);
          return s;
        });
      }),
    [],
  );
  useEffect(() => {
    if (surface === "activity") setActivityUnread(0);
  }, [surface]);
  const [projectPath, setProjectPath] = useLocalStorageState("protopen.projectPath", "", [
    "protoagent.projectPath",
  ]);
  const [needsAuth, setNeedsAuth] = useState(false);
  const [keyInput, setKeyInput] = useState(() => getOperatorKey());
  const [runtime, setRuntime] = useState<RuntimeStatus | null>(null);
  const [subagents, setSubagents] = useState<Subagent[]>([]);
  const [engagement, setEngagement] = useState<EngagementStatus | null>(null);
  const [workspace, setWorkspace] = useState<NotesWorkspace | null>(null);
  const [beadsIssues, setBeadsIssues] = useState<BeadsIssue[]>([]);
  const [beadsReady, setBeadsReady] = useState<boolean | null>(null);
  const [status, setStatus] = useState("ready");
  const [error, setError] = useState("");

  const [subagentType, setSubagentType] = useState("researcher");
  const [subagentMode, setSubagentMode] = useState<SubagentMode>("single");
  const [subagentDescription, setSubagentDescription] = useState("");
  const [subagentPrompt, setSubagentPrompt] = useState("");
  const [batchTasks, setBatchTasks] = useState<BatchTask[]>(() => [createBatchTask()]);
  const [emitSkill, setEmitSkill] = useState(false);
  const [subagentOutput, setSubagentOutput] = useState("");
  const [subagentBusy, setSubagentBusy] = useState(false);

  const [agentRuns, setAgentRuns] = useState<AgentRun[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);

  const [knowledgeQuery, setKnowledgeQuery] = useState("");
  const [knowledgeTable, setKnowledgeTable] = useState("");
  const [knowledgeHits, setKnowledgeHits] = useState<KnowledgeHit[]>([]);
  const [knowledgeBusy, setKnowledgeBusy] = useState(false);
  const [knowledgeSearched, setKnowledgeSearched] = useState(false);

  const [scheduleJobs, setScheduleJobs] = useState<ScheduledJob[]>([]);
  const [scheduleBackend, setScheduleBackend] = useState("");
  const [scheduleBusy, setScheduleBusy] = useState(false);
  const [scheduleLoaded, setScheduleLoaded] = useState(false);
  const [schedulePrompt, setSchedulePrompt] = useState("");
  const [scheduleWhen, setScheduleWhen] = useState("");

  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [auditBusy, setAuditBusy] = useState(false);
  const [auditLoaded, setAuditLoaded] = useState(false);
  const [auditFilter, setAuditFilter] = useState<AuditFilter>("all");
  const [auditTool, setAuditTool] = useState("");

  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  const [report, setReport] = useState<EngagementReport | null>(null);
  const [reportOpen, setReportOpen] = useState(false);
  const [reportBusy, setReportBusy] = useState(false);

  const [notesBusy, setNotesBusy] = useState(false);
  const [notesDirty, setNotesDirty] = useState(false);
  const [issueDraft, setIssueDraft] = useState<IssueDraft>(emptyIssueDraft);
  const [beadsBusy, setBeadsBusy] = useState(false);

  const activeTab = workspace?.tabs[workspace.activeTabId] || null;

  async function refreshRuntime() {
    const [runtimePayload, subagentPayload, engagementPayload] = await Promise.all([
      api.runtimeStatus(),
      api.subagents(),
      api.engagement(),
    ]);
    setRuntime(runtimePayload);
    setSubagents(subagentPayload.subagents);
    setEngagement(engagementPayload);
    if (!subagentPayload.subagents.some((item) => item.name === subagentType)) {
      setSubagentType(subagentPayload.subagents[0]?.name || "researcher");
    }
  }

  async function refreshProjectState(path = projectPath) {
    if (!path.trim()) return;
    const [notesPayload, beadsStatus] = await Promise.all([
      api.getNotes(path),
      api.beadsStatus(path),
    ]);
    setWorkspace(notesPayload.workspace);
    setNotesDirty(false);
    setBeadsReady(beadsStatus.initialized);
    if (beadsStatus.initialized) {
      const issuesPayload = await api.beadsIssues(path);
      setBeadsIssues(issuesPayload.issues);
    } else {
      setBeadsIssues([]);
    }
  }

  async function refreshAll() {
    setStatus("refreshing");
    setError("");
    try {
      await refreshRuntime();
      await refreshProjectState();
      setStatus("ready");
    } catch (exc) {
      if (exc instanceof UnauthorizedError) {
        setNeedsAuth(true);
        setStatus("error");
        setError("");
        return;
      }
      setStatus("error");
      setError(exc instanceof Error ? exc.message : String(exc));
    }
  }

  useEffect(() => {
    void refreshAll();
  }, []);

  useEffect(() => {
    if (!notesDirty || !workspace || !projectPath.trim()) return;
    const handle = window.setTimeout(() => {
      void saveWorkspaceSnapshot(workspace, { quiet: true });
    }, 800);
    return () => window.clearTimeout(handle);
  }, [notesBusy, notesDirty, projectPath, workspace]);

  useEffect(() => {
    if (surface === "audit" && !auditLoaded && !auditBusy) {
      void refreshAudit();
    }
  }, [surface, auditLoaded, auditBusy]);

  useEffect(() => {
    if (surface === "schedule" && !scheduleLoaded && !scheduleBusy) {
      void refreshSchedule();
    }
  }, [surface, scheduleLoaded, scheduleBusy]);

  // Live agent monitor: load on entering the surface, poll while any run is active.
  useEffect(() => {
    if (surface !== "subagents") return;
    void refreshAgents();
    const handle = window.setInterval(() => {
      if (agentRuns.some((run) => run.status === "running")) void refreshAgents();
    }, 3000);
    return () => window.clearInterval(handle);
  }, [surface, agentRuns]);

  // Live engagement monitor: poll while the engagement panel is open.
  useEffect(() => {
    if (rightPanel !== "engagement") return;
    let cancelled = false;
    const tick = async () => {
      try {
        const payload = await api.engagement();
        if (!cancelled) setEngagement(payload);
      } catch {
        // Transient poll errors are non-fatal; the next tick retries.
      }
    };
    void tick();
    const handle = window.setInterval(() => void tick(), 5000);
    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
  }, [rightPanel]);

  async function runSubagent() {
    const prompt = subagentPrompt.trim();
    const runnableBatchTasks = batchTasks.filter((task) => task.prompt.trim());
    if (subagentBusy) return;
    if (subagentMode === "single" && !prompt) return;
    if (subagentMode === "batch" && runnableBatchTasks.length === 0) return;
    setSubagentBusy(true);
    setError("");
    setSubagentOutput("");
    try {
      const response = subagentMode === "single"
        ? await api.runSubagent({
            session_id: sessionId,
            type: subagentType,
            description: subagentDescription.trim(),
            prompt,
            emit_skill: emitSkill,
          })
        : await api.runSubagentBatch({
            session_id: sessionId,
            tasks: runnableBatchTasks.map((task) => ({
              type: task.type,
              description: task.description.trim(),
              prompt: task.prompt.trim(),
              emit_skill: emitSkill,
            })),
          });
      setSubagentOutput(response.output);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setSubagentBusy(false);
    }
  }

  async function refreshSchedule() {
    if (scheduleBusy) return;
    setScheduleBusy(true);
    setError("");
    try {
      const result = await api.schedulerJobs();
      setScheduleJobs(result.jobs);
      setScheduleBackend(result.backend);
      setScheduleLoaded(true);
    } catch (exc) {
      if (exc instanceof UnauthorizedError) setNeedsAuth(true);
      else setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setScheduleBusy(false);
    }
  }

  async function addSchedule() {
    const prompt = schedulePrompt.trim();
    const schedule = scheduleWhen.trim();
    if (!prompt || !schedule || scheduleBusy) return;
    setScheduleBusy(true);
    setError("");
    try {
      await api.addSchedule({ prompt, schedule });
      setSchedulePrompt("");
      setScheduleWhen("");
      await refreshSchedule();
    } catch (exc) {
      if (exc instanceof UnauthorizedError) setNeedsAuth(true);
      else setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setScheduleBusy(false);
    }
  }

  async function cancelSchedule(jobId: string) {
    setError("");
    try {
      await api.cancelSchedule(jobId);
      await refreshSchedule();
    } catch (exc) {
      if (exc instanceof UnauthorizedError) setNeedsAuth(true);
      else setError(exc instanceof Error ? exc.message : String(exc));
    }
  }

  async function searchKnowledge() {
    const query = knowledgeQuery.trim();
    if (!query || knowledgeBusy) return;
    setKnowledgeBusy(true);
    setError("");
    try {
      const result = await api.knowledgeSearch(query, {
        k: 20,
        table: knowledgeTable || undefined,
      });
      setKnowledgeHits(result.hits);
      setKnowledgeSearched(true);
    } catch (exc) {
      if (exc instanceof UnauthorizedError) {
        setNeedsAuth(true);
      } else {
        setError(exc instanceof Error ? exc.message : String(exc));
      }
    } finally {
      setKnowledgeBusy(false);
    }
  }

  async function refreshAudit() {
    if (auditBusy) return;
    setAuditBusy(true);
    setError("");
    try {
      const result = await api.auditRecent({ n: 200 });
      setAuditEntries(result.entries);
      setAuditLoaded(true);
    } catch (exc) {
      if (exc instanceof UnauthorizedError) {
        setNeedsAuth(true);
      } else {
        setError(exc instanceof Error ? exc.message : String(exc));
      }
    } finally {
      setAuditBusy(false);
    }
  }

  async function openReport() {
    setReportOpen(true);
    setReportBusy(true);
    setError("");
    try {
      setReport(await api.engagementReport());
    } catch (exc) {
      if (exc instanceof UnauthorizedError) setNeedsAuth(true);
      else setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setReportBusy(false);
    }
  }

  async function generateReport() {
    if (reportBusy) return;
    setReportBusy(true);
    setError("");
    try {
      setReport(await api.generateEngagementReport());
    } catch (exc) {
      if (exc instanceof UnauthorizedError) setNeedsAuth(true);
      else setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setReportBusy(false);
    }
  }

  async function refreshAgents() {
    try {
      const result = await api.listAgents();
      setAgentRuns(result.agents);
    } catch (exc) {
      if (exc instanceof UnauthorizedError) setNeedsAuth(true);
      // Other poll errors are transient — next tick retries.
    }
  }

  async function launchAgent() {
    const prompt = subagentPrompt.trim();
    if (!prompt || subagentBusy) return;
    setSubagentBusy(true);
    setError("");
    try {
      await api.launchAgent({
        session_id: sessionId,
        type: subagentType,
        description: subagentDescription.trim(),
        prompt,
        emit_skill: emitSkill,
      });
      setSubagentPrompt("");
      await refreshAgents();
    } catch (exc) {
      if (exc instanceof UnauthorizedError) setNeedsAuth(true);
      else setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setSubagentBusy(false);
    }
  }

  async function cancelAgent(id: string) {
    setError("");
    try {
      await api.cancelAgent(id);
      await refreshAgents();
    } catch (exc) {
      if (exc instanceof UnauthorizedError) setNeedsAuth(true);
      else setError(exc instanceof Error ? exc.message : String(exc));
    }
  }

  function updateBatchTask(id: string, patch: Partial<BatchTask>) {
    setBatchTasks((tasks) => tasks.map((task) => (task.id === id ? { ...task, ...patch } : task)));
  }

  function addBatchTask() {
    setBatchTasks((tasks) => [...tasks, createBatchTask(subagentType)]);
  }

  function removeBatchTask(id: string) {
    setBatchTasks((tasks) => (tasks.length > 1 ? tasks.filter((task) => task.id !== id) : tasks));
  }

  async function loadProject() {
    setNotesBusy(true);
    setBeadsBusy(true);
    setError("");
    try {
      await refreshProjectState();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setNotesBusy(false);
      setBeadsBusy(false);
    }
  }

  function updateWorkspace(nextWorkspace: NotesWorkspace) {
    setWorkspace(nextWorkspace);
    setNotesDirty(true);
  }

  function saveActiveNote(content: string) {
    if (!workspace || !activeTab || !projectPath.trim()) return;
    const nextWorkspace: NotesWorkspace = {
      ...workspace,
      workspaceVersion: workspace.workspaceVersion + 1,
      tabs: {
        ...workspace.tabs,
        [activeTab.id]: {
          ...activeTab,
          content,
          metadata: {
            ...activeTab.metadata,
            updatedAt: Date.now(),
            characterCount: content.length,
            wordCount: content.trim() ? content.trim().split(/\s+/).length : 0,
          },
        },
      },
    };
    updateWorkspace(nextWorkspace);
  }

  async function saveWorkspaceSnapshot(
    snapshot: NotesWorkspace,
    options: { quiet?: boolean } = {},
  ) {
    if (!projectPath.trim() || notesBusy) return;
    setNotesBusy(true);
    if (!options.quiet) setError("");
    try {
      await api.saveNotes(projectPath, snapshot);
      setNotesDirty(false);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setNotesBusy(false);
    }
  }

  async function persistNotes() {
    if (!workspace) return;
    await saveWorkspaceSnapshot(workspace);
  }

  function createNote() {
    if (!workspace) return;
    const tab = createNoteTab();
    updateWorkspace({
      ...workspace,
      workspaceVersion: workspace.workspaceVersion + 1,
      activeTabId: tab.id,
      tabOrder: [...workspace.tabOrder, tab.id],
      tabs: { ...workspace.tabs, [tab.id]: tab },
    });
  }

  function deleteActiveNote() {
    if (!workspace || workspace.tabOrder.length <= 1) return;
    const nextOrder = workspace.tabOrder.filter((id) => id !== workspace.activeTabId);
    const nextTabs = { ...workspace.tabs };
    delete nextTabs[workspace.activeTabId];
    updateWorkspace({
      ...workspace,
      workspaceVersion: workspace.workspaceVersion + 1,
      activeTabId: nextOrder[0],
      tabOrder: nextOrder,
      tabs: nextTabs,
    });
  }

  function renameActiveNote(name: string) {
    if (!workspace || !activeTab) return;
    updateWorkspace({
      ...workspace,
      workspaceVersion: workspace.workspaceVersion + 1,
      tabs: {
        ...workspace.tabs,
        [activeTab.id]: {
          ...activeTab,
          name,
          metadata: { ...activeTab.metadata, updatedAt: Date.now() },
        },
      },
    });
  }

  function toggleActiveNotePermission(permission: "agentRead" | "agentWrite", value: boolean) {
    if (!workspace || !activeTab) return;
    updateWorkspace({
      ...workspace,
      workspaceVersion: workspace.workspaceVersion + 1,
      tabs: {
        ...workspace.tabs,
        [activeTab.id]: {
          ...activeTab,
          permissions: { ...activeTab.permissions, [permission]: value },
          metadata: { ...activeTab.metadata, updatedAt: Date.now() },
        },
      },
    });
  }

  async function initBeads() {
    if (!projectPath.trim() || beadsBusy) return;
    setBeadsBusy(true);
    setError("");
    try {
      await api.initBeads(projectPath);
      await refreshProjectState();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBeadsBusy(false);
    }
  }

  async function createIssue() {
    const title = issueDraft.title.trim();
    if (!projectPath.trim() || !title || beadsBusy) return;
    setBeadsBusy(true);
    setError("");
    try {
      const response = await api.createIssue(projectPath, {
        title,
        type: issueDraft.type,
        priority: issueDraft.priority,
        description: issueDraft.description.trim() || undefined,
      });
      setBeadsIssues((items) => [response.issue, ...items]);
      setIssueDraft(emptyIssueDraft);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBeadsBusy(false);
    }
  }

  function replaceIssue(issue: BeadsIssue) {
    setBeadsIssues((items) => items.map((item) => (item.id === issue.id ? { ...item, ...issue } : item)));
  }

  async function updateIssueStatus(issue: BeadsIssue, nextStatus: string) {
    if (!projectPath.trim() || beadsBusy) return;
    setBeadsBusy(true);
    setError("");
    try {
      const response = await api.updateIssue(projectPath, issue.id, { status: nextStatus });
      replaceIssue(response.issue.id ? response.issue : { ...issue, status: nextStatus });
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBeadsBusy(false);
    }
  }

  async function closeIssue(issue: BeadsIssue) {
    if (!projectPath.trim() || beadsBusy) return;
    setBeadsBusy(true);
    setError("");
    try {
      const response = await api.closeIssue(projectPath, issue.id);
      replaceIssue(response.issue.id ? response.issue : { ...issue, status: "closed" });
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBeadsBusy(false);
    }
  }

  async function deleteIssue(issue: BeadsIssue) {
    if (!projectPath.trim() || beadsBusy) return;
    if (!window.confirm(`Delete ${issue.id}?`)) return;
    setBeadsBusy(true);
    setError("");
    try {
      await api.deleteIssue(projectPath, issue.id);
      setBeadsIssues((items) => items.filter((item) => item.id !== issue.id));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBeadsBusy(false);
    }
  }

  const middleware = useMemo(() => {
    if (!runtime) return [];
    return Object.entries(runtime.middleware).sort(([a], [b]) => a.localeCompare(b));
  }, [runtime]);

  const groupedIssues = useMemo(() => groupIssues(beadsIssues), [beadsIssues]);

  const auditTools = useMemo(
    () => Array.from(new Set(auditEntries.map((entry) => entry.tool).filter(Boolean))).sort(),
    [auditEntries],
  );

  const filteredAudit = useMemo(
    () =>
      auditEntries.filter((entry) => {
        if (auditFilter === "ok" && !entry.success) return false;
        if (auditFilter === "failed" && entry.success) return false;
        if (auditTool && entry.tool !== auditTool) return false;
        return true;
      }),
    [auditEntries, auditFilter, auditTool],
  );

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <img src="/app/protolabs-icon-outline.svg" alt="" className="brand-mark" />
          <div>
            <div className="brand-name">protoPen</div>
            <div className="brand-subline">protoLabs.studio</div>
          </div>
        </div>
        <div className="topbar-status">
          <StatusPill
            label={runtime?.setup_complete ? "setup complete" : "setup pending"}
            tone={statusTone(runtime?.setup_complete)}
          />
          <StatusPill
            label={runtime?.graph_loaded ? "graph loaded" : "graph offline"}
            tone={statusTone(runtime?.graph_loaded)}
          />
          <StatusPill label={status} tone={status === "error" ? "error" : "muted"} />
          <span
            className={`live-dot ${live ? "is-live" : ""}`}
            role="status"
            aria-label={live ? "event stream connected" : "event stream offline"}
            title={live ? "Live — event stream connected" : "Event stream offline"}
            data-testid="live-indicator"
            data-live={live ? "true" : "false"}
          />
          <button className="icon-button" type="button" onClick={() => void refreshAll()} title="Refresh">
            <RefreshCw size={16} />
          </button>
        </div>
      </header>

      <div className="workspace">
        <aside className="rail" aria-label="Workspace surfaces">
          <RailButton
            active={surface === "chat"}
            label="Chat"
            icon={<MessageSquare size={18} />}
            onClick={() => setSurface("chat")}
          />
          <RailButton
            active={surface === "activity"}
            label="Activity"
            icon={<ActivityIcon size={18} />}
            onClick={() => setSurface("activity")}
            badge={activityUnread}
          />
          <RailButton
            active={surface === "knowledge"}
            label="Knowledge"
            icon={<Search size={18} />}
            onClick={() => setSurface("knowledge")}
          />
          <RailButton
            active={surface === "subagents"}
            label="Subagents"
            icon={<Network size={18} />}
            onClick={() => setSurface("subagents")}
          />
          <RailButton
            active={surface === "runtime"}
            label="Runtime"
            icon={<Gauge size={18} />}
            onClick={() => setSurface("runtime")}
          />
          <RailButton
            active={surface === "audit"}
            label="Audit"
            icon={<ScrollText size={18} />}
            onClick={() => setSurface("audit")}
          />
          <RailButton
            active={surface === "schedule"}
            label="Schedule"
            icon={<CalendarClock size={18} />}
            onClick={() => setSurface("schedule")}
          />
        </aside>

        <main className="stage">
          {error ? (
            <div className="error-strip" role="alert">
              <CircleAlert size={16} />
              <span>{error}</span>
            </div>
          ) : null}

          {surface === "chat" ? (
            <ChatSurface onError={setError} />
          ) : null}

          {surface === "activity" ? <ActivitySurface onError={setError} /> : null}

          {surface === "knowledge" ? (
            <section className="panel stage-panel knowledge-panel">
              <div className="panel-header">
                <div>
                  <h1>Knowledge</h1>
                  <p className="panel-kicker">hybrid search · cve / exploit / advisory intel</p>
                </div>
                <StatusPill
                  label={knowledgeBusy ? "searching" : `${knowledgeHits.length} hit${knowledgeHits.length === 1 ? "" : "s"}`}
                  tone={knowledgeBusy ? "warning" : "muted"}
                />
              </div>
              <form
                className="knowledge-search"
                onSubmit={(event) => {
                  event.preventDefault();
                  void searchKnowledge();
                }}
              >
                <input
                  value={knowledgeQuery}
                  onChange={(event) => setKnowledgeQuery(event.target.value)}
                  placeholder="Search advisories, exploits, CVEs…"
                  aria-label="Knowledge query"
                  autoFocus
                />
                <select
                  value={knowledgeTable}
                  onChange={(event) => setKnowledgeTable(event.target.value)}
                  aria-label="Filter table"
                >
                  <option value="">all sources</option>
                  {KNOWLEDGE_TABLES.map((table) => (
                    <option key={table} value={table}>
                      {table}
                    </option>
                  ))}
                </select>
                <button className="primary-button" type="submit" disabled={knowledgeBusy || !knowledgeQuery.trim()}>
                  {knowledgeBusy ? <Loader2 className="spin" size={16} /> : <Search size={16} />}
                  Search
                </button>
              </form>
              <div className="knowledge-results">
                {knowledgeHits.length > 0 ? (
                  knowledgeHits.map((hit, index) => (
                    <article className="knowledge-hit" key={`${hit.table}:${hit.source_id}:${index}`}>
                      <div className="knowledge-hit-head">
                        <StatusPill label={hit.table || "—"} tone="muted" />
                        <span className="knowledge-hit-id">{hit.source_id}</span>
                        <span className="knowledge-hit-score">{hit.score.toFixed(2)}</span>
                      </div>
                      <p className="knowledge-hit-preview">{hit.preview || "(no preview)"}</p>
                    </article>
                  ))
                ) : (
                  <div className="empty-state stacked">
                    <Search size={18} />
                    <span>{knowledgeSearched ? "No matches in the knowledge store." : "Search the threat-intel knowledge store."}</span>
                  </div>
                )}
              </div>
            </section>
          ) : null}

          {surface === "subagents" ? (
            <section className="panel stage-panel">
              <div className="panel-header">
                <div>
                  <h1>Manual Subagent</h1>
                  <p className="panel-kicker">{subagents.length} registered</p>
                </div>
                <StatusPill label={subagentBusy ? "running" : "ready"} tone={subagentBusy ? "warning" : "muted"} />
              </div>
              <div className="stage-body">
              <div className="subagent-mode segmented">
                <button type="button" className={subagentMode === "single" ? "active" : ""} onClick={() => setSubagentMode("single")}>
                  Single
                </button>
                <button type="button" className={subagentMode === "batch" ? "active" : ""} onClick={() => setSubagentMode("batch")}>
                  Batch
                </button>
              </div>
              <div className="subagent-grid">
                <label className="field">
                  <span>Type</span>
                  <select value={subagentType} onChange={(event) => setSubagentType(event.target.value)}>
                    {subagents.map((subagent) => (
                      <option key={subagent.name} value={subagent.name}>
                        {subagent.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  <span>Description</span>
                  <input
                    value={subagentDescription}
                    onChange={(event) => setSubagentDescription(event.target.value)}
                    placeholder="Short task label"
                  />
                </label>
                <label className="checkbox-field">
                  <input
                    type="checkbox"
                    checked={emitSkill}
                    onChange={(event) => setEmitSkill(event.target.checked)}
                  />
                  <span>Emit skill</span>
                </label>
              </div>
              {subagentMode === "single" ? (
                <label className="field grow">
                  <span>Prompt</span>
                  <textarea
                    value={subagentPrompt}
                    onChange={(event) => setSubagentPrompt(event.target.value)}
                    placeholder="Subagent instructions"
                    rows={8}
                  />
                </label>
              ) : (
                <div className="batch-task-list">
                  {batchTasks.map((task, index) => (
                    <div className="batch-task-row" key={task.id}>
                      <div className="batch-task-header">
                        <span>Task {index + 1}</span>
                        <button className="icon-button" type="button" onClick={() => removeBatchTask(task.id)} disabled={batchTasks.length === 1} title="Remove task">
                          <Trash2 size={15} />
                        </button>
                      </div>
                      <div className="batch-task-fields">
                        <label className="field">
                          <span>Type</span>
                          <select value={task.type} onChange={(event) => updateBatchTask(task.id, { type: event.target.value })}>
                            {subagents.map((subagent) => (
                              <option key={subagent.name} value={subagent.name}>
                                {subagent.name}
                              </option>
                            ))}
                          </select>
                        </label>
                        <label className="field">
                          <span>Description</span>
                          <input value={task.description} onChange={(event) => updateBatchTask(task.id, { description: event.target.value })} placeholder="Task label" />
                        </label>
                      </div>
                      <label className="field">
                        <span>Prompt</span>
                        <textarea value={task.prompt} onChange={(event) => updateBatchTask(task.id, { prompt: event.target.value })} rows={4} />
                      </label>
                    </div>
                  ))}
                </div>
              )}
              <div className="panel-actions">
                {subagentMode === "batch" ? (
                  <button className="secondary-button" type="button" onClick={addBatchTask}>
                    <Plus size={15} />
                    Add task
                  </button>
                ) : null}
                <button
                  className="primary-button"
                  type="button"
                  onClick={() => void (subagentMode === "single" ? launchAgent() : runSubagent())}
                  disabled={
                    subagentBusy ||
                    (subagentMode === "single" ? !subagentPrompt.trim() : !batchTasks.some((task) => task.prompt.trim()))
                  }
                >
                  {subagentBusy ? <Loader2 className="spin" size={16} /> : <Play size={16} />}
                  {subagentMode === "single" ? "Launch" : "Run batch"}
                </button>
              </div>
              {subagentOutput ? <pre className="output-block">{subagentOutput}</pre> : null}
              <div className="agent-runs">
                <div className="agent-runs-head">
                  <span>Tracked agents</span>
                  <button className="icon-button" type="button" onClick={() => void refreshAgents()} title="Refresh agents">
                    <RefreshCw size={15} />
                  </button>
                </div>
                {agentRuns.length === 0 ? (
                  <p className="panel-kicker agent-runs-empty">No launched agents yet.</p>
                ) : (
                  agentRuns.map((run) => {
                    const open = selectedAgentId === run.id;
                    const body = run.error || run.output;
                    return (
                      <div className="agent-run" key={run.id}>
                        <div className="agent-run-head">
                          <button
                            type="button"
                            className="agent-run-toggle"
                            onClick={() => setSelectedAgentId(open ? null : run.id)}
                            aria-expanded={open}
                          >
                            <StatusPill label={run.status} tone={agentStatusTone(run.status)} />
                            <strong className="agent-run-type">{run.type}</strong>
                            <span className="agent-run-desc">{run.description}</span>
                            <span className="agent-run-dur">
                              {run.status === "running" ? "running…" : `${run.duration_ms}ms`}
                            </span>
                          </button>
                          {run.status === "running" ? (
                            <button
                              className="icon-button danger"
                              type="button"
                              onClick={() => void cancelAgent(run.id)}
                              title="Cancel agent"
                            >
                              <Square size={14} />
                            </button>
                          ) : null}
                        </div>
                        {open && body ? <pre className="agent-run-output">{body}</pre> : null}
                      </div>
                    );
                  })
                )}
              </div>
              </div>
            </section>
          ) : null}

          {surface === "runtime" ? (
            <section className="panel stage-panel">
              <div className="panel-header">
                <div>
                  <h1>Runtime</h1>
                  <p className="panel-kicker">{runtime?.model?.name || "model not configured"}</p>
                </div>
                <StatusPill label={runtime?.scheduler.backend || "scheduler"} tone="muted" />
              </div>
              <div className="stage-body">
              <div className="metric-grid">
                <Metric icon={<Bot size={16} />} label="Agent" value={runtime?.identity?.name || "protopen"} />
                <Metric icon={<Settings2 size={16} />} label="Provider" value={runtime?.model?.provider || "none"} />
                <Metric icon={<Database size={16} />} label="Knowledge" value={runtime?.knowledge.resolved_path || runtime?.knowledge.configured_path || "disabled"} />
                <Metric icon={<Sparkles size={16} />} label="Goal mode" value={formatBool(Boolean(runtime?.goal.enabled))} />
              </div>
              <div className="table-list">
                {middleware.map(([name, enabled]) => (
                  <div className="table-row" key={name}>
                    <span>{name}</span>
                    <StatusPill label={formatBool(enabled)} tone={enabled ? "success" : "muted"} />
                  </div>
                ))}
              </div>
              <div className="subagent-list">
                {subagents.map((subagent) => (
                  <div className="subagent-row" key={subagent.name}>
                    <div>
                      <strong>{subagent.name}</strong>
                      <span>{subagent.tools.join(", ") || "no tools"}</span>
                    </div>
                    <StatusPill label={`${subagent.max_turns} turns`} tone={subagent.enabled ? "success" : "muted"} />
                  </div>
                ))}
              </div>
              </div>
            </section>
          ) : null}

          {surface === "audit" ? (
            <section className="panel stage-panel audit-panel">
              <div className="panel-header">
                <div>
                  <h1>Audit</h1>
                  <p className="panel-kicker">
                    {filteredAudit.length} of {auditEntries.length} tool call{auditEntries.length === 1 ? "" : "s"}
                  </p>
                </div>
                <button className="icon-button" type="button" onClick={() => void refreshAudit()} title="Refresh audit">
                  {auditBusy ? <Loader2 className="spin" size={16} /> : <RefreshCw size={16} />}
                </button>
              </div>
              <div className="audit-controls">
                <div className="segmented">
                  <button type="button" className={auditFilter === "all" ? "active" : ""} onClick={() => setAuditFilter("all")}>
                    All
                  </button>
                  <button type="button" className={auditFilter === "ok" ? "active" : ""} onClick={() => setAuditFilter("ok")}>
                    OK
                  </button>
                  <button type="button" className={auditFilter === "failed" ? "active" : ""} onClick={() => setAuditFilter("failed")}>
                    Failed
                  </button>
                </div>
                <select value={auditTool} onChange={(event) => setAuditTool(event.target.value)} aria-label="Filter tool">
                  <option value="">all tools</option>
                  {auditTools.map((tool) => (
                    <option key={tool} value={tool}>
                      {tool}
                    </option>
                  ))}
                </select>
              </div>
              <div className="audit-list">
                {filteredAudit.length > 0 ? (
                  filteredAudit.map((entry, index) => (
                    <article className="audit-row" key={`${entry.ts}:${entry.tool}:${entry.session_id}:${index}`}>
                      <div className="audit-row-head">
                        <StatusPill label={entry.success ? "ok" : "failed"} tone={entry.success ? "success" : "error"} />
                        <strong className="audit-tool">{entry.tool || "—"}</strong>
                        <span className="audit-duration">{entry.duration_ms}ms</span>
                        <span className="audit-ts">{formatAuditTime(entry.ts)}</span>
                      </div>
                      {entry.result_summary ? <p className="audit-summary">{entry.result_summary}</p> : null}
                      <div className="audit-meta">
                        {entry.session_id ? <span>{entry.session_id}</span> : null}
                        {entry.trace_id ? <span>trace {entry.trace_id.slice(0, 8)}</span> : null}
                      </div>
                    </article>
                  ))
                ) : (
                  <div className="empty-state stacked">
                    <ScrollText size={18} />
                    <span>
                      {!auditLoaded
                        ? "Loading audit trail…"
                        : auditEntries.length === 0
                          ? "No tool calls recorded yet."
                          : "No entries match the current filter."}
                    </span>
                  </div>
                )}
              </div>
            </section>
          ) : null}

          {surface === "schedule" ? (
            <section className="panel stage-panel audit-panel">
              <div className="panel-header">
                <div>
                  <h1>Schedule</h1>
                  <p className="panel-kicker">
                    {scheduleJobs.length} job{scheduleJobs.length === 1 ? "" : "s"} · backend {scheduleBackend || "—"}
                  </p>
                </div>
                <button className="icon-button" type="button" onClick={() => void refreshSchedule()} title="Refresh jobs">
                  {scheduleBusy ? <Loader2 className="spin" size={16} /> : <RefreshCw size={16} />}
                </button>
              </div>
              <form
                className="knowledge-search"
                onSubmit={(event) => {
                  event.preventDefault();
                  void addSchedule();
                }}
              >
                <input
                  value={schedulePrompt}
                  onChange={(event) => setSchedulePrompt(event.target.value)}
                  placeholder="Prompt to run on schedule…"
                  aria-label="Scheduled prompt"
                />
                <input
                  value={scheduleWhen}
                  onChange={(event) => setScheduleWhen(event.target.value)}
                  placeholder="cron (0 9 * * 1-5) or ISO datetime"
                  aria-label="Schedule"
                />
                <button
                  className="primary-button"
                  type="submit"
                  disabled={scheduleBusy || !schedulePrompt.trim() || !scheduleWhen.trim()}
                >
                  {scheduleBusy ? <Loader2 className="spin" size={16} /> : <Plus size={16} />}
                  Add
                </button>
              </form>
              <div className="audit-list">
                {scheduleJobs.length > 0 ? (
                  scheduleJobs.map((job) => (
                    <article className="audit-row" key={job.id}>
                      <div className="audit-row-head">
                        <StatusPill label={job.schedule} tone="muted" />
                        <strong className="audit-tool">{job.prompt}</strong>
                        <button
                          className="icon-button danger"
                          type="button"
                          onClick={() => void cancelSchedule(job.id)}
                          title="Cancel job"
                          style={{ marginLeft: "auto" }}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                      <div className="audit-meta">
                        <span>next {job.next_fire ? formatAuditTime(job.next_fire) : "—"}</span>
                        {job.last_fire ? <span>last {formatAuditTime(job.last_fire)}</span> : null}
                        <span>{job.id}</span>
                      </div>
                    </article>
                  ))
                ) : (
                  <div className="empty-state stacked">
                    <CalendarClock size={18} />
                    <span>
                      {!scheduleLoaded
                        ? "Loading scheduled jobs…"
                        : "No scheduled jobs. Add a prompt + cron/ISO schedule above."}
                    </span>
                  </div>
                )}
              </div>
            </section>
          ) : null}
        </main>

        <aside className="right-panel">
          <div className="project-bar">
            <input
              value={projectPath}
              onChange={(event) => setProjectPath(event.target.value)}
              placeholder="Project path"
            />
            <button className="icon-button" type="button" onClick={() => void loadProject()} title="Load project">
              {notesBusy || beadsBusy ? <Loader2 className="spin" size={16} /> : <RefreshCw size={16} />}
            </button>
          </div>
          <div className="segmented">
            <button type="button" className={rightPanel === "notes" ? "active" : ""} onClick={() => setRightPanel("notes")}>
              <FileText size={15} />
              Notes
            </button>
            <button type="button" className={rightPanel === "beads" ? "active" : ""} onClick={() => setRightPanel("beads")}>
              <Boxes size={15} />
              Beads
            </button>
            <button
              type="button"
              className={rightPanel === "engagement" ? "active" : ""}
              onClick={() => setRightPanel("engagement")}
            >
              <Boxes size={15} />
              Engagement
            </button>
          </div>

          {rightPanel === "engagement" ? (
            <section className="panel side-panel engagement-panel">
              <div className="panel-header compact">
                <div>
                  <h2>{engagement?.active ? engagement.name || "Engagement" : "No active engagement"}</h2>
                  <p className="panel-kicker">
                    {engagement?.active
                      ? `${engagement.phase || "—"} • ${engagement.mode || "—"} • ${engagement.total_findings} finding${engagement.total_findings === 1 ? "" : "s"}`
                      : "protoPen is idle"}
                  </p>
                </div>
                <div className="notes-actions">
                  {engagement?.active ? <StatusPill label="live" tone="success" /> : null}
                  <button className="icon-button" type="button" onClick={() => void openReport()} title="View report">
                    <FileText size={16} />
                  </button>
                </div>
              </div>
              {engagement?.active ? (
                <div className="engagement-body">
                  {engagement.scope ? <p className="panel-kicker">Scope: {engagement.scope}</p> : null}
                  <div className="severity-row">
                    {Object.entries(engagement.finding_counts).map(([sev, count]) => (
                      <span key={sev} className={`status-pill sev-${sev}`}>
                        {sev}: {count}
                      </span>
                    ))}
                  </div>
                  <div className="finding-list">
                    {engagement.findings.length === 0 ? (
                      <p className="panel-kicker">No findings logged yet.</p>
                    ) : (
                      engagement.findings.map((finding, index) => {
                        const open = expandedFinding === index;
                        const hasDetail = Boolean(finding.detail);
                        return (
                          <div className="finding-row" key={index}>
                            <button
                              type="button"
                              className="finding-head"
                              onClick={() => setExpandedFinding(open ? null : index)}
                              aria-expanded={open}
                            >
                              {hasDetail ? (
                                open ? <ChevronDown size={14} /> : <ChevronRight size={14} />
                              ) : (
                                <span className="finding-bullet" />
                              )}
                              <span className={`status-pill sev-${finding.severity || "info"}`}>
                                {finding.severity || "—"}
                              </span>
                              <span className="finding-title">{finding.title || "(untitled)"}</span>
                            </button>
                            <div className="finding-sub">{finding.category || "—"}</div>
                            {open && hasDetail ? <pre className="finding-detail">{finding.detail}</pre> : null}
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              ) : null}
            </section>
          ) : null}

          {rightPanel === "notes" ? (
            <section className="panel side-panel notes-panel">
              <div className="panel-header compact">
                <div>
                  <h2>{activeTab?.name || "Notes"}</h2>
                  <p className="panel-kicker">
                    {workspace ? `${workspace.tabOrder.length} tab${workspace.tabOrder.length === 1 ? "" : "s"}${notesDirty ? " • unsaved" : ""}` : "not loaded"}
                  </p>
                </div>
                <div className="notes-actions">
                  <button className="icon-button" type="button" onClick={createNote} disabled={!workspace} title="New note">
                    <Plus size={16} />
                  </button>
                  <button className="icon-button" type="button" onClick={deleteActiveNote} disabled={!workspace || workspace.tabOrder.length <= 1} title="Delete note">
                    <Trash2 size={16} />
                  </button>
                  <button className="icon-button" type="button" onClick={() => void persistNotes()} disabled={!workspace || notesBusy} title="Save notes">
                    {notesBusy ? <Loader2 className="spin" size={16} /> : <Save size={16} />}
                  </button>
                </div>
              </div>
              {workspace ? (
                <div className="notes-tabbar">
                  {workspace.tabOrder.map((tabId) => {
                    const tab = workspace.tabs[tabId];
                    if (!tab) return null;
                    const active = tab.id === workspace.activeTabId;
                    return (
                      <button className={active ? "active" : ""} type="button" key={tab.id} onClick={() => updateWorkspace({ ...workspace, activeTabId: tab.id })}>
                        {tab.name || "Notes"}
                      </button>
                    );
                  })}
                </div>
              ) : null}
              {activeTab ? (
                <div className="notes-meta">
                  <input
                    value={activeTab.name}
                    onChange={(event) => renameActiveNote(event.target.value)}
                    aria-label="Note name"
                  />
                  <label className="checkbox-field">
                    <input
                      type="checkbox"
                      checked={activeTab.permissions.agentRead}
                      onChange={(event) => toggleActiveNotePermission("agentRead", event.target.checked)}
                    />
                    <span>Agent read</span>
                  </label>
                  <label className="checkbox-field">
                    <input
                      type="checkbox"
                      checked={activeTab.permissions.agentWrite}
                      onChange={(event) => toggleActiveNotePermission("agentWrite", event.target.checked)}
                    />
                    <span>Agent write</span>
                  </label>
                </div>
              ) : null}
              <textarea
                className="notes-editor"
                value={activeTab?.content || ""}
                onChange={(event) => saveActiveNote(event.target.value)}
                placeholder="Project notes"
                disabled={!workspace}
              />
            </section>
          ) : null}

          {rightPanel === "beads" ? (
            <section className="panel side-panel beads-panel">
              <div className="panel-header compact">
                <div>
                  <h2>Beads</h2>
                  <p className="panel-kicker">
                    {beadsReady === null ? "not checked" : beadsReady ? `${beadsIssues.length} task${beadsIssues.length === 1 ? "" : "s"}` : "not initialized"}
                  </p>
                </div>
                {beadsReady === false ? (
                  <button className="icon-button" type="button" onClick={() => void initBeads()} title="Initialize beads">
                    <CheckCircle2 size={16} />
                  </button>
                ) : null}
              </div>
              <form
                className="issue-create"
                onSubmit={(event) => {
                  event.preventDefault();
                  void createIssue();
                }}
              >
                <input
                  value={issueDraft.title}
                  onChange={(event) => setIssueDraft((draft) => ({ ...draft, title: event.target.value }))}
                  placeholder="New issue title"
                  disabled={!beadsReady}
                />
                <button className="primary-button" type="submit" disabled={!beadsReady || !issueDraft.title.trim() || beadsBusy}>
                  {beadsBusy ? <Loader2 className="spin" size={16} /> : <Play size={16} />}
                  Add
                </button>
                <div className="issue-create-meta">
                  <select
                    value={issueDraft.type}
                    onChange={(event) => setIssueDraft((draft) => ({ ...draft, type: event.target.value }))}
                    disabled={!beadsReady}
                    aria-label="Issue type"
                  >
                    <option value="task">task</option>
                    <option value="bug">bug</option>
                    <option value="feature">feature</option>
                    <option value="chore">chore</option>
                  </select>
                  <select
                    value={issueDraft.priority}
                    onChange={(event) => setIssueDraft((draft) => ({ ...draft, priority: Number(event.target.value) }))}
                    disabled={!beadsReady}
                    aria-label="Issue priority"
                  >
                    <option value={0}>P0</option>
                    <option value={1}>P1</option>
                    <option value={2}>P2</option>
                    <option value={3}>P3</option>
                    <option value={4}>P4</option>
                  </select>
                  <input
                    value={issueDraft.description}
                    onChange={(event) => setIssueDraft((draft) => ({ ...draft, description: event.target.value }))}
                    placeholder="Description"
                    disabled={!beadsReady}
                  />
                </div>
              </form>
              <div className="issue-list">
                {beadsReady === null ? (
                  <div className="empty-state stacked">
                    <Boxes size={18} />
                    <span>Load a project to check beads.</span>
                  </div>
                ) : beadsReady === false ? (
                  <div className="empty-state stacked">
                    <Boxes size={18} />
                    <span>Beads is not initialized.</span>
                    <button className="secondary-button" type="button" onClick={() => void initBeads()} disabled={beadsBusy}>
                      <CheckCircle2 size={16} />
                      Initialize
                    </button>
                  </div>
                ) : beadsIssues.length === 0 ? (
                  <div className="empty-state stacked">
                    <Boxes size={18} />
                    <span>No beads loaded.</span>
                  </div>
                ) : (
                  groupedIssues.map((group) => (
                    <section className="issue-group" key={group.status}>
                      <div className="issue-group-header">
                        <span>{issueStatusLabel(group.status)}</span>
                        <StatusPill label={String(group.issues.length)} tone="muted" />
                      </div>
                      {group.issues.map((issue) => {
                        const status = issueStatus(issue);
                        const isClosed = status === "closed";
                        const isActive = status === "in_progress";
                        return (
                          <div className="issue-row" key={issue.id}>
                            <div className="issue-main">
                              <div className="issue-titleline">
                                <strong>{issue.title}</strong>
                                <StatusPill label={issueStatusLabel(status)} tone={issueStatusTone(status)} />
                              </div>
                              <div className="issue-meta">
                                <span>{issue.id}</span>
                                <span>{issueType(issue)}</span>
                                <span>{priorityLabel(issue.priority)}</span>
                                {issue.assignee ? <span>{issue.assignee}</span> : null}
                              </div>
                              {issue.description ? <p className="issue-description">{issue.description}</p> : null}
                            </div>
                            <div className="issue-actions">
                              <button
                                className="icon-button"
                                type="button"
                                onClick={() => void updateIssueStatus(issue, isActive ? "open" : "in_progress")}
                                disabled={beadsBusy || isClosed}
                                title={isActive ? "Mark open" : "Start issue"}
                              >
                                {isActive ? <CircleAlert size={15} /> : <Play size={15} />}
                              </button>
                              <button
                                className="icon-button"
                                type="button"
                                onClick={() => void (isClosed ? updateIssueStatus(issue, "open") : closeIssue(issue))}
                                disabled={beadsBusy}
                                title={isClosed ? "Reopen issue" : "Close issue"}
                              >
                                {isClosed ? <Play size={15} /> : <CheckCircle2 size={15} />}
                              </button>
                              <button
                                className="icon-button danger"
                                type="button"
                                onClick={() => void deleteIssue(issue)}
                                disabled={beadsBusy}
                                title="Delete issue"
                              >
                                <Trash2 size={15} />
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </section>
                  ))
                )}
              </div>
            </section>
          ) : null}
        </aside>
      </div>
      <SetupWizard
        open={runtime?.setup_complete === false}
        projectPath={projectPath}
        onProjectPathChange={setProjectPath}
        onFinished={() => void refreshAll()}
      />
      {reportOpen && (
        <div className="setup-overlay" role="dialog" aria-modal="true" aria-label="Engagement report">
          <div className="report-frame">
            <div className="report-bar">
              <div>
                <h2>Engagement Report</h2>
                <p className="panel-kicker">{report?.name || engagement?.name || "—"}</p>
              </div>
              <div className="notes-actions">
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => void generateReport()}
                  disabled={reportBusy || !engagement?.active}
                  title="Regenerate report (writes report.md + Discord)"
                >
                  {reportBusy ? <Loader2 className="spin" size={16} /> : <RefreshCw size={16} />}
                  {report?.available ? "Regenerate" : "Generate"}
                </button>
                <button className="icon-button" type="button" onClick={() => setReportOpen(false)} title="Close">
                  <X size={16} />
                </button>
              </div>
            </div>
            <div className="report-body">
              {reportBusy && !report ? (
                <div className="empty-state stacked">
                  <Loader2 className="spin" size={18} />
                  <span>Loading report…</span>
                </div>
              ) : report?.available ? (
                <pre className="report-markdown">{report.markdown}</pre>
              ) : (
                <div className="empty-state stacked">
                  <FileText size={18} />
                  <span>
                    {engagement?.active
                      ? "No report generated yet for this engagement."
                      : "No active engagement — nothing to report."}
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
      {needsAuth && (
        <div className="setup-overlay" role="dialog" aria-modal="true" aria-label="Operator login">
          <div className="setup-frame">
            <section className="setup-card">
              <h2 className="brand-name">protoPen</h2>
              <p>Enter the operator API key to access the console.</p>
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  setOperatorKey(keyInput.trim());
                  setNeedsAuth(false);
                  void refreshAll();
                }}
              >
                <input
                  type="password"
                  value={keyInput}
                  onChange={(event) => setKeyInput(event.target.value)}
                  placeholder="x-api-key"
                  autoFocus
                  style={{ width: "100%", marginBottom: 12 }}
                />
                <button type="submit" disabled={!keyInput.trim()}>
                  Connect
                </button>
              </form>
            </section>
          </div>
        </div>
      )}
    </div>
  );
}

function StatusPill({ label, tone }: { label: string; tone: StatusTone }) {
  return <span className={`status-pill ${tone}`}>{label}</span>;
}

function RailButton({
  active,
  label,
  icon,
  onClick,
  badge = 0,
}: {
  active: boolean;
  label: string;
  icon: ReactNode;
  onClick: () => void;
  badge?: number;
}) {
  return (
    <button className={active ? "active" : ""} type="button" onClick={onClick} title={label} aria-label={label}>
      {icon}
      <span>{label}</span>
      {badge > 0 ? <span className="rail-badge">{badge > 99 ? "99+" : badge}</span> : null}
    </button>
  );
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="metric">
      {icon}
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
