# Companion Autonomy — Implementation Slices

> **Status: ACTIVE (2026-06-06).** Sequenced plan to make protoPen the
> autonomous-first companion from `2026-06-05-companion-ui-vision.md`. The HITL
> *console* shipped in PR #181; this plan builds the autonomy + gate behind it.

## Backend map (verified 2026-06-06)

Four mechanisms, traced end-to-end:

1. **Pause / `input_required`** — `a2a_executor.py` is a complete **consumer**
   (parks the task in `TASK_STATE_INPUT_REQUIRED`, rides the `hitl-v1` DataPart).
   **There is NO producer** — `server/chat.py:_chat_langgraph_stream` only yields
   `text/tool_start/tool_end/status/done/error`, never `input_required`. No
   `interrupt()` is used; the graph is a vanilla `create_agent`.
2. **Resume model** — resume = a **new `HumanMessage` on the same `thread_id`**
   ("without special handling"); the durable SQLite checkpointer
   (`agent_init._build_checkpointer` → `create_researcher_graph(checkpointer=)`)
   retains the agent's question across the park. **No `Command(resume=)`, no
   checkpointer surgery needed.**
3. **Enforcement gate** — `graph/middleware/enforcement.py:_enforce` runs before
   every tool, check 4 = `EngagementManager.is_allowed` (`tool_risk[name] <=
   mode.value`) → hard BLOCK on mode gap. The single chokepoint that sees every
   tool call + the current mode. `POST /api/engagement` flips the live singleton.
4. **Autonomy loop** — `GoalController` + the `while True` re-invocation loop in
   `_chat_langgraph_stream` already drives multi-turn self-driving toward a
   verifier-checked goal.

**Key seam:** contextvars only flow parent→child (server sets, tool reads — see
`graph/goals/context.py`). For a tool/middleware to signal the stream loop
(child→parent), use a **session-keyed module registry**, not a contextvar.

## Slice 1 — Agent-initiated HITL producer  ← THIS PR

Make the shipped HITL console live: the agent can pause and ask the operator.

- **`graph/hitl_context.py`** — a session-keyed pending registry:
  `request_pending_hitl(session_id, payload)` / `take_pending_hitl(session_id)`
  (module dict, popped by the loop). Mirrors the goals-context module.
- **Tools** (`tools/lg_tools.py`, read session via `get_current_session()`):
  - `request_user_input(prompt, fields=None, title=None)` → free-text **question**
    (no `fields`) or a **form** (`{kind:"form", title, steps: fields}`).
  - `request_approval(action, detail="")` → **approval** card
    (`{kind:"approval", title: action, detail}`).
  Each stashes the `hitl-v1` payload in the registry and returns "Paused — await
  the operator; do not continue." so the agent ends its turn.
- **`server/chat.py`** — after the `astream_events` loop, before the goal eval:
  `pending = take_pending_hitl(session_id); if pending: yield ("input_required",
  pending); return`. Parks ahead of goal continuation.
- **Resume** — already works: the operator's response arrives as a new message;
  the agent continues on-thread (sees its own request + the answer).
- **Tests** — payload shape per the `hitl-v1` contract (flat `{id,label,type}`
  steps); the loop parks when a request is pending.

Delivers the end-to-end loop and exercises all three card types (question /
form / approval) the console renders.

## Slice 2 — Enforcement approval gate  — DROPPED (operator decision 2026-06-06)

Decision: **keep agent self-escalation** of engagement mode (passive→active→
redteam), headless included — maximum autonomy. Today `tools/engagement.py:
_exec_set_mode` lets the agent set any mode freely and `engagement` is
enforcement-exempt; we are NOT gating that behind operator approval. The
enforcement gate stays a speed-bump the agent consciously steps past, and the
operator sets the mode ceiling up front when needed. `request_approval` (Slice 1)
remains for cases where the *agent itself* decides a human should weigh in.

## Slice 3 — Companion presence / status surface (frontend)

The Pwnagotchi "face" beat. A glanceable Home element: engagement state
(mode/target), what the agent is doing *now*, a pending-approval indicator,
recent-findings ticker. Consumes existing `/api/engagement`, `/api/activity`,
runtime status — mostly presentation.

## Later (vision backlog)

Engagement-as-object UI · Capabilities catalog (the B subtext) · IA rail
restructure to companion nouns (Home/Engagement/Findings/Activity/Capabilities/
System). See the vision doc.
