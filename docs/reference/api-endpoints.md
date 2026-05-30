# API Endpoints

All HTTP endpoints exposed by the protoPen server (default port `7870`, mapped to `7872` in standard Docker Compose, `7870` in lab profile).

## Chat UI

### `GET /`

Serves the Gradio chat UI (PWA-enabled). This is the primary user interface.

---

## Chat API

### `POST /api/chat`

Programmatic chat access for evals and scripts.

**Request:**

```json
{
  "message": "Scan 192.168.1.0/24 for open services",
  "session_id": "my-session-01"
}
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `message` | string | yes | -- | The user message |
| `session_id` | string | no | `"api-default"` | Session identifier for conversation continuity |

**Response:**

```json
{
  "response": "## Scan Results\n\nFound 12 live hosts...",
  "messages": [
    {"role": "assistant", "content": "## Scan Results\n\nFound 12 live hosts..."}
  ]
}
```

---

## OpenAI-Compatible API

These endpoints allow protoPen to be registered as a model in LiteLLM Gateway or OpenWebUI.

### `POST /v1/chat/completions`

OpenAI-compatible chat completions endpoint. Supports both streaming and non-streaming modes.

**Request:**

```json
{
  "model": "protopen",
  "messages": [
    {"role": "user", "content": "What are the latest critical CVEs affecting Linux?"}
  ],
  "stream": false
}
```

**Response (non-streaming):**

```json
{
  "id": "protopen-openai-compat-1712956800",
  "object": "chat.completion",
  "created": 1712956800,
  "model": "protopen",
  "choices": [
    {
      "index": 0,
      "message": {"role": "assistant", "content": "Here are the recent critical CVEs..."},
      "finish_reason": "stop"
    }
  ],
  "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
}
```

**Response (streaming, `"stream": true`):**

Server-Sent Events:

```
data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{"role":"assistant","content":"Here are the..."},"finish_reason":null}]}

data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{},"finish_reason":"stop"}]}

data: [DONE]
```

### `GET /v1/models`

Lists available models.

**Response:**

```json
{
  "object": "list",
  "data": [
    {
      "id": "protopen",
      "object": "model",
      "created": 1774600000,
      "owned_by": "protolabs"
    }
  ]
}
```

---

## Agent-to-Agent (A2A)

All A2A tasks are fully async. `message/send` and `POST /message:send` return `submitted` in under a second; the LangGraph agent runs in the background. See the [A2A Integration guide](../guides/a2a-integration.md) for full workflow examples.

**Common headers:**

| Header | Required | Description |
|---|---|---|
| `Content-Type` | yes | `application/json` |
| `x-api-key` | conditional | Required when `PROTOPEN_API_KEY` is set |

---

### `GET /.well-known/agent.json`

Returns the A2A agent card describing protoPen's capabilities and skills.

**Response:**

```json
{
  "name": "protopen",
  "description": "Autonomous pen testing and security research agent...",
  "url": "http://steamdeck:7870",
  "provider": {"organization": "protoLabsAI"},
  "version": "2.0",
  "capabilities": {"streaming": true, "pushNotifications": true},
  "skills": [
    {"id": "passive_recon", "name": "Passive Reconnaissance", "...": "..."},
    {"id": "active_pentest", "name": "Active Penetration Test", "...": "..."},
    {"id": "security_report", "name": "Security Report", "...": "..."},
    {"id": "threat_intel", "name": "Threat Intelligence", "...": "..."},
    {"id": "summarize", "name": "Summarize", "...": "..."}
  ]
}
```

---

### `POST /a2a`

JSON-RPC 2.0 envelope. Dispatches to the method named in `"method"`.

**Methods:**

| Method | Description |
|---|---|
| `message/send` | Submit task — returns `submitted` immediately, runs in background |
| `message/sendStream` | Submit task and stream SSE events; first frame is always `submitted` |

---

### `POST /message:send`

REST alias for `message/send`. Returns `HTTP 202 Accepted` with the task record (no JSON-RPC wrapper).

**Request body:**

```json
{
  "message": {"parts": [{"kind": "text", "text": "your prompt"}]},
  "contextId": "optional-session-id",
  "pushNotification": {"url": "https://...", "token": "optional-bearer-token"}
}
```

---

### `POST /message:stream`

REST alias for `message/sendStream`. Returns `text/event-stream`. First SSE frame carries `submitted` state + task ID.

---

### `GET /tasks/{id}`

Poll task status and retrieve artifacts once complete.

**Response:**

```json
{
  "id": "3f8a1c2d-...",
  "contextId": "engagement-001",
  "status": {"state": "completed"},
  "artifacts": [{"parts": [{"kind": "text", "text": "..."}]}]
}
```

**Status codes:** `200 OK`, `404 Not Found`

---

### `GET /tasks/{id}:subscribe`

Subscribe to a running task's SSE stream. Replays current state on connect and streams updates until the task reaches a terminal state. Use this to reconnect after a dropped stream.

---

### `POST /tasks/{id}:cancel`

Request cancellation of a running task.

**Status codes:**
- `200 OK` — canceled
- `409 Conflict` — task already in terminal state
- `404 Not Found` — unknown task ID

---

### `POST /tasks/{id}/pushNotificationConfigs`

Register a webhook URL to receive state-change POSTs (working, completed, failed). Delivery retried up to 3× with exponential backoff.

**Request body:**

```json
{"url": "https://your-server.example.com/hook", "token": "optional-bearer-token"}
```

---

## Observability

### `GET /metrics`

Prometheus metrics endpoint (requires `prometheus-client` package).

Exposed metrics:

| Metric | Type | Labels | Description |
|---|---|---|---|
| `protopen_llm_calls_total` | Counter | `model`, `finish_reason` | Total LLM API calls |
| `protopen_llm_latency_seconds` | Histogram | `model` | LLM call latency |
| `protopen_llm_tokens_total` | Counter | `model`, `direction` | Tokens consumed (input/output) |
| `protopen_tool_calls_total` | Counter | `tool_name`, `success` | Total tool executions |
| `protopen_tool_latency_seconds` | Histogram | `tool_name` | Tool execution latency |
| `protopen_active_sessions` | Gauge | -- | Currently active chat sessions |

## Operator Console API

Routes that back the webview operator console (served at `/app`). When
`PROTOPEN_API_KEY` (or `RESEARCHER_API_KEY`) is set, **every** route below
requires a matching `x-api-key` header; a `401` drives the console's login gate.
When unset (local dev) the routes are open.

### Runtime & subagents

| Method / Path | Description |
|---|---|
| `GET /api/runtime/status` | Model, identity, middleware, knowledge, scheduler, and goal-mode status. |
| `GET /api/subagents` | Registered subagents (name, description, tools, max turns, enabled). |
| `POST /api/subagents/run` | Run one subagent synchronously. Body: `{session_id, type, description, prompt, emit_skill}` → `{ok, session_id, output}`. |
| `POST /api/subagents/batch` | Run independent subagent tasks concurrently. Body: `{session_id, tasks:[{type, description, prompt, emit_skill}]}`. |

### Live agent monitoring

Manual subagents launched as tracked, cancellable background tasks.

| Method / Path | Description |
|---|---|
| `POST /api/agents/launch` | Launch a subagent asynchronously. Body as `/api/subagents/run` → `{task_id}`. |
| `GET /api/agents` | All tracked runs, newest first (`id, type, description, status, started_at, ended_at, duration_ms, output, error`). `status` ∈ `running`/`done`/`error`/`cancelled`. |
| `GET /api/agents/{task_id}` | One run, or `404` if unknown. |
| `POST /api/agents/{task_id}/cancel` | Cancel a running task → `{cancelled: bool}`. |

### Knowledge search

| Method / Path | Description |
|---|---|
| `GET /api/knowledge/search?q=&k=&table=` | Hybrid search (vector + BM25, RRF) over the threat-intel store. `k` clamped 1–50; `table` ∈ `cves`/`exploits`/`advisories`/`threat_intel`/`topics`/`digests`. Returns `{query, table, count, hits:[{table, source_id, preview, score}]}`. |

### Audit trail

| Method / Path | Description |
|---|---|
| `GET /api/audit/recent?n=&session_id=` | Newest-first tool-execution entries (`ts, session_id, tool, success, duration_ms, result_summary, trace_id, args`) + a window `summary`. `n` clamped 1–200. |

### Engagement monitor

| Method / Path | Description |
|---|---|
| `GET /api/engagement` | Live engagement snapshot — `active, name, scope, mode, phase, finding_counts, total_findings, findings:[{severity, category, title, detail, timestamp}]`. |
| `GET /api/engagement/report` | Read the generated `report.md` (side-effect-free) → `{available, name, path, markdown}`. |
| `POST /api/engagement/report` | (Re)generate the report — writes `report.md` and delivers to Discord; `409` if no active engagement. |

### Notes & beads

| Method / Path | Description |
|---|---|
| `GET /api/notes/workspace?project_path=` | Load the project notes workspace. |
| `POST /api/notes/workspace` | Save the workspace. Body: `{project_path, workspace}`. |
| `GET /api/beads/status?project_path=` | Whether beads is initialized for the project. |
| `POST /api/beads/init` | Initialize beads. Body: `{project_path, prefix?}`. |
| `GET /api/beads/issues?project_path=` | List issues. |
| `POST /api/beads/issues` | Create an issue. Body: `{project_path, title, type?, priority?, description?, assignee?}`. |
| `PATCH /api/beads/issues/{id}` | Update an issue (status, priority, …). |
| `POST /api/beads/issues/{id}/close` | Close an issue. |
| `DELETE /api/beads/issues/{id}?project_path=` | Delete an issue. |
