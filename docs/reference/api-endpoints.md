# API Endpoints

All HTTP endpoints exposed by the protoPen server (default port `7870`, mapped to `7872` in standard Docker Compose, `7870` in lab profile).

The REST surface below is **generated from the OpenAPI spec** at [`openapi.json`](/openapi.json) by `scripts/gen_api_docs.py`. Regenerate the spec from the live app with `python -m server --dump-openapi docs/public/openapi.json` after changing a route; CI fails if this page drifts from the spec. The Agent-to-Agent (A2A) JSON-RPC surface is mounted separately and is not part of the OpenAPI schema, so it is documented by hand below — see the [A2A Integration guide](../guides/a2a-integration.md) for worked examples.

**Authentication:** when `PROTOPEN_API_KEY` (or `RESEARCHER_API_KEY`) is set, every `/api/*` route requires a matching `x-api-key` header — a `401` drives the operator console's login gate. When unset (local dev) the routes are open. The universal `x-api-key` header is omitted from the per-endpoint parameter tables below.

## Chat UI

### `GET /`

Serves the Gradio chat UI (PWA-enabled). This is the primary user interface.

---

## REST API

<!-- BEGIN GENERATED API — run: python scripts/gen_api_docs.py -->

_39 endpoints, generated from [`openapi.json`](/openapi.json) (spec 3.1.0, protoPen — protoLabs 0.1.0) — do not edit by hand._

### Chat

#### `POST /api/chat`

Chat (programmatic)

**Request body** (`ChatRequest`)

| Field | Type | Required |
|---|---|---|
| `message` | string | yes |
| `session_id` | string | no |

**Responses:** `200` Successful Response, `422` Validation Error

#### `GET /api/chat/commands`

List chat slash-commands

**Responses:** `200` Successful Response

### OpenAI-Compatible API

#### `POST /v1/chat/completions`

OpenAI-compatible chat completions

**Request body**

**Responses:** `200` Successful Response, `422` Validation Error

#### `GET /v1/models`

List models (OpenAI-compatible)

**Responses:** `200` Successful Response

### Runtime

#### `GET /api/runtime/status`

Runtime status

**Responses:** `200` Successful Response

### Subagents

#### `GET /api/subagents`

List subagents

**Responses:** `200` Successful Response

#### `POST /api/subagents/batch`

Run subagents concurrently

**Request body** (`SubagentBatchRequest`)

| Field | Type | Required |
|---|---|---|
| `session_id` | string | no |
| `tasks` | object[] | yes |

**Responses:** `200` Successful Response, `422` Validation Error

#### `POST /api/subagents/run`

Run a subagent

**Request body** (`SubagentRunRequest`)

| Field | Type | Required |
|---|---|---|
| `session_id` | string | no |
| `type` | string | no |
| `description` | string | no |
| `prompt` | string | yes |
| `emit_skill` | boolean | no |

**Responses:** `200` Successful Response, `422` Validation Error

### Live Agents

#### `GET /api/agents`

List agent runs

**Responses:** `200` Successful Response

#### `POST /api/agents/launch`

Launch a tracked agent

**Request body** (`SubagentRunRequest`)

| Field | Type | Required |
|---|---|---|
| `session_id` | string | no |
| `type` | string | no |
| `description` | string | no |
| `prompt` | string | yes |
| `emit_skill` | boolean | no |

**Responses:** `200` Successful Response, `422` Validation Error

#### `GET /api/agents/{task_id}`

Get an agent run

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `task_id` | path | yes | string |  |

**Responses:** `200` Successful Response, `422` Validation Error

#### `POST /api/agents/{task_id}/cancel`

Cancel an agent run

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `task_id` | path | yes | string |  |

**Responses:** `200` Successful Response, `422` Validation Error

### Engagement

#### `GET /api/engagement`

Engagement snapshot

**Responses:** `200` Successful Response

#### `GET /api/engagement/report`

Read engagement report

**Responses:** `200` Successful Response

#### `POST /api/engagement/report`

Generate engagement report

**Responses:** `200` Successful Response

### Knowledge

#### `GET /api/knowledge/search`

Search the knowledge store

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `q` | query | yes | string |  |
| `k` | query | no | integer | `10` |
| `table` | query | no | string |  |

**Responses:** `200` Successful Response, `422` Validation Error

### Audit

#### `GET /api/audit/recent`

Recent audit entries

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `n` | query | no | integer | `50` |
| `session_id` | query | no | string |  |

**Responses:** `200` Successful Response, `422` Validation Error

### Scheduler

#### `GET /api/scheduler/jobs`

List scheduled jobs

**Responses:** `200` Successful Response

#### `POST /api/scheduler/jobs`

Schedule a job

**Request body** (`ScheduleAddRequest`)

| Field | Type | Required |
|---|---|---|
| `prompt` | string | yes |
| `schedule` | string | yes |
| `job_id` | string | no |

**Responses:** `200` Successful Response, `422` Validation Error

#### `DELETE /api/scheduler/jobs/{job_id}`

Cancel a scheduled job

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `job_id` | path | yes | string |  |

**Responses:** `200` Successful Response, `422` Validation Error

### Notes

#### `GET /api/notes/workspace`

Load notes workspace

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `project_path` | query | yes | string |  |

**Responses:** `200` Successful Response, `422` Validation Error

#### `POST /api/notes/workspace`

Save notes workspace

**Request body** (`NotesSaveRequest`)

| Field | Type | Required |
|---|---|---|
| `project_path` | string | yes |
| `workspace` | object | yes |

**Responses:** `200` Successful Response, `422` Validation Error

### Beads

#### `POST /api/beads/init`

Initialize beads

**Request body** (`BeadsInitRequest`)

| Field | Type | Required |
|---|---|---|
| `project_path` | string | yes |
| `prefix` | string | no |

**Responses:** `200` Successful Response, `422` Validation Error

#### `GET /api/beads/issues`

List beads issues

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `project_path` | query | yes | string |  |

**Responses:** `200` Successful Response, `422` Validation Error

#### `POST /api/beads/issues`

Create a beads issue

**Request body** (`BeadsCreateRequest`)

| Field | Type | Required |
|---|---|---|
| `project_path` | string | yes |
| `title` | string | yes |
| `type` | string | no |
| `priority` | integer | no |
| `description` | string | no |
| `assignee` | string | no |

**Responses:** `200` Successful Response, `422` Validation Error

#### `DELETE /api/beads/issues/{issue_id}`

Delete a beads issue

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `issue_id` | path | yes | string |  |
| `project_path` | query | yes | string |  |

**Responses:** `200` Successful Response, `422` Validation Error

#### `PATCH /api/beads/issues/{issue_id}`

Update a beads issue

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `issue_id` | path | yes | string |  |

**Request body** (`BeadsUpdateRequest`)

| Field | Type | Required |
|---|---|---|
| `project_path` | string | yes |
| `title` | string | no |
| `description` | string | no |
| `status` | string | no |
| `priority` | integer | no |
| `type` | string | no |
| `assignee` | string | no |

**Responses:** `200` Successful Response, `422` Validation Error

#### `POST /api/beads/issues/{issue_id}/close`

Close a beads issue

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `issue_id` | path | yes | string |  |

**Request body** (`BeadsCloseRequest`)

| Field | Type | Required |
|---|---|---|
| `project_path` | string | yes |
| `reason` | string | no |

**Responses:** `200` Successful Response, `422` Validation Error

#### `GET /api/beads/status`

Beads status

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `project_path` | query | yes | string |  |

**Responses:** `200` Successful Response, `422` Validation Error

### Activity

#### `GET /api/activity`

Activity thread history (ADR 0003)

**Responses:** `200` Successful Response

### Engagements

#### `GET /api/engagements`

Engagement history

**Responses:** `200` Successful Response

### Events

#### `GET /api/events`

Server→client event stream (SSE)

**Responses:** `200` Successful Response

### Intel

#### `GET /api/intel/search`

Unified intel search

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `q` | query | yes | string |  |
| `k` | query | no | integer | `20` |

**Responses:** `200` Successful Response, `422` Validation Error

### Playbooks

#### `GET /api/playbooks`

List playbooks

**Responses:** `200` Successful Response

#### `POST /api/playbooks/{name}/run`

Run a playbook

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `name` | path | yes | string |  |

**Request body**

**Responses:** `200` Successful Response, `422` Validation Error

### Targets

#### `GET /api/targets`

List discovered targets

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `q` | query | no | string |  |
| `device_type` | query | no | string |  |
| `limit` | query | no | integer | `50` |

**Responses:** `200` Successful Response, `422` Validation Error

#### `GET /api/targets/{host_id}`

Target profile

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `host_id` | path | yes | integer |  |

**Responses:** `200` Successful Response, `422` Validation Error

### Workflows

#### `GET /api/workflows`

List workflow recipes (ADR 0002)

**Responses:** `200` Successful Response

#### `POST /api/workflows/{name}/run`

Run a workflow recipe (ADR 0002)

**Parameters**

| Name | In | Required | Type | Default |
|---|---|---|---|---|
| `name` | path | yes | string |  |

**Request body**

**Responses:** `200` Successful Response, `422` Validation Error

<!-- END GENERATED API -->

> The Targets / Intel / Playbooks / Workflows routes above are operator-key-gated
> (`x-api-key`). `POST /api/playbooks/{name}/run` returns **`409`** when the
> engagement/scope gate blocks an offensive fire — see [Playbooks](./playbooks.md).

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
