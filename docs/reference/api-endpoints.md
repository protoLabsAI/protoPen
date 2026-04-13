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
  "model": "protoresearcher",
  "messages": [
    {"role": "user", "content": "What are the latest MoE papers?"}
  ],
  "stream": false
}
```

**Response (non-streaming):**

```json
{
  "id": "protoresearcher-openai-compat-1712956800",
  "object": "chat.completion",
  "created": 1712956800,
  "model": "protoresearcher",
  "choices": [
    {
      "index": 0,
      "message": {"role": "assistant", "content": "Here are the recent MoE papers..."},
      "finish_reason": "stop"
    }
  ],
  "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
}
```

**Response (streaming, `"stream": true`):**

Server-Sent Events:

```
data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{"role":"assistant","content":"Here are..."},"finish_reason":null}]}

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
      "id": "protoresearcher",
      "object": "model",
      "created": 1774600000,
      "owned_by": "protolabs"
    }
  ]
}
```

---

## Agent-to-Agent (A2A)

### `GET /.well-known/agent.json`

Returns the A2A agent card describing protoPen's capabilities and skills.

**Response:**

```json
{
  "name": "protopen",
  "description": "Autonomous pen testing and AI research agent...",
  "url": "http://steamdeck:7870",
  "provider": {"organization": "protoLabsAI"},
  "version": "2.0",
  "capabilities": {"streaming": true, "pushNotifications": false},
  "skills": [
    {"id": "passive_recon", "name": "Passive Reconnaissance", "...": "..."},
    {"id": "active_pentest", "name": "Active Penetration Test", "...": "..."},
    {"id": "security_report", "name": "Security Report", "...": "..."},
    {"id": "deep_research", "name": "Deep Research", "...": "..."},
    {"id": "summarize", "name": "Summarize", "...": "..."}
  ]
}
```

### `POST /a2a`

JSON-RPC 2.0 endpoint for agent-to-agent communication.

**Methods:**

| Method | Description |
|---|---|
| `message/send` | Synchronous -- waits for full response |
| `message/sendStream` | SSE streaming -- returns incremental progress events |

See the [A2A Integration guide](../guides/a2a-integration.md) for curl examples.

**Headers:**

| Header | Required | Description |
|---|---|---|
| `Content-Type` | yes | `application/json` |
| `x-api-key` | conditional | Required when `PROTOPEN_API_KEY` / `RESEARCHER_API_KEY` is set |

---

## Observability

### `GET /metrics`

Prometheus metrics endpoint (requires `prometheus-client` package).

Exposed metrics:

| Metric | Type | Labels | Description |
|---|---|---|---|
| `protoresearcher_llm_calls_total` | Counter | `model`, `finish_reason` | Total LLM API calls |
| `protoresearcher_llm_latency_seconds` | Histogram | `model` | LLM call latency |
| `protoresearcher_llm_tokens_total` | Counter | `model`, `direction` | Tokens consumed (input/output) |
| `protoresearcher_tool_calls_total` | Counter | `tool_name`, `success` | Total tool executions |
| `protoresearcher_tool_latency_seconds` | Histogram | `tool_name` | Tool execution latency |
| `protoresearcher_active_sessions` | Gauge | -- | Currently active chat sessions |
