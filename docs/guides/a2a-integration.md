# A2A Integration

protoPen exposes an [Agent-to-Agent (A2A)](https://google.github.io/A2A/) JSON-RPC 2.0 endpoint that other agents (e.g. protoWorkstacean) can call to request pen testing or threat intelligence tasks.

Tasks are **fully asynchronous** — `message/send` returns a `submitted` task ID in under a second regardless of how long the underlying operation takes. Long-running LangGraph workflows (recon, audits, multi-step exploits) run in the background while callers poll or subscribe for results.

## Agent Card

The agent card is served at the well-known URL:

```
GET /.well-known/agent.json
```

```bash
curl http://steamdeck:7870/.well-known/agent.json | jq
```

The card advertises the agent name (`protopen`), capabilities (`streaming: true`, `pushNotifications: true`), and available skills.

## Skills

| Skill ID | Name | Description |
|---|---|---|
| `passive_recon` | Passive Reconnaissance | WiFi AP/station enumeration, RF survey, host discovery, service fingerprinting. Observation only. |
| `active_pentest` | Active Penetration Test | PMKID capture, vuln scanning, RF replay, RFID read/write. Requires active or redteam mode. |
| `security_report` | Security Report | Generate a professional assessment report from engagement findings. |
| `threat_intel` | Threat Intelligence | Search CVE databases, security feeds, GitHub, web, and internal knowledge store. Returns structured findings. |
| `summarize` | Summarize | Summarize recent advisories, threat intel, or exploits from the knowledge store. |

## Task Lifecycle

```
submitted → working → completed
                    ↘ failed
                    ↘ canceled
```

Every task transitions through these states. `submitted` is set the moment `message/send` returns. `working` is set when the LangGraph agent begins executing. Terminal states (`completed`, `failed`, `canceled`) are set when the background task finishes.

## Sending a Message

### JSON-RPC (POST /a2a)

Submit a task and get back a task ID immediately:

```bash
curl -X POST http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"kind": "text", "text": "Scan the 192.168.1.0/24 subnet for open services"}]
      },
      "contextId": "engagement-001"
    }
  }'
```

Response (immediate, <1s):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "id": "3f8a1c2d-...",
    "contextId": "engagement-001",
    "status": {"state": "submitted"},
    "artifacts": []
  }
}
```

### REST alias (POST /message:send)

Same behavior, no JSON-RPC wrapper:

```bash
curl -X POST http://steamdeck:7870/message:send \
  -H "Content-Type: application/json" \
  -d '{"message":{"parts":[{"kind":"text","text":"Scan 192.168.1.0/24"}]},"contextId":"eng-001"}'
```

Returns `HTTP 202 Accepted` with the task record.

## Polling for Results

After submitting, poll `GET /tasks/{id}` until the state is terminal:

```bash
TASK_ID="3f8a1c2d-..."

while true; do
  STATE=$(curl -s http://steamdeck:7870/tasks/$TASK_ID | jq -r '.status.state')
  echo "State: $STATE"
  [[ "$STATE" == "completed" || "$STATE" == "failed" || "$STATE" == "canceled" ]] && break
  sleep 5
done

# Fetch the result
curl -s http://steamdeck:7870/tasks/$TASK_ID | jq '.artifacts[0].parts[0].text'
```

**Response shape:**

```json
{
  "id": "3f8a1c2d-...",
  "contextId": "engagement-001",
  "status": {"state": "completed"},
  "artifacts": [
    {"parts": [{"kind": "text", "text": "## Scan Results\n\n..."}]}
  ]
}
```

## Streaming (SSE)

### JSON-RPC stream (POST /a2a, method: message/sendStream)

```bash
curl -N -X POST http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "message/sendStream",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"kind": "text", "text": "Research the latest critical CVEs affecting network infrastructure"}]
      },
      "contextId": "research-session-42"
    }
  }'
```

### REST stream alias (POST /message:stream)

```bash
curl -N -X POST http://steamdeck:7870/message:stream \
  -H "Content-Type: application/json" \
  -d '{"message":{"parts":[{"kind":"text","text":"Passive recon 192.168.1.0/24"}]},"contextId":"eng-001"}'
```

### SSE event sequence

The **first frame is always `submitted`** — clients can extract the task ID from it and use polling as a fallback if the stream drops:

```
data: {"jsonrpc":"2.0","id":2,"result":{"id":"<task-uuid>","status":{"state":"submitted"},"artifacts":[]}}

data: {"jsonrpc":"2.0","id":2,"result":{"id":"<task-uuid>","status":{"state":"working"}}}

data: {"jsonrpc":"2.0","id":2,"result":{"artifact":{"parts":[{"kind":"text","text":"Scanning..."}]},"append":true,"lastChunk":false}}

data: {"jsonrpc":"2.0","id":2,"result":{"artifact":{"parts":[{"kind":"text","text":"## Results\n\n..."}]},"append":true,"lastChunk":true}}

data: {"jsonrpc":"2.0","id":2,"result":{"id":"<task-uuid>","status":{"state":"completed"}}}
```

## Reconnecting to a Running Task

If the SSE stream drops, reconnect via the subscribe endpoint — it will replay the current state and continue streaming:

```bash
curl -N http://steamdeck:7870/tasks/3f8a1c2d-...:subscribe
```

The subscribe stream closes automatically when the task reaches a terminal state.

## Canceling a Task

```bash
curl -X POST http://steamdeck:7870/tasks/3f8a1c2d-...:cancel
```

- `200 OK` — task was canceled
- `409 Conflict` — task already in a terminal state (completed/failed)
- `404 Not Found` — unknown task ID

## Push Notifications (Webhooks)

Register a webhook to receive state change events without polling. The server POSTs to your URL on each state transition (working, completed, failed).

### Register a webhook

```bash
curl -X POST "http://steamdeck:7870/tasks/3f8a1c2d-.../pushNotificationConfigs" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://your-server.example.com/hooks/protopen", "token": "YOUR_SECRET_TOKEN"}'
```

Or include `pushNotification` in the initial `message/send` params:

```bash
curl -X POST http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
      "message": {"role": "user", "parts": [{"kind": "text", "text": "Run audit"}]},
      "pushNotification": {
        "url": "https://your-server.example.com/hooks/protopen",
        "token": "YOUR_SECRET_TOKEN"
      }
    }
  }'
```

### Webhook payload

```json
{
  "task_id": "3f8a1c2d-...",
  "context_id": "engagement-001",
  "status": {"state": "completed"},
  "artifact": {
    "parts": [{"kind": "text", "text": "## Results\n\n..."}]
  }
}
```

The `artifact` field is only included for `completed` tasks. The `Authorization: Bearer <token>` header is set if a token was provided.

Delivery is retried up to 3 times with exponential backoff on non-2xx responses.

## Conversation Continuity

Use `contextId` to maintain conversation state across multiple calls. The LangGraph backend persists sessions in SQLite, so context survives container restarts.

```bash
# First message
curl -X POST http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"Start a passive recon of the office WiFi"}]},"contextId":"office-audit"}}'

# Follow-up uses the same contextId
curl -X POST http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"Now show me which APs have weak encryption"}]},"contextId":"office-audit"}}'
```

## Authentication

Authentication is optional. When `PROTOPEN_API_KEY` is set in the environment, all A2A requests must include the key:

```
x-api-key: <your-key>
```

Requests without a valid key receive a `401 Unauthorized` response.

::: warning
If no API key is configured, the A2A endpoint is open to anyone who can reach the port. On the Steam Deck, this is typically fine on a private network but not suitable for public exposure.
:::

## Best Practices

### Use streaming or webhooks for long tasks

Recon, audits, and multi-step exploits can take 5–10 minutes. Rather than polling every few seconds, use one of:

- **SSE streaming** (`message/sendStream` or `POST /message:stream`) — get incremental output as the agent works
- **Webhooks** — register a push notification config and receive a POST when the task completes
- **Subscribe endpoint** (`GET /tasks/{id}:subscribe`) — reconnect to a running task's SSE stream at any point

### Extract task ID from the first SSE frame

The first SSE frame always carries state `submitted` with the task ID. Extract it before consuming the rest of the stream — you can use it as a fallback polling handle if the connection drops.

### Prefer Tailscale over SSH

Use `http://steamdeck:7870/a2a` directly over the Tailscale network instead of SSH tunneling. Benefits:

- Lower latency — no SSH connection overhead
- Encrypted via WireGuard — same security as SSH
- Simpler automation — just `curl`, no `ssh` wrapper
- Works from any device on the tailnet

### Context ID hygiene

Always provide a meaningful `contextId` to maintain conversation state. If omitted, the server generates a random UUID — fine for one-shot calls, but you lose the ability to send follow-up messages in the same conversation.

Avoid reusing generic context IDs across sessions. The LangGraph checkpointer persists conversation state in SQLite, so a corrupted session on one context ID will poison all future requests on that same ID.
