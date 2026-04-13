# A2A Integration

protoPen exposes an [Agent-to-Agent (A2A)](https://google.github.io/A2A/) JSON-RPC 2.0 endpoint that other agents (e.g. protoWorkstacean) can call to request pen testing or threat intelligence tasks.

## Agent Card

The agent card is served at the well-known URL:

```
GET /.well-known/agent.json
```

```bash
curl http://steamdeck:7870/.well-known/agent.json | jq
```

The card advertises the agent name (`protopen`), capabilities, and available skills.

## Skills

| Skill ID | Name | Description |
|---|---|---|
| `passive_recon` | Passive Reconnaissance | WiFi AP/station enumeration, RF survey, host discovery, service fingerprinting. Observation only. |
| `active_pentest` | Active Penetration Test | PMKID capture, vuln scanning, RF replay, RFID read/write. Requires active or redteam mode. |
| `security_report` | Security Report | Generate a professional assessment report from engagement findings. |
| `threat_intel` | Threat Intelligence | Search CVE databases, security feeds, GitHub, web, and internal knowledge store. Returns structured findings. |
| `summarize` | Summarize | Summarize recent advisories, threat intel, or exploits from the knowledge store. |

## Sending a Message

### Synchronous (message/send)

Sends a message and waits for the full response:

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "id": "<task-uuid>",
    "contextId": "engagement-001",
    "status": {"state": "completed"},
    "artifacts": [
      {"parts": [{"kind": "text", "text": "## Scan Results\n\n..."}]}
    ]
  }
}
```

### Streaming (message/sendStream)

Returns Server-Sent Events with incremental progress:

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

Events arrive as SSE:

```
data: {"jsonrpc":"2.0","id":2,"result":{"id":"<task-uuid>","status":{"state":"working"},...}}

data: {"jsonrpc":"2.0","id":2,"result":{"id":"<task-uuid>","status":{"state":"completed"},"artifacts":[...]}}
```

::: tip
Streaming requires the LangGraph backend (`AGENT_BACKEND=langgraph`). If nanobot is active, `message/sendStream` falls back to a single completed event.
:::

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

### Prefer Tailscale over SSH

Use `http://steamdeck:7870/a2a` directly over the Tailscale network instead of SSH tunneling. Benefits:

- Lower latency — no SSH connection overhead
- Encrypted via WireGuard — same security as SSH
- Simpler automation — just `curl`, no `ssh` wrapper
- Works from any device on the tailnet

### Context ID hygiene

Always provide a meaningful `contextId` to maintain conversation state. If omitted, the server generates a random UUID — fine for one-shot calls, but you lose the ability to send follow-up messages in the same conversation.

Avoid reusing generic context IDs across sessions. The LangGraph checkpointer persists conversation state in SQLite, so a corrupted session on one context ID will poison all future requests on that same ID.

### Timeout guidance

- Simple queries (ping, status): 15–30s
- Tool execution (nmap, tshark, CIS audit): 2–5 min
- Multi-tool workflows (purple team exercise): 5–10 min

Set `curl --max-time` accordingly, or use `message/sendStream` for long-running tasks to get incremental progress.
