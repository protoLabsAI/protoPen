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
