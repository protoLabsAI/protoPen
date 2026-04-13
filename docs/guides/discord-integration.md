# Discord Integration

protoPen integrates with Discord in three ways: a Gateway bot for interactive analysis, a webhook for publishing reports and digests, and a feed scanner for reading channel history.

## Components

| Component | File | Purpose |
|---|---|---|
| **Discord Bot** | `discord_bot.py` | Gateway bot — responds to @mentions and 🔒 reactions with security analysis in threads |
| **Discord Feed Tool** | `tools/discord_feed.py` | Agent-callable tool for publishing embeds and scanning channels |
| **`/intel` Command** | `server.py` | Chat command that generates and publishes a threat intel digest |

## Webhook Publishing

The primary mechanism for pushing content to Discord. Used for security reports, threat intel digests, and engagement summaries.

### Setup

1. **Create a webhook** in your target Discord channel (Channel Settings → Integrations → Webhooks)
2. **Store the URL** in Infisical under the `DISCORD_WEBHOOK_URL` key (protoPen `prod` environment)
3. **Restart protoPen** so `start.sh` fetches the new secret

The webhook is used by:
- `discord_feed action=publish` — posts content as rich embeds (auto-chunks at 4096 chars)
- `/intel` chat command — publishes a formatted security intelligence digest
- Engagement alerts — critical/high findings trigger webhook notifications

### Publishing via the Agent

```
Publish the engagement report to Discord
```

The agent calls `discord_feed action=publish content="..." title="..."` which:
1. Splits content into 4096-character chunks (Discord embed description limit)
2. Creates an embed per chunk; first embed gets the title
3. Sends in batches of 10 embeds per webhook POST
4. Uses `INSTANCE_NAME` for the webhook username (e.g., "protoPen [steamdeck]")

### Publishing via A2A

Other agents can trigger Discord publishing by sending a message via the A2A endpoint:

```bash
curl -X POST http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"kind": "text", "text": "Publish the latest engagement report to Discord"}]
      }
    }
  }'
```

## Discord Bot

The bot connects via the Discord Gateway (WebSocket) and provides interactive security analysis.

### Triggers

- **@mention** — mention the bot in any channel; it analyzes the message (plus thread/reply context) and responds in a new thread
- **🔒 reaction** — react with 🔒 to any message; the bot analyzes that message's content and embeds

### Setup

Set `DISCORD_BOT_TOKEN` in Infisical. The bot starts automatically as a daemon thread when the server launches.

Required Gateway intents: `GUILDS`, `GUILD_MESSAGES`, `GUILD_MESSAGE_REACTIONS`, `MESSAGE_CONTENT`.

## Channel Scanning

The `discord_feed` tool can read channel history for security intelligence gathering:

| Action | Description |
|---|---|
| `scan` | Extract and classify URLs from messages |
| `history` | Raw message history |
| `channels` | List channels in a guild |
| `digest` | Structured link digest |

These actions require `DISCORD_BOT_TOKEN` and a `channel_id` parameter.

## Environment Variables

| Variable | Purpose |
|---|---|
| `DISCORD_BOT_TOKEN` | Bot authentication for Gateway + REST API |
| `DISCORD_WEBHOOK_URL` | Webhook URL for publishing embeds (managed via Infisical) |
| `INSTANCE_NAME` | Tags webhook messages with the instance name |

## Current Webhook

| Property | Value |
|---|---|
| **Name** | protoPen Security Reports |
| **Channel** | `1493168494945243227` |
| **Guild** | `1070606339363049492` |
| **Secret** | `DISCORD_WEBHOOK_URL` in Infisical (`prod`) |
