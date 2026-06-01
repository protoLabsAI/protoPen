# Chat Commands

Slash commands available in the protoPen chat UI. These are handled locally before reaching the agent backend.

| Command | Arguments | Description |
|---|---|---|
| `/new` | -- | Clear chat history and start a new session. Resets the session ID. |
| `/clear` | -- | Clear the chat display. Session and history are preserved server-side. |
| `/think <level>` | `low`, `medium`, `high`, `off` | Set the LLM reasoning effort level. `off` disables extended thinking. |
| `/compact` | -- | Force memory consolidation on the current session. Compresses older messages to free context window space. |
| `/model` | -- | Show the currently active model name. |
| `/tools` | -- | List all registered tools with their names. |
| `/topics` | -- | Show tracked security topics with priority, keywords, and last scan time. |
| `/agenda` | -- | Show security agenda summary: advisory count, threat intel, digests, exploits, active topics. |
| `/cves [query]` | optional search query | Search stored advisories. Without a query, shows the 10 most recent CVEs. |
| `/recent [n]` | optional count (default 10) | Show recent advisories and threat intel. |
| `/audit [n]` | optional count (default 20) | Show recent audit log entries for the current session with tool name, duration, and status. |
| `/intel` | -- | Generate a weekly threat intel digest and publish it to Discord via the configured webhook. |
| `/goal <condition>` | text, or a JSON `{condition, verifier}` spec | Set an autonomous goal — the agent is re-invoked each turn until a verifier passes. `/goal` alone shows status; `/goal clear` stops it. See [Goals](goals.md). |
| `/help` | -- | Show the command help table. |

::: tip
Commands are case-insensitive. `/Think HIGH` and `/think high` are equivalent.
:::

::: warning
`/new` permanently clears the session history. There is no undo.
:::
