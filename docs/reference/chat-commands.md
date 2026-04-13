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
| `/topics` | -- | Show tracked research topics with priority, keywords, and last scan time. |
| `/agenda` | -- | Show research agenda summary: paper count, findings, digests, model releases, active topics. |
| `/papers [query]` | optional search query | Search stored papers. Without a query, shows the 10 most recent papers. |
| `/recent [n]` | optional count (default 10) | Show recent papers and findings. |
| `/audit [n]` | optional count (default 20) | Show recent audit log entries for the current session with tool name, duration, and status. |
| `/lab on\|off\|status` | `on`, `off`, or `status` | Toggle lab mode (GPU experiment runner). Registers/unregisters the `lab_bench` tool. |
| `/publish` | -- | Generate a weekly research digest and publish it to Discord via the configured webhook. |
| `/help` | -- | Show the command help table. |

::: tip
Commands are case-insensitive. `/Think HIGH` and `/think high` are equivalent.
:::

::: warning
`/new` permanently clears the session history. There is no undo.
:::
