---
outline: deep
---

# Reference

Complete technical reference for the protoPen API, tools, and configuration.

## API

- **[API Endpoints](./api-endpoints.md)** -- All HTTP endpoints with request/response formats.
- **[Chat Commands](./chat-commands.md)** -- Slash commands available in the chat UI.

## Tools

- **[Tools](./tools.md)** -- All agent tools and their actions.
- **[Adding a Tool](./adding-a-tool.md)** -- Scaffold (`scripts/new_tool.py`) + the impl/registration pattern.
- **[Playbooks](./playbooks.md)** -- Declarative tool-chain recipes, modes, and the operator firing gate.
- **[Goals (Autonomy)](./goals.md)** -- Verifier-backed goal mode: `/goal`, the `set_goal` tool, and the re-invocation loop.
- **[Target Intel](./target-intel.md)** -- Target intelligence database schema (9 SQLite tables).

## Configuration

- **[Engagement Modes](./engagement-modes.md)** -- PASSIVE, ACTIVE, REDTEAM mode definitions and risk gating.
- **[Environment Variables](./environment-variables.md)** -- All environment variables and their purposes.
- **[Configuration Files](./configuration.md)** -- Config file locations and structure.
