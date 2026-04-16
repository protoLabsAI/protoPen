# Environment Variables

All environment variables used by protoPen. Set these in your `docker-compose.yml`, `.env` file, or shell.

## Secrets / Infisical

| Variable | Required | Default | Description |
|---|---|---|---|
| `INFISICAL_TOKEN` | yes (prod) | -- | Infisical service token for non-interactive secret fetching. Set via systemd override at `~/.config/systemd/user/protopen.service.d/infisical.conf`. |

::: tip All secrets auto-exported
`start.sh` exports **every** secret from the Infisical protoPen project (prod env) into the process environment. You do not need to manually set individual API keys — they are all fetched at startup. The variables below document what the code expects to find, but they are populated automatically from Infisical.
:::

### Infisical Secrets Inventory

Secrets stored in the Infisical protoPen project (`f7d3c43d`, `prod` environment):

| Secret Key | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Anthropic API key for LLM access |
| `DISCORD_BOT_TOKEN` | Discord bot token for Gateway + REST API |
| `DISCORD_WEBHOOK_URL` | Discord webhook for publishing digests, security reports, and alerts |
| `GITHUB_TOKEN` | GitHub personal access token |
| `LANGFUSE_PUBLIC_KEY` | Langfuse tracing public key |
| `LANGFUSE_SECRET_KEY` | Langfuse tracing secret key |
| `PROTOPEN_API_KEY` | API key for A2A endpoint authentication |

## Core

| Variable | Required | Default | Description |
|---|---|---|---|
| `AGENT_BACKEND` | no | `langgraph` | Agent backend to use (`langgraph`) |
| `SANDBOX_DIR` | no | `/sandbox` | Root directory for the sandboxed workspace |
| `INSTANCE_NAME` | no | `ava` | Instance name for multi-node identification and Discord digest branding |

## LLM / API Keys

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENAI_API_KEY` | yes | -- | LiteLLM gateway master key |
| `ANTHROPIC_API_KEY` | no | -- | Direct Anthropic API key (optional) |
| `OPENAI_API_KEY` | no | -- | OpenAI-compatible API key (used for LiteLLM gateway access) |

## Observability

| Variable | Required | Default | Description |
|---|---|---|---|
| `LANGFUSE_PUBLIC_KEY` | no | -- | Langfuse public key for tracing |
| `LANGFUSE_SECRET_KEY` | no | -- | Langfuse secret key for tracing |
| `LANGFUSE_HOST` | no | `http://host.docker.internal:3001` | Langfuse server URL |

## Integrations

| Variable | Required | Default | Description |
|---|---|---|---|
| `GITHUB_TOKEN` | no | -- | GitHub personal access token (higher API rate limits for trending tool) |
| `DISCORD_BOT_TOKEN` | no | -- | Discord bot token for reading channel feeds and reacting to mentions |
| `DISCORD_WEBHOOK_URL` | no | -- | Discord webhook URL for publishing research digests, security alerts, and engagement reports as rich embeds. Managed via Infisical in prod. |


## A2A Authentication

| Variable | Required | Default | Description |
|---|---|---|---|
| `PROTOPEN_API_KEY` | no | -- | API key for authenticating A2A requests. Checked via `x-api-key` header. |

::: tip
When `PROTOPEN_API_KEY` is not set, the A2A endpoint accepts unauthenticated requests. This is appropriate for a private Tailnet but not for public exposure.
:::

::: warning
Never commit API keys to the repository. Use a `.env` file (git-ignored) or inject them via your deployment pipeline.
:::
