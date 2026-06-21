#!/usr/bin/env bash
# protoPen runtime container entrypoint. Secrets are injected by the host
# (deck/protopen-runtime-run.sh fetches them from Infisical into an --env-file),
# so this just maps the gateway key, ensures the workspace, and starts the server.
# Tracker: protopen-3t5.1 / 3t5.3.
set -euo pipefail

# protoLabs gateway key -> OPENAI_API_KEY (the LiteLLM gateway key), per start.sh.
if [ -z "${OPENAI_API_KEY:-}" ] && [ -n "${GATEWAY_API_KEY:-}" ]; then
    export OPENAI_API_KEY="$GATEWAY_API_KEY"
fi
if [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "[entrypoint] WARN: OPENAI_API_KEY unset — UI/API serve, but agent turns" \
         "fail until a gateway key is provided (INFISICAL_TOKEN drop-in or -e OPENAI_API_KEY)."
fi

export AGENT_BACKEND="${AGENT_BACKEND:-langgraph}"
mkdir -p /sandbox/knowledge /sandbox/audit /sandbox/papers
exec python -m server --port "${PROTOPEN_PORT:-7870}"
