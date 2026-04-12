#!/usr/bin/env bash
# protoPen launcher — fetches secrets from Infisical at runtime, no env on disk.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Activate venv if present
if [ -f .venv/bin/activate ]; then
    source .venv/bin/activate
fi

# Fetch LiteLLM key from Infisical (in-memory only)
export OPENAI_API_KEY="$(infisical export \
    --domain https://secrets.proto-labs.ai/api \
    --projectId f0e3382b-611c-4964-8b57-89d0db4976be \
    --env staging \
    --format dotenv \
    --silent \
    | grep LITELLM_MASTER_KEY | cut -d"'" -f2)"

if [ -z "$OPENAI_API_KEY" ]; then
    echo "ERROR: Failed to fetch LITELLM_MASTER_KEY from Infisical."
    echo "Run: infisical login --domain https://secrets.proto-labs.ai/api"
    exit 1
fi

echo "✓ LiteLLM key loaded from Infisical"

# Use LangGraph backend pointed at ava
export AGENT_BACKEND=langgraph

exec python server.py "$@"
