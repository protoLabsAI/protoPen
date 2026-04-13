#!/usr/bin/env bash
# protoPen launcher — fetches secrets from Infisical at runtime, no env on disk.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Activate venv if present
if [ -f .venv/bin/activate ]; then
    source .venv/bin/activate
fi

# Create workspace directories (Docker uses /sandbox, native uses ./data)
SANDBOX="${SANDBOX_DIR:-$SCRIPT_DIR/data}"
mkdir -p "$SANDBOX/knowledge" "$SANDBOX/audit" "$SANDBOX/papers" "$SANDBOX/lab"
export SANDBOX_DIR="$SANDBOX"

# Symlink /sandbox for code that hardcodes the path (skip if already exists)
if [ ! -e /sandbox ]; then
    if [ "$(id -u)" -eq 0 ]; then
        ln -sfn "$SANDBOX" /sandbox
    else
        sudo ln -sfn "$SANDBOX" /sandbox 2>/dev/null \
            || echo "WARN: could not symlink /sandbox → $SANDBOX (knowledge store will fail)"
    fi
fi

# Fetch secrets from Infisical (in-memory only)
# Supports both service token (INFISICAL_TOKEN) and interactive login session.
INFISICAL_ARGS="--domain https://secrets.proto-labs.ai/api --env prod --format dotenv --silent"
if [ -n "${INFISICAL_TOKEN:-}" ]; then
    INFISICAL_ARGS="$INFISICAL_ARGS --token $INFISICAL_TOKEN"
fi

SECRETS="$(infisical export $INFISICAL_ARGS 2>/dev/null)" || true

export OPENAI_API_KEY="$(echo "$SECRETS" | grep LITELLM_MASTER_KEY | cut -d"'" -f2)"

if [ -z "$OPENAI_API_KEY" ]; then
    echo "ERROR: Failed to fetch LITELLM_MASTER_KEY from Infisical."
    echo "Set INFISICAL_TOKEN or run: infisical login --domain https://secrets.proto-labs.ai/api"
    exit 1
fi

echo "✓ LiteLLM key loaded from Infisical"

# Use LangGraph backend pointed at ava
export AGENT_BACKEND=langgraph

exec python server.py "$@"
