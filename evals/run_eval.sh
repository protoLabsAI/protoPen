#!/usr/bin/env bash
# protoPen eval harness — runs tasks against the live instance
#
# Usage:
#   ./evals/run_eval.sh                    # run all tasks against current backend
#   ./evals/run_eval.sh --dry-run          # validate harness only
#   ./evals/run_eval.sh --compare          # run both backends and compare
#
# The runner calls the Gradio API at RESEARCHER_URL (default: http://localhost:7870)

set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"
VENV=".venv/bin/activate"
EXTRA_ARGS="${@}"

if [ -f "$VENV" ]; then
    source "$VENV"
fi

# Install gradio_client if needed
$PYTHON -c "import gradio_client" 2>/dev/null || pip install gradio_client -q

if echo "$EXTRA_ARGS" | grep -q "\-\-compare"; then
    echo "=== Backend Comparison Mode ==="
    echo ""
    echo "Step 1: Ensure container is running with AGENT_BACKEND=nanobot"
    echo "  Edit .env: AGENT_BACKEND=nanobot"
    echo "  docker compose up -d --build"
    read -p "Press Enter when nanobot backend is ready..."

    $PYTHON -m evals.runner --backend nanobot
    NANOBOT_RESULT=$(ls -t evals/results/nanobot_*.json 2>/dev/null | head -1)

    echo ""
    echo "Step 2: Switch to LangGraph"
    echo "  Edit .env: AGENT_BACKEND=langgraph"
    echo "  docker compose up -d --build"
    read -p "Press Enter when langgraph backend is ready..."

    $PYTHON -m evals.runner --backend langgraph
    LANGGRAPH_RESULT=$(ls -t evals/results/langgraph_*.json 2>/dev/null | head -1)

    echo ""
    echo "Step 3: Generating comparison report..."
    if [ -n "$NANOBOT_RESULT" ] && [ -n "$LANGGRAPH_RESULT" ]; then
        $PYTHON -m evals.compare "$NANOBOT_RESULT" "$LANGGRAPH_RESULT" -o evals/results/comparison.md
        echo ""
        cat evals/results/comparison.md
    else
        echo "Error: Could not find result files"
    fi
else
    # Single backend run
    BACKEND=$(docker exec protopen printenv AGENT_BACKEND 2>/dev/null || echo "unknown")
    echo "Running eval against live instance (backend: $BACKEND)"
    echo "URL: ${RESEARCHER_URL:-http://localhost:7870}"
    echo ""
    $PYTHON -m evals.runner --backend "$BACKEND" $EXTRA_ARGS
fi
