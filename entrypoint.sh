#!/bin/bash
# protoPen — container entrypoint

echo "[entrypoint] Starting protoPen"

# Create dirs inside tmpfs home
mkdir -p /home/sandbox/.local

# Ensure persistent volume dirs exist
mkdir -p /sandbox/audit /sandbox/knowledge /sandbox/papers

# Copy skills into workspace
mkdir -p /sandbox
cp -r /opt/protopen/skills /sandbox/skills

# Lab mode setup (if GPU available)
if [ -n "${LAB_GPU}" ] || command -v nvidia-smi &>/dev/null; then
    echo "[entrypoint] GPU detected — lab mode available (/lab on)"
    mkdir -p /sandbox/lab
    if command -v nvidia-smi &>/dev/null; then
        nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null || true
    fi
fi

# Browser tool: pin the system Chromium (installed in the image) so agent-browser
# finds it regardless of the runtime user / HOME=/tmp override in tools/browser.py.
if [ -z "${AGENT_BROWSER_EXECUTABLE_PATH:-}" ]; then
    for b in /usr/bin/chromium /usr/bin/chromium-browser /usr/bin/google-chrome; do
        if [ -x "$b" ]; then
            export AGENT_BROWSER_EXECUTABLE_PATH="$b"
            break
        fi
    done
fi

# Start protoPen Gradio UI on port 7870
exec python /opt/protopen/server.py
