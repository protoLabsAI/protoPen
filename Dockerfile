FROM python:3.12-slim AS base

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential gettext-base \
    && rm -rf /var/lib/apt/lists/*

# Create non-root sandbox user
ARG SANDBOX_UID=1001
RUN useradd -m -s /bin/bash -u ${SANDBOX_UID} sandbox

# Node.js (for agent-browser)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Browser tool: agent-browser + Chromium
RUN npm install -g agent-browser \
    && (agent-browser install --with-deps 2>/dev/null \
        || (apt-get update && apt-get install -y --no-install-recommends chromium && rm -rf /var/lib/apt/lists/*))

# Claude Code CLI (for Claude model access)
RUN npm install -g @anthropic-ai/claude-code

# CLIProxyAPI — OpenAI-compatible proxy that uses Claude Code OAuth
ARG CLIPROXY_VERSION=6.8.55
RUN ARCH=$(dpkg --print-architecture) \
    && curl -fsSL "https://github.com/router-for-me/CLIProxyAPI/releases/download/v${CLIPROXY_VERSION}/CLIProxyAPI_${CLIPROXY_VERSION}_linux_${ARCH}.tar.gz" \
    | tar xz -C /usr/local/bin cli-proxy-api \
    && chmod +x /usr/local/bin/cli-proxy-api

# Install nanobot from submodule + Python deps
COPY nanobot/ /opt/nanobot/
RUN pip install --no-cache-dir /opt/nanobot/ \
    gradio sqlite-vec httpx uvicorn langfuse prometheus-client PyMuPDF pyyaml \
    langchain langchain-openai langgraph websockets

# Install protoPen
COPY tools/ /opt/protopen/tools/
COPY knowledge/ /opt/protopen/knowledge/
COPY lab/ /opt/protopen/lab/
COPY graph/ /opt/protopen/graph/
COPY skills/ /opt/protopen/skills/
COPY audit.py /opt/protopen/audit.py
COPY tracing.py /opt/protopen/tracing.py
COPY metrics.py /opt/protopen/metrics.py
COPY chat_ui.py /opt/protopen/chat_ui.py
COPY server.py /opt/protopen/server.py
COPY discord_bot.py /opt/protopen/discord_bot.py
COPY guardrails.py /opt/protopen/guardrails.py
COPY entrypoint.sh /opt/protopen/entrypoint.sh
COPY config/ /opt/protopen/config/
COPY static/ /opt/protopen/static/

# Sandbox workspace + knowledge/audit/papers dirs
RUN mkdir -p /sandbox /tmp/sandbox /sandbox/audit /sandbox/knowledge /sandbox/papers \
    && chown -R sandbox:sandbox /sandbox /tmp/sandbox

# Persistent dirs (volumes mounted at runtime)
RUN mkdir -p /opt/.cliproxy /opt/.cron \
    && chown -R sandbox:sandbox /opt/.cliproxy /opt/.cron

# Nanobot data dir
RUN mkdir -p /home/sandbox/.nanobot \
    && chown -R sandbox:sandbox /home/sandbox/.nanobot

# Drop to sandbox user
USER sandbox
WORKDIR /sandbox

EXPOSE 7870
CMD ["/opt/protopen/entrypoint.sh"]

# ---------------------------------------------------------------------------
# Lab stage — adds torch + LLaMA-Factory deps for GPU training
# Usage: docker compose --profile lab up --build
# ---------------------------------------------------------------------------
FROM base AS lab

USER root

# Install PyTorch (CUDA 12.8) + training deps
RUN pip install --no-cache-dir \
    torch==2.9.1 --index-url https://download.pytorch.org/whl/cu128 \
    && pip install --no-cache-dir \
    transformers accelerate peft trl datasets bitsandbytes

# Lab workspace
RUN mkdir -p /sandbox/lab /mnt/data/training/researcher \
    && chown -R sandbox:sandbox /sandbox/lab /mnt/data/training/researcher

USER sandbox
WORKDIR /sandbox
EXPOSE 7870
CMD ["/opt/protopen/entrypoint.sh"]
