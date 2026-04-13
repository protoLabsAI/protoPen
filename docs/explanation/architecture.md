# Architecture

protoPen is an autonomous pen-testing and security research agent that runs on a Steam Deck with attached RF/WiFi/RFID peripherals. It combines hardware-in-the-loop security assessments with threat intelligence capabilities.

## System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│  Clients                                                        │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────────────┐  │
│  │ Chat UI  │  │ OpenAI API   │  │ A2A (protoWorkstacean)    │  │
│  │ (Gradio) │  │ /v1/chat     │  │ JSON-RPC /a2a             │  │
│  └────┬─────┘  └──────┬───────┘  └─────────────┬─────────────┘  │
│       └───────────────┬┘                        │                │
│                       ▼                         │                │
│              ┌────────────────┐                  │                │
│              │   server.py    │◄─────────────────┘                │
│              │   (FastAPI)    │                                   │
│              └───────┬────────┘                                   │
│                      │                                           │
│         ┌────────────┴────────────┐                              │
│         ▼                         ▼                              │
│  ┌──────────────┐      ┌───────────────────┐                    │
│  │   nanobot    │      │    LangGraph       │                    │
│  │  AgentLoop   │      │  create_agent()    │                    │
│  │  (legacy)    │      │  + middleware      │                    │
│  └──────┬───────┘      └───────┬───────────┘                    │
│         │                      │                                 │
│         └──────────┬───────────┘                                 │
│                    ▼                                             │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Subagents (task tool)                  │    │
│  │  ┌──────────┐ ┌─────────┐ ┌────────┐                    │    │
│  │  │ Threat   │ │  Vuln   │ │ Intel  │  (Security          │    │
│  │  │ Scanner  │ │ Analyst │ │Reporter│   Research)         │    │
│  │  ├──────────┤ ├─────────┤ ├────────┤                    │    │
│  │  │  Recon   │ │ Exploit │ │Reporter│  (Pentest)         │    │
│  │  └──────────┘ └─────────┘ └────────┘                    │    │
│  └─────────────────────┬───────────────────────────────────┘    │
│                        ▼                                         │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                     Tool Layer                           │    │
│  │  portapack │ flipper │ marauder │ blackarch              │    │
│  │  device_manager │ engagement │ target_intel              │    │
│  │  cve_search │ security_feeds │ github_trending            │    │
│  │  browser │ security_memory │ discord_feed                │    │
│  │  rabbit_hole_bridge │ lab_bench                          │    │
│  └─────────────────────┬───────────────────────────────────┘    │
│                        ▼                                         │
│  ┌───────────────┐  ┌───────────────┐  ┌──────────────────┐    │
│  │  USB Serial   │  │  Network      │  │  Knowledge       │    │
│  │  (PortaPack,  │  │  (nmap, WiFi, │  │  Store (SQLite   │    │
│  │   Flipper,    │  │   bettercap,  │  │  + sqlite-vec    │    │
│  │   Marauder)   │  │   web)        │  │  + FTS5)         │    │
│  └───────────────┘  └───────────────┘  └──────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Observability                          │    │
│  │  audit.py (JSONL) │ metrics.py (Prometheus)              │    │
│  │  tracing.py (Langfuse) │ Discord alerts                  │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Two Agent Backends

protoPen supports two agent backends, selected via the `AGENT_BACKEND` environment variable:

### nanobot (legacy)

The original backend. Uses the nanobot `AgentLoop` with a `LiteLLMProvider` for model access. Tools are registered directly on the agent's tool registry. Session state is managed by nanobot's built-in session manager.

### LangGraph (recommended)

The current backend. Uses LangChain's `create_agent()` with a compiled LangGraph state machine. Features:

- **Middleware chain**: Knowledge injection, audit logging, memory consolidation, message capture
- **Persistent sessions**: SQLite-backed checkpointer that survives container restarts
- **Streaming**: `astream_events` for real-time tool progress and text generation
- **Subagent delegation**: The `task` tool spawns specialized `create_react_agent` subgraphs

Both backends share the same tool implementations, chat command handler, and HTTP endpoints.

## Six Subagents

The lead agent delegates work to six specialized subagents via the `task` tool:

### Security Research Domain

| Subagent | Role | Tools |
|---|---|---|
| **Threat Scanner** | Scans CVE feeds, Exploit-DB, security RSS, GitHub for new threats | cve_search, security_feeds, github_trending, browser, security_memory, rabbit_hole_bridge |
| **Vuln Analyst** | Deep-reads advisories and PoCs, correlates with target intel, rates exploitability | cve_search, security_feeds, security_memory, browser, rabbit_hole_bridge |
| **Intel Reporter** | Synthesizes threat intel reports, publishes security digests to Discord | security_memory, discord_feed, rabbit_hole_bridge |

### Pentest Domain

| Subagent | Role | Tools |
|---|---|---|
| **Recon** | Passive reconnaissance -- RF survey, WiFi scan, network enum | device_manager, portapack, flipper, marauder, blackarch, engagement |
| **Exploit** | Active exploitation -- PMKID capture, signal replay, vuln scan | device_manager, portapack, flipper, marauder, blackarch, engagement |
| **Reporter** | Finding synthesis -- triage, correlation, report generation | engagement, security_memory, discord_feed |

Each subagent gets a filtered tool set and a focused system prompt. The lead agent decides which subagent to invoke based on the task type.

## Engagement Lifecycle

1. **Start** -- Name the engagement, define scope, set mode (passive/active/redteam)
2. **Recon** -- Map the environment. Subagent: Recon
3. **Exploit** -- Test vulnerabilities. Subagent: Exploit (mode-gated)
4. **Report** -- Synthesize findings. Subagent: Reporter
5. **End** -- Close the engagement, persist findings and report

All findings are logged in real time. Critical/high findings trigger Discord alerts.

## System Prompt Composition

The system prompt is assembled from multiple sources:

1. **SOUL.md** -- Agent identity, personality, values
2. **Hardware status** -- Boot-time sitrep (devices connected, network, engagement state)
3. **Skills** -- Research methodology and pentest playbooks from `skills/` directory
4. **Subagent instructions** -- Available subagent types and delegation rules
5. **Security context** -- Dynamic injection via KnowledgeMiddleware (recent advisories, threat intel)
6. **Guidelines** -- Operational rules and output conventions

## Observability Stack

| Component | Purpose | Storage |
|---|---|---|
| **audit.py** | JSONL log of every tool call with args, result, duration, session | `/sandbox/audit/audit.jsonl` |
| **metrics.py** | Prometheus counters/histograms for LLM calls, tool latency, sessions | `/metrics` endpoint |
| **tracing.py** | Langfuse spans for tool calls, organized by research phase | Langfuse server |
| **Discord alerts** | Real-time webhook notifications for critical/high findings | Discord channel |
