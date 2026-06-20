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
│                      │                                           │
│                      ▼                                           │
│              ┌───────────────────┐                               │
│              │    LangGraph       │                               │
│              │  create_agent()    │                               │
│              │  + middleware      │                               │
│              └───────────────────┘                               │
│                      │                                           │
│                      ▼                                           │
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

## Agent Backend

protoPen uses LangChain's `create_agent()` with a compiled LangGraph state machine. Features:

- **Middleware chain**: Knowledge injection, audit logging, memory consolidation, message capture
- **Persistent sessions**: SQLite-backed checkpointer that survives container restarts
- **Streaming**: `astream_events` for real-time tool progress and text generation
- **Subagent delegation**: The `task` tool spawns specialized `create_react_agent` subgraphs

## Subagents

The lead agent delegates work to eleven specialized subagents via the `task` tool
(synchronously, or detached with `run_in_background=True` — see [Autonomy](autonomy.md)).

### Security Research Domain

| Subagent | Role | Tools |
|---|---|---|
| **Threat Scanner** | Scans CVE feeds, Exploit-DB, security RSS, GitHub for new threats | cve_search, security_feeds, github_trending, browser, security_memory |
| **Vuln Analyst** | Deep-reads advisories and PoCs, correlates with target intel, rates exploitability | cve_search, security_feeds, security_memory, browser |
| **Intel Reporter** | Synthesizes threat intel reports, publishes security digests to Discord | security_memory, discord_feed |

### Pentest Domain

| Subagent | Role | Tools |
|---|---|---|
| **Orchestrator** | Meta-orchestrator: runs a full scripted pipeline, interprets findings, probes high-value targets | (delegates across the pentest tools) |
| **Recon** | Passive reconnaissance -- RF survey, WiFi scan, network enum | device_manager, portapack, flipper, marauder, blackarch, engagement |
| **Exploit** | Active exploitation -- PMKID capture, signal replay, vuln scan (mode-gated) | device_manager, portapack, flipper, marauder, blackarch, websocket_test, opsec, engagement |
| **Reporter** | Finding synthesis -- triage, correlation, report generation | engagement, security_memory |

### Blue / Purple Team Domain

| Subagent | Role | Tools |
|---|---|---|
| **Defender** | CIS audits, hardening checks, container security, port baselines | cis_audit, hardening_check, container_audit, engagement |
| **Incident Responder** | Log analysis, IOC matching, timeline reconstruction, containment | ir_toolkit, net_monitor, engagement, security_memory |
| **Purple Team** | Correlates red+blue results, measures ATT&CK coverage gaps | purple_team, cis_audit, container_audit, net_monitor, ir_toolkit, engagement, security_memory |

### Self-Curation Domain

| Subagent | Role | Tools |
|---|---|---|
| **Dream** | Memory consolidation -- prune stale/duplicate/superseded facts (no shell, no SQL) | memory_list, forget_memory, recent_activity, security_memory |

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
