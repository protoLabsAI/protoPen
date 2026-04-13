# protoPen

Autonomous Security Research & Pen-Testing Agent

A LangGraph-powered agent that runs on a Steam Deck with attached RF/WiFi/RFID peripherals. It combines real-time threat intelligence — CVE tracking, exploit monitoring, security feed aggregation — with hardware-in-the-loop pen testing using PortaPack H4M, Flipper Zero, WiFi Marauder, and BlackArch tools. All findings flow into a hybrid-search knowledge store (SQLite + sqlite-vec + FTS5) and are correlated across sensors automatically.

## Features

- **Threat Intelligence** — CVE search (NVD/MITRE), Exploit-DB monitoring, security RSS feeds (CISA, Krebs, THN), GitHub security tool tracking
- **Pen Testing** — WiFi (deauth, PMKID, evil portal, karma), Bluetooth (BLE spam, Swift Pair), RF (Sub-GHz capture/replay), RFID/NFC (read/write/emulate), network (nmap, bettercap, nikto)
- **Knowledge Store** — Hybrid search across advisories, exploits, and threat intel using vector similarity + BM25 keyword matching with Reciprocal Rank Fusion
- **Security Subagents** — Threat Scanner (feed monitoring), Vuln Analyst (deep advisory analysis + target correlation), Intel Reporter (digest generation + Discord publishing)
- **Pen-Test Subagents** — Recon (passive enumeration), Exploit (active testing), Reporter (finding synthesis + report generation)
- **Blue Team** — CIS benchmarks, service hardening audits, network anomaly detection, DNS exfiltration monitoring, incident response (log correlation, IOC matching, timeline reconstruction, containment)
- **Purple Team** — MITRE ATT&CK coverage matrix, red↔blue detection gap analysis, exercise reporting
- **Target Intelligence** — Unified SQLite database tracks hosts, ports, WiFi networks, RF signals, BLE devices, RFID tags, and credentials across all sensors
- **Engagement Modes** — Risk-gated tool access: PASSIVE (observe only), ACTIVE (directed probing), REDTEAM (full offensive)
- **Discord Integration** — Real-time alerts on critical/high findings, automated threat intel digests, security assessment reports published as rich embeds via webhook
- **Agent-to-Agent (A2A)** — JSON-RPC endpoint for other agents to delegate recon, pen testing, or threat intel tasks
- **Observability** — Langfuse tracing, Prometheus metrics, JSONL audit trail

## Hardware

| Device | Role |
|---|---|
| **Steam Deck** | Compute platform — runs the agent, tools, and knowledge store |
| **PortaPack H4M** | HackRF One + Mayhem firmware — RF capture/replay/transmit (1 MHz–6 GHz) |
| **Flipper Zero** | Multi-tool — Sub-GHz, NFC, RFID, IR, BLE, GPIO |
| **WiFi Marauder (ESP32)** | WiFi attacks — scan, deauth, PMKID capture, evil portal, karma AP |
| **External WiFi Adapter** | Monitor mode + packet injection (aircrack-ng, bettercap) |
| **BlackArch Tools** | nmap, tshark, nikto, gobuster, hashcat, john, sqlmap, hydra, etc. |

## Quick Start

### Prerequisites: Claude Code Authentication

protoPen uses **CLIProxyAPI** to access Claude models through your existing Claude Code subscription — no separate API key needed. It works by reading the OAuth token from Claude Code's credential file on your host.

**Setup:**

1. **Install and authenticate Claude Code** on the host machine:

   ```bash
   npm install -g @anthropic-ai/claude-code
   claude  # This opens a browser for OAuth login
   ```

2. **Ensure the credentials file is readable** by the container (runs as uid 1001):

   ```bash
   chmod 644 ~/.claude/.credentials.json
   ```

   This file is mounted read-only into the container at `/opt/claude-creds/`. The entrypoint extracts the OAuth token and injects it into CLIProxyAPI's config. A background watcher refreshes the token every 5 minutes if the file changes.

3. **Verify the file exists:**
   ```bash
   ls -la ~/.claude/.credentials.json
   # Should show: -rw-r--r-- ... .credentials.json
   ```

> **How it works:** CLIProxyAPI runs inside the container on port 8317, exposing an OpenAI-compatible API that routes requests to Anthropic using your Claude Code OAuth token. The agent is configured to use this as its LLM provider (`cliproxy` in `nanobot-config.json`). This means LLM calls use your Claude Code subscription, not a separate API key.

> **Alternative:** If you prefer to use an API key directly, set `ANTHROPIC_API_KEY` in your environment and change the nanobot config provider from `cliproxy` to `anthropic`.

### Docker (recommended)

```bash
# Clone with submodules (nanobot is a git submodule)
git clone --recursive https://github.com/protoLabsAI/protoPen
cd protoPen

# Start (basic mode)
docker compose up --build
# UI at http://localhost:7872
```

### With Lab Mode (GPU experiments)

```bash
docker compose --profile lab up --build
# UI at http://localhost:7872, then /lab on in chat
```

Requires NVIDIA GPU. Lab mode mounts LLaMA-Factory + HuggingFace model cache from the host.

### Local

```bash
pip install -r requirements.txt
python server.py --port 7870
```

## Tools

### Security Research

| Tool | Description |
|---|---|
| `cve_search` | Query NVD/MITRE CVE database — search by keyword, product, severity, date range |
| `security_feeds` | Aggregate RSS/Atom feeds from CISA, NVD, Exploit-DB, security blogs |
| `security_memory` | Store/search advisories, exploits, threat intel — hybrid search with target correlation |
| `github_trending` | Track trending security tools, exploit PoCs, and offensive/defensive repos |
| `browser` | Deep-read security advisories, blog posts, PoC writeups |
| `discord_feed` | Scan Discord channels for security intel, publish digests and security reports as rich embeds via webhook |
| `rabbit_hole_bridge` | Ship threat intel to rabbit-hole.io knowledge graph |

### Pen Testing

| Tool | Description |
|---|---|
| `portapack` | PortaPack H4M control — RF scan, capture, replay, transmit, GPS inject |
| `flipper` | Flipper Zero — Sub-GHz, NFC, RFID, IR, BLE, GPIO, storage |
| `marauder` | WiFi Marauder — AP/station scan, deauth, PMKID, evil portal, karma, BLE spam |
| `blackarch` | Curated wrappers — nmap, aircrack-ng, bettercap, nikto, gobuster, hashcat, tshark |
| `device_manager` | USB serial connection management for all hardware peripherals |
| `engagement` | Mission control — lifecycle, mode enforcement, findings, reports |
| `target_intel` | Target database — hosts, ports, WiFi, RF, BLE, RFID, credentials |

### Blue Team / Defensive

| Tool | Description |
|---|---|
| `cis_audit` | CIS benchmark scanning — SSH, TLS, firewall config audits, patch assessment, port baseline |
| `net_monitor` | Network monitoring — passive traffic baselines, host anomaly detection, DNS exfiltration/tunneling detection |
| `hardening_check` | Service hardening validation — SSH, Nginx, Apache, Docker, Kubernetes with specific remediation steps |
| `ir_toolkit` | Incident response — log correlation, IOC matching, auth log analysis, timeline reconstruction, containment |
| `purple_team` | Purple team mode — MITRE ATT&CK coverage matrix, detection gap analysis, exercise reports |

## Engagement Modes

| Mode | Level | Allows |
|---|---|---|
| **PASSIVE** | 0 | Listen, scan, enumerate. No transmission. |
| **ACTIVE** | 1 | Active probing, PMKID capture, signal replay, vuln scan |
| **REDTEAM** | 2 | Deauth, evil portal, karma AP, BLE spam, brute force |

The agent does not auto-escalate modes. If it needs a higher mode, it reports the requirement and waits for explicit human instruction.

## Architecture

```
protoPen
├── nanobot/              # Agent framework (submodule)
├── tools/
│   ├── base.py           # BasePentestTool — async subprocess runner
│   ├── cve_search.py     # NVD/MITRE CVE database search
│   ├── security_feeds.py # RSS/Atom security feed aggregator
│   ├── security_memory.py# Security knowledge store tool
│   ├── github_trending.py# Security tool + exploit PoC tracking
│   ├── browser.py        # Web automation
│   ├── discord_feed.py   # Discord channel scanner
│   ├── portapack.py      # PortaPack H4M serial bridge
│   ├── flipper.py        # Flipper Zero serial bridge
│   ├── marauder.py       # WiFi Marauder serial bridge
│   ├── blackarch.py      # BlackArch tool wrappers
│   ├── device_manager.py # USB serial management
│   ├── engagement.py     # Engagement lifecycle + findings
│   ├── target_intel.py   # Target intelligence database
│   ├── rabbit_hole_bridge.py # Knowledge graph integration
│   ├── lab_bench.py      # GPU experiment runner (lab mode)
│   ├── cis_audit.py      # CIS benchmark + config audits
│   ├── net_monitor.py    # Network monitoring + anomaly detection
│   ├── hardening_check.py# Service hardening validation
│   ├── ir_toolkit.py     # Incident response toolkit
│   ├── purple_team.py    # Purple team correlation engine
│   ├── parsers/          # Output normalizers (nmap XML, ATT&CK alignment)
│   └── scripts/          # Standalone audit scripts (ssh_audit, tls_audit, etc.)
├── playbooks/
│   ├── library/          # YAML playbook definitions
│   ├── loader.py         # Load + variable substitution
│   ├── runner.py         # Sequential executor + step output refs + ATT&CK normalization
│   └── schema.py         # Playbook/Step data models
├── graph/                # LangGraph agent + subagents + middleware
├── knowledge/            # SQLite + sqlite-vec + FTS5 hybrid search
├── lab/                  # Experiment runner + templates
├── server.py             # FastAPI server (Gradio UI + API + A2A)
├── chat_ui.py            # Chat interface
├── Dockerfile            # Multi-stage build (base + lab)
└── docker-compose.yml    # Orchestration (with lab GPU profile)
```

### Subagents

The lead agent delegates to nine specialized subagents via the `task` tool:

| Domain | Subagent | Role |
|---|---|---|
| Security Research | **Threat Scanner** | Scans CVE feeds, Exploit-DB, security RSS, GitHub for new threats |
| Security Research | **Vuln Analyst** | Deep-reads advisories, correlates with target intel, rates exploitability |
| Security Research | **Intel Reporter** | Synthesizes threat intel reports, publishes security digests |
| Pen Testing | **Recon** | Passive reconnaissance — RF survey, WiFi scan, network enumeration |
| Pen Testing | **Exploit** | Active exploitation — PMKID capture, signal replay, vuln scanning |
| Pen Testing | **Reporter** | Finding synthesis — triage, correlation, report generation |
| Blue Team | **Defender** | CIS audits, hardening checks, patch assessment, port baselines |
| Blue Team | **Incident Responder** | Log analysis, IOC matching, timeline reconstruction, containment |
| Blue Team | **Purple Team** | Red↔blue correlation, MITRE ATT&CK coverage, detection gap analysis |

## Chat Commands

| Command | Description |
|---|---|
| `/purple <scope>` | Run purple team exercise — red recon → blue defense → ATT&CK coverage report |
| `/topics` | Show tracked security topics |
| `/agenda` | Security agenda with stats |
| `/cves [query]` | Search stored advisories |
| `/recent [n]` | Show recent advisories and threat intel |
| `/intel` | Generate and publish threat intel digest |
| `/lab on\|off\|status` | Toggle lab mode (GPU experiments) |
| `/think <level>` | Set reasoning effort |
| `/tools` | List registered tools |
| `/audit [n]` | Show recent audit log entries |
| `/help` | Show all commands |

## Playbooks

protoPen ships with six pre-built playbooks that chain tools into multi-step workflows. All steps produce structured JSON output and handle tool failures gracefully (`on_fail: continue`).

| Playbook | Steps | Description |
|---|---|---|
| `purple_team_exercise` | 9 | Red recon → blue defense → MITRE ATT&CK coverage matrix + exercise report |
| `defensive_assessment` | 6 | CIS SSH/TLS/firewall audits, SSH hardening, patch check, port baseline |
| `incident_response` | 5 | Log search, IOC scan, auth log analysis, timeline, containment |
| `full_recon` | 6 | nmap, DNS enum, subdomain discovery, OSINT, web dirs, SSL check |
| `web_vuln_assessment` | 6 | nikto, nuclei, XSS, SQLi, CORS, CVE scan |
| `smb_enum` | 4 | enum4linux, SMB shares, RPC users, CVE check |

Run via the `/purple` command (for purple team exercises) or programmatically:

```python
from playbooks.loader import load_playbook
from playbooks.runner import run_playbook

pb = load_playbook("defensive_assessment", {"target": "192.168.4.1"})
result = await run_playbook(pb, dispatch)
```

## Rabbit Hole Integration

protoPen connects to [rabbit-hole.io](https://github.com/protoLabsAI/rabbit-hole.io)'s knowledge graph via HTTP bridge, shipping advisories, exploits, and threat intel as structured bundles.

Set `RABBIT_HOLE_URL` and `MCP_AUTH_TOKEN` in your environment. See [docs/guides/rabbit-hole-mcp.md](docs/guides/rabbit-hole-mcp.md) for details.

## API

### Chat API

```bash
curl -s http://localhost:7872/api/chat -H "Content-Type: application/json" \
  -d '{"message": "What are the latest critical CVEs affecting Linux?"}'
```

### OpenAI-Compatible API

```bash
curl http://localhost:7872/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "protopen",
    "messages": [{"role": "user", "content": "Search for recent RCE vulnerabilities in network equipment"}]
  }'
```

### A2A (Agent-to-Agent)

```bash
curl -X POST http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"kind": "text", "text": "Run a passive recon of 192.168.1.0/24"}]
      }
    }
  }'
```

## Knowledge Search

Hybrid search combining vector similarity (Qwen3-Embedding-0.6B via sqlite-vec) with BM25 keyword matching (SQLite FTS5), fused via Reciprocal Rank Fusion (RRF). Searches across advisories, exploits, threat intel, and digests.

**Search modes** (configurable in `langgraph-config.yaml`):
- `hybrid` (default) — RRF fusion of vector + keyword results
- `vector` — semantic similarity only
- `keyword` — BM25 keyword matching only

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `AGENT_BACKEND` | No | `nanobot` (legacy) or `langgraph` (recommended) |
| `PROTOPEN_API_KEY` | No | API key for A2A authentication |
| `MCP_AUTH_TOKEN` | No | Token for rabbit-hole knowledge graph |
| `ANTHROPIC_API_KEY` | No | Direct Anthropic API (alternative to CLIProxyAPI) |
| `GITHUB_TOKEN` | No | GitHub API (higher rate limits) |
| `DISCORD_BOT_TOKEN` | No | Discord channel reading |
| `DISCORD_WEBHOOK_URL` | No | Discord webhook for publishing digests, security alerts, and engagement reports (managed via Infisical in prod) |
| `LANGFUSE_PUBLIC_KEY` | No | Langfuse tracing |
| `LANGFUSE_SECRET_KEY` | No | Langfuse tracing |
| `LAB_GPU` | No | GPU ID for lab mode (default: `1`) |

## Stack

- **Agent**: LangGraph (recommended) or nanobot (legacy)
- **LLM**: CLIProxyAPI → Claude Code OAuth (no API key needed) or direct Anthropic API
- **UI**: Gradio 5 (dark theme, PWA)
- **Knowledge**: SQLite + sqlite-vec + FTS5 (hybrid search: vector similarity + BM25 keyword, RRF fusion)
- **Training**: LLaMA-Factory with LoRA DPO on Qwen3.5-0.8B/2B (lab mode)
- **Observability**: Langfuse tracing, Prometheus metrics, JSONL audit
- **Container**: Docker with seccomp, read-only root, tmpfs workspace

## Part of protoLabs

protoPen is part of the [protoLabs](https://protolabs.studio) autonomous development studio.

| Agent | Role |
|---|---|
| **Ava** | Chief of Staff — orchestration and strategy |
| **Quinn** | QA Engineer — verification and release management |
| **protoPen** | Security — threat intelligence, pen testing, and security research |
