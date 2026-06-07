<p align="center">
  <img src="docs/public/pwnDeck-banner.png" alt="pwnDeck — protoPen on a Steam Deck" width="640">
</p>

# protoPen

Autonomous Security Research & Pen-Testing Agent

A LangGraph-powered agent that runs on a Steam Deck with attached RF/WiFi/RFID peripherals. It combines real-time threat intelligence — CVE tracking, exploit monitoring, security feed aggregation — with hardware-in-the-loop pen testing using PortaPack H4M, Flipper Zero, WiFi Marauder, and BlackArch tools. All findings flow into a hybrid-search knowledge store (SQLite + sqlite-vec + FTS5) and are correlated across sensors automatically.

## What it does

protoPen is a single agent that covers the full offensive and defensive
spectrum, then correlates everything it finds into one knowledge store. The
exact tool set is generated live in [Tools](#tools); the domains it spans:

- **Threat intelligence** — CVE tracking (NVD/MITRE), Exploit-DB and security
  feed monitoring, GitHub trend watching, hybrid-search knowledge store
- **Reconnaissance & enumeration** — passive OSINT, external/perimeter footprint,
  DNS and subdomain discovery, network/service/web enumeration
- **Vulnerability assessment** — web, API, auth, GraphQL/gRPC, SSRF, injection,
  and CVE matching
- **Exploitation & post-exploitation** — Metasploit, credential attacks, privilege
  escalation, lateral movement, persistence, Active Directory, evasion, phishing
- **Wireless, RF & hardware** — WiFi (deauth, PMKID, evil portal, karma), Sub-GHz
  RF capture/replay, NFC/RFID, BLE — via PortaPack, Flipper, Marauder, and an Alfa
  adapter
- **Specialized domains** — IoT/OT protocols, mobile, telecom, serverless, CI/CD,
  supply chain, LLM/AI, and container/Kubernetes security
- **Blue & purple team** — CIS benchmarks, service hardening, anomaly detection,
  incident response, and MITRE ATT&CK coverage mapping
- **Operations** — risk-gated engagement modes, OPSEC controls, playbooks, the
  local scheduler, Discord publishing, and an Agent-to-Agent (A2A) endpoint
- **Observability** — Langfuse tracing, Prometheus metrics, JSONL audit trail

### Subagents

- **Security Research** — Threat Scanner (feed monitoring), Vuln Analyst (advisory
  analysis + target correlation), Intel Reporter (digests + Discord publishing)
- **Pen Testing** — Recon (passive enumeration), Exploit (active testing), Reporter
  (finding synthesis + reports)
- **Blue Team** — Defender (CIS/hardening), Incident Responder (correlation/IR),
  Purple Team (red↔blue detection-gap analysis)

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

### Prerequisites

protoPen routes LLM calls through a LiteLLM gateway. Set the gateway key:

```bash
export OPENAI_API_KEY=<litellm-master-key>   # required — LiteLLM gateway auth
export ANTHROPIC_API_KEY=sk-ant-...          # optional — direct Anthropic access
```

### Docker (recommended)

```bash
git clone https://github.com/protoLabsAI/protoPen
cd protoPen

# Start (basic mode)
docker compose up --build
# Operator console at http://localhost:7872/app/
```

### Local

```bash
pip install -r requirements.txt
python -m server --port 7870
# Operator console at http://localhost:7870/app/
```

## Operator Console

A webview UI served at **`/app`** for driving protoPen as a **companion presence
+ a running engagement** — autonomous-first, with a capability catalog as the
opt-in manual layer. Six rails: **Home** (companion presence + the always-on
chat steering channel), **Engagement** (scope a target, set the
passive/active/redteam ceiling, start/watch/end), **Findings** (targets · search
· knowledge), **Activity** (the durable agent-initiated thread), **Capabilities**
(a searchable catalog of the live tool registry, plus skills/workflows/subagents),
and **System** (status · audit · schedule).

The chat is **always streaming**: token-by-token answers, it keeps running in the
background as you navigate rails, and it self-heals a turn interrupted by a
reload by reconciling against the durable server task. See the
[Operator Console guide](docs/guides/operator-console.md).

## Tools

The catalog below is generated from the live tool registry
(`get_combined_tools()`) by `scripts/gen_tool_docs.py` — adding or removing a
tool updates it automatically. Run `python scripts/gen_tool_docs.py` after
changing the tool set; CI fails if it drifts. Deeper, hand-written detail for
the external-attack tools follows in [External Attack Simulation](#external-attack-simulation).

<!-- BEGIN GENERATED TOOLS — run: python scripts/gen_tool_docs.py -->

_85 tools, generated from the live registry — do not edit by hand._

### Threat Intelligence & Research

| Tool | Description |
|---|---|
| `cve_search` | Search the NVD CVE database for vulnerabilities |
| `security_feeds` | Aggregate security advisory feeds from well-known sources |
| `github_trending` | Search GitHub for trending and notable AI/ML repositories |
| `browser` | Automate a web browser |
| `lab_monitor` | Monitor protoLabsAI/lab for new experiments, docs, and changes |
| `security_memory` | Persistent security knowledge store with hybrid search |
| `discord_feed` | Read Discord channels and publish research digests |

### Reconnaissance & OSINT

| Tool | Description |
|---|---|
| `external_recon` | Passive external reconnaissance from an attacker's perspective |
| `dns_enum` | DNS enumeration — dig, nslookup, zone transfers, reverse lookups, subdomain brute force |
| `subdomain_discovery` | Subdomain enumeration via subfinder and amass passive mode |
| `osint_recon` | OSINT reconnaissance — theHarvester and whois lookups |
| `maigret` | Maigret OSINT username reconnaissance across 3000+ sites |
| `phoneinfoga` | PhoneInfoga OSINT phone-number reconnaissance |
| `holehe` | holehe OSINT email reconnaissance — which sites have an account for an email |
| `recon_pipeline` | Automated recon pipeline — chained reconnaissance orchestration |

### Network Enumeration

| Tool | Description |
|---|---|
| `blackarch` | Run BlackArch security tools (nmap, aircrack, bettercap, tshark, etc) |
| `lan_scan` | LAN discovery and enumeration (risk level 1 — active probing) |
| `service_enum` | Service enumeration — enum4linux, SMB share listing, RPC queries |
| `web_enum` | Web content enumeration — directory brute force, vhost discovery, parameter fuzzing |
| `api_enum` | API enumeration — Swagger/OpenAPI discovery, endpoint brute force, method checking |
| `ssl_audit` | SSL/TLS audit via testssl.sh — protocols, ciphers, vulnerabilities, certificates |
| `perimeter_audit` | Network perimeter and router/CPE audit — UPnP, default creds, RouterSploit, WAN exposure |
| `ipv6_attack` | IPv6 network attack and discovery — THC-IPv6 suite, nmap IPv6 |

### Vulnerability Assessment

| Tool | Description |
|---|---|
| `vuln_scan` | Vulnerability scanning — nikto, nuclei templates, nmap NSE vuln scripts |
| `sql_test` | SQL injection testing via sqlmap |
| `web_vuln` | Web vulnerability testing — XSS (dalfox), CORS misconfiguration, open redirect |
| `cve_match` | CVE matching — searchsploit, nmap vulners NSE, nuclei CVE templates |
| `ssrf_detect` | SSRF detection — payload injection, callback server, cloud metadata checks |
| `rate_limit` | Rate limit testing — detect and test bypass techniques |

### Web, API & Auth Testing

| Tool | Description |
|---|---|
| `jwt_tool` | JWT analysis — decode, algorithm-none attack, crack weak secrets, tamper claims |
| `auth_test` | Authentication & authorization testing — BOLA/IDOR, privilege escalation, session testing |
| `auth_audit` | Modern authentication security testing |
| `graphql_test` | GraphQL security testing — introspection, depth/complexity fuzzing, batch query abuse |
| `grpc_audit` | gRPC and protobuf security testing |
| `websocket_test` | WebSocket security testing — authentication bypass, CSWSH, injection |
| `spa_test` | SPA client-side security testing |

### Exploitation & Post-Exploitation

| Tool | Description |
|---|---|
| `msf_exploit` | Metasploit Framework — module search, exploit execution, payload generation |
| `credential_attack` | Credential attacks — hydra brute force, password spraying, combo lists, Responder LLMNR/NBT-NS poisoning, CrackMapExec SMB enumeration/sp… |
| `hashcat_rules` | Hash cracking — hashcat, john the ripper, hash identification |
| `ad_attack` | Active Directory security testing — BloodHound, Certipy, impacket |
| `priv_esc` | Privilege escalation enumeration — linpeas, sudo checks, SUID discovery |
| `lateral_move` | Lateral movement — psexec, wmiexec, evil-winrm, SSH pivoting |
| `data_exfil` | Data exfiltration — controlled file extraction for evidence collection |
| `persistence` | Persistence — establish persistence for authorized engagement testing |
| `cleanup` | Cleanup — remove engagement artifacts and persistence from targets |
| `evasion` | Payload evasion and AV bypass — encoding, obfuscation, detection testing |
| `phishing` | Phishing simulation — GoPhish, Evilginx, email security |

### Wireless, RF & Hardware

| Tool | Description |
|---|---|
| `device_manager` | Manage USB device connections (PortaPack, Flipper, Marauder, WiFi adapter) |
| `portapack` | Control PortaPack H4M via Mayhem serial shell (RF 1MHz–6GHz) |
| `flipper` | Control Flipper Zero via serial CLI |
| `marauder` | Control WiFi Marauder on Flipper Zero (ESP32 WiFi attacks) |
| `wifi_intel` | Alfa WiFi adapter control — passive landscape surveys and targeted WPA capture |

### Specialized Domains

| Tool | Description |
|---|---|
| `iot_protocol` | IoT protocol security testing — MQTT, CoAP, Modbus, BACnet, UPnP, Zigbee |
| `iot_audit` | IoT device security audit — discovery, fingerprinting, and vulnerability assessment |
| `mobile_audit` | Mobile app security testing — APK decompilation, static/dynamic analysis |
| `telecom_attack` | 5G/telecom security testing — GTP, SIP, SS7, Diameter, IMSI |
| `supply_chain` | Supply chain attack testing — dependency confusion, typosquatting, secrets |
| `serverless_audit` | Serverless/edge function security testing |
| `cicd_audit` | CI/CD pipeline security scanning — secret detection, IaC scanning, SAST |
| `sdn_attack` | SDN/network automation security testing |
| `llm_audit` | AI/LLM security testing — prompt injection, model abuse, RAG poisoning |
| `container_audit` | Container & Kubernetes security auditing and escape detection |

### Traffic Analysis & Network Monitoring

| Tool | Description |
|---|---|
| `traffic_analysis` | Packet capture and traffic analysis for networks you own or have authorization to test |
| `net_monitor` | Network monitoring — traffic baselines, host anomaly detection, DNS monitoring |

### Blue Team / Defensive

| Tool | Description |
|---|---|
| `cis_audit` | Defensive CIS benchmark scanning and configuration auditing |
| `hardening_check` | Per-service hardening validation with specific remediation steps |
| `ir_toolkit` | Incident response — log correlation, IOC matching, timeline reconstruction |
| `purple_team` | Purple team mode — correlate red-team attacks with blue-team detections |

### Engagement & Orchestration

| Tool | Description |
|---|---|
| `engagement` | Manage pentest engagements — mode enforcement, logging, reporting |
| `target_intel` | Query and manage the target intelligence database |
| `opsec` | Opsec management — MAC randomization, interface fingerprint control, nmap opsec profiles |
| `playbook` | Playbook system — run predefined tool sequences |
| `orchestrator` | Automated engagement orchestrator — scripted pen test pipeline with agent hand-off |
| `chain_planner` | Recommend next tool actions based on accumulated target intelligence |
| `technique_library` | Store and retrieve successful attack techniques for reuse |
| `schedule_task` | Schedule a future task |
| `list_schedules` | List the current scheduled jobs |
| `cancel_schedule` | Cancel a scheduled job by id (from ``schedule_task`` or ``list_schedules``) |
| `create_task` | Track a long-running or multi-step task in the persistent tracker (beads) |
| `list_tasks` | List tracked tasks |
| `update_task` | Advance or re-prioritize a tracked task — set its status (open → in_progress → closed, or blocked) and/or its priority |
| `close_task` | Mark a tracked task done/closed once its work is complete |
| `set_goal` | Commit to an autonomous goal — keep working across turns until a verifier confirms it's met (or the iteration budget runs out) |
| `request_user_input` | Pause and ask the operator for input, then STOP and wait — do not continue until they respond |
| `request_approval` | Pause for the operator's approval of a specific action, then STOP and wait |

<!-- END GENERATED TOOLS -->

### External Attack Simulation

Simulates a real external attacker with no prior access — passive footprint first, then active perimeter assault. All WAN-facing scans route through a configured external pivot (`PIVOT_HOST` env) to ensure results reflect a genuine outside-in view rather than hairpin NAT artifacts.

| Tool | Description |
|---|---|
| `external_recon` | Passive external footprint: WAN IP discovery, Shodan/Censys host intelligence, BGP/ASN ownership, certificate transparency (crt.sh subdomain enumeration), DNS security posture (SPF/DKIM/DMARC/CAA), cloud storage exposure (S3/Azure/GCS). `SHODAN_API_KEY` enables API mode; falls back to Shodan CLI if absent. |
| `perimeter_audit` | Active perimeter assault: router fingerprinting (banner/SNMP/web UI), UPnP device discovery and unauthenticated port-mapping abuse, default credential testing, RouterSploit autopwn, WAN port scan (parallel SYN+ACK via SSH pivot), DNS rebinding check, firewall egress mapping. |

#### `perimeter_audit` actions

| Action | Description |
|---|---|
| `router_fingerprint` | Banner grab, HTTP/HTTPS web UI title, SNMP community string enumeration |
| `upnp_discover` | SSDP broadcast — find all UPnP devices including the IGD |
| `upnp_portmap` | List existing UPnP port-forwarding rules (what's already exposed on WAN) |
| `upnp_add_portmap` | Test whether the IGD accepts unauthenticated port mapping additions |
| `default_creds` | Spray common ISP default credentials against router admin interface |
| `routersploit_scan` | RouterSploit autopwn — tests all known router CVEs against the gateway |
| `wan_portscan` | Parallel SYN+ACK scan of WAN IP via SSH pivot — reports all port states (open/filtered/closed), not just open. Includes ISP management ports (4567, 7547, 9443). |
| `tcp_probe` | **Deep TCP flag analysis** on specific ports via `hping3` + `nmap -sA/-sF/-sN` battery. Distinguishes: `FIN+ACK` (IP-allowlisted ISP/CPE management — port is live but rejects non-ISP source IPs), `RST` (closed), `SYN+ACK` (open), silence (stateful firewall drop). Run this when Shodan shows a port indexed but nmap reports it filtered. |
| `acs_fingerprint` | Probe ISP/CPE management infrastructure: TR-069 CWMP (7547), proprietary ACS (4567), Lumen Tungsten HTTPS (9443), Huawei HG (30005). Banner-grabs each port and correlates rDNS with known ISP management architectures (CenturyLink/Lumen, Comcast, AT&T, Verizon, Cox). |
| `dns_rebind_check` | Test whether the router blocks DNS rebinding attacks |
| `firewall_egress` | Test which outbound ports pass through the firewall (C2 channel assessment) |
| `full_perimeter` | Run all checks in parallel. Includes `tcp_probe` + `acs_fingerprint` automatically when `external_ip`/`pivot_host` is provided. |

#### External pivot

WAN-facing actions (`wan_portscan`, `tcp_probe`, `acs_fingerprint`) **strongly recommend an external pivot** for public IPs — scanning from the local host traverses hairpin NAT and produces unreliable results. Without a pivot the tool warns and proceeds locally (useful only if the host is externally routed). Set the pivot once and all tools use it automatically:

```bash
# systemd drop-in (persistent across restarts)
mkdir -p ~/.config/systemd/user/protopen.service.d/
cat > ~/.config/systemd/user/protopen.service.d/pivot.conf <<EOF
[Service]
Environment=PIVOT_HOST=root@your-vps-ip
EOF
systemctl --user daemon-reload && systemctl --user restart protopen
```

Or set in `docker-compose.yml`:
```yaml
environment:
  - PIVOT_HOST=root@your-vps-ip
```

The pivot needs `nmap`, `hping3`, `nc`, `bash`, and `timeout` — plus SSH access. Any external VPS works (AWS, DigitalOcean, Vultr — or a Tailscale-connected host).

#### Playbooks

Two new playbooks for end-to-end external attack simulation:

| Playbook | Steps | Description |
|---|---|---|
| `external_recon` | 13 | Passive footprint: WAN IP → Shodan → BGP/ASN → cert transparency → DNS security → subdomain enum → OSINT → cloud exposure → SSL audit |
| `perimeter_attack` | 14 | Active assault: router fingerprint → UPnP abuse → default creds → RouterSploit → WAN port scan → **TCP flag analysis** → **ACS fingerprint** → CVE correlation |

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
│   ├── cis_audit.py      # CIS benchmark + config audits
│   ├── net_monitor.py    # Network monitoring + anomaly detection
│   ├── hardening_check.py# Service hardening validation
│   ├── ir_toolkit.py     # Incident response toolkit
│   ├── purple_team.py    # Purple team correlation engine
│   ├── external_recon.py # Passive external footprint (Shodan, BGP, crt.sh, DNS, cloud)
│   ├── perimeter_audit.py# Active perimeter assault (router, UPnP, WAN scan, tcp_probe, ACS)
│   ├── parsers/          # Output normalizers (nmap XML, ATT&CK alignment, etc.)
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
| `/think <level>` | Set reasoning effort |
| `/tools` | List registered tools |
| `/audit [n]` | Show recent audit log entries |
| `/goal <condition>` | Set an autonomous goal — re-invoke the agent until a verifier passes ([Goals](docs/reference/goals.md)) |
| `/help` | Show all commands |

## Goals (Autonomy)

For outcomes that need several turns, the agent can be pointed at a **goal** — set
by the operator with `/goal <condition>` or by the agent itself via the `set_goal`
tool. protoPen then re-invokes the agent each turn until a **verifier** confirms
completion, the iteration budget runs out, or it's flagged unreachable. Verifiers
are read-only (no shell): `findings` (engagement findings), `targets` (discovered
hosts), `task` (a tracked task is done), or `llm` (a judge). The console's **Goals**
tab browses active/past goals. See **[Goals (Autonomy)](docs/reference/goals.md)**.

## Playbooks

protoPen ships with pre-built playbooks that chain tools into multi-step workflows. All steps produce structured JSON output and handle tool failures gracefully (`on_fail: continue`).

| Playbook | Steps | Description |
|---|---|---|
| `external_recon` | 13 | **Passive external footprint** — WAN IP discovery, Shodan/BGP/ASN, cert transparency, DNS security posture, subdomain enum, OSINT, cloud storage exposure, SSL audit |
| `personal_osint` | 6 | **Passive personal profiling** — pivot a person across username (maigret), email→accounts (holehe), phone (phoneinfoga), and an associated domain (theHarvester). Each step runs only if its seed is given. `requires_engagement`. |
| `perimeter_attack` | 14 | **Active perimeter assault** — router fingerprint, UPnP abuse, default creds, RouterSploit, WAN scan (SYN+ACK via pivot), TCP flag analysis, ACS fingerprint, CVE correlation |
| `post_exploitation` | 16 | **Post-exploitation chain** — sudo enum, SUID discovery, kernel exploits, linpeas, persistence check, SSH key plant, SSH pivot, pass-the-hash, psexec, evidence collection |
| `ad_attack` | 16 | **Active Directory attack chain** — LDAP enum, enum4linux-ng, BloodHound collection, ADCS enumeration (certipy), AS-REP roasting, Kerberoasting, certificate abuse (ESC1), secretsdump |
| `api_security_assessment` | 23 | **Modern API security** — gRPC reflection + auth testing, GraphQL introspection/depth/batch, JWT decode + algorithm bypass + crack, SSRF injection + blind callback, rate limit detection + bypass |
| `spa_assessment` | 10 | **SPA security** — source map exposure, token leakage audit, route guard bypass, state store inspection, postMessage scanning, DOM XSS |
| `purple_team_exercise` | 9 | Red recon → blue defense → MITRE ATT&CK coverage matrix + exercise report |
| `defensive_assessment` | 6 | CIS SSH/TLS/firewall audits, SSH hardening, patch check, port baseline |
| `incident_response` | 5 | Log search, IOC scan, auth log analysis, timeline, containment |
| `full_recon` | 6 | nmap, DNS enum, subdomain discovery, OSINT, web dirs, SSL check |
| `web_vuln_assessment` | 6 | nikto, nuclei, XSS, SQLi, CORS, CVE scan |
| `smb_enum` | 4 | enum4linux, SMB shares, RPC users, CVE check |
| `wifi_landscape_survey` | 6 | **Passive WiFi landscape survey** — monitor start, airodump-ng scan on stable channel list (2.4+5GHz, 5 min default), target_intel upsert, monitor stop, report. Safe to run repeatedly via A2A. |
| `wifi_pentest_local` | 9 | **Active WiFi pen test** — monitor start, 60s survey, passive PMKID capture (hcxdumptool → hc22000), WPA handshake capture (deauth, conditional on bssid+channel set and REDTEAM mode). Note: handshake capture requires kernel < 6.9 for frame injection. |
| `network_traffic_survey` | 4 | **Passive network traffic capture and analysis** — live pcap capture (tcpdump), full flow/protocol/anomaly analysis (tshark), cleartext credential harvest. Safe, no injection. Suitable for own-network baseline monitoring. |
| `tls_intercept_session` | 4 | **TLS interception session** — ARP spoof + mitmproxy transparent intercept, flow analysis, session reconstruction. REDTEAM engagement level; own devices only; tears down cleanly on timeout. |

Run via the `/purple` command (for purple team exercises) or programmatically:

```python
from playbooks.loader import load_playbook
from playbooks.runner import run_playbook

pb = load_playbook("defensive_assessment", {"target": "192.168.4.1"})
result = await run_playbook(pb, dispatch)
```


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

`message/send` returns immediately with a `submitted` task — long-running ops run in the background.

```bash
# Submit a task (returns in <1s)
TASK=$(curl -s -X POST http://steamdeck:7870/a2a \
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
  }' | jq -r '.result.id')

# Poll until completed
curl http://steamdeck:7870/tasks/$TASK | jq '.status.state,.artifacts[0].parts[0].text'
```

Or stream progress in real-time via SSE (first frame is always `submitted`):

```bash
curl -N -X POST http://steamdeck:7870/message:stream \
  -H "Content-Type: application/json" \
  -d '{"message":{"parts":[{"kind":"text","text":"Passive recon 192.168.1.0/24"}]}}'
```

See the [A2A Integration guide](docs/guides/a2a-integration.md) for full details: polling, streaming, push notifications, and task cancellation.

## Knowledge Search

Hybrid search combining vector similarity (Qwen3-Embedding-0.6B via sqlite-vec) with BM25 keyword matching (SQLite FTS5), fused via Reciprocal Rank Fusion (RRF). Searches across advisories, exploits, threat intel, and digests.

**Search modes** (configurable in `langgraph-config.yaml`):
- `hybrid` (default) — RRF fusion of vector + keyword results
- `vector` — semantic similarity only
- `keyword` — BM25 keyword matching only

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `AGENT_BACKEND` | No | `langgraph` |
| `PROTOPEN_API_KEY` | No | API key for A2A authentication |
| `OPENAI_API_KEY` | Yes | LiteLLM gateway master key |
| `ANTHROPIC_API_KEY` | No | Direct Anthropic API key (optional) |
| `GITHUB_TOKEN` | No | GitHub API (higher rate limits) |
| `DISCORD_BOT_TOKEN` | No | Discord channel reading |
| `DISCORD_WEBHOOK_URL` | No | Discord webhook for publishing digests, security alerts, and engagement reports (managed via Infisical in prod) |
| `SHODAN_API_KEY` | No | Shodan API — enables `external_recon shodan_host/shodan_search` actions |
| `CENSYS_API_ID` | No | Censys API ID — enables `external_recon censys_host` |
| `CENSYS_API_SECRET` | No | Censys API secret |
| `PIVOT_HOST` | No | External pivot for WAN scanning — `user@host` (e.g. `root@1.2.3.4`). Required for `wan_portscan`, `tcp_probe`, `acs_fingerprint` against public IPs. |
| `MAIGRET_BIN` | No | Path to the isolated `maigret` binary for the `maigret` OSINT username tool. Auto-set by `start.sh` (`~/.maigret-venv/bin/maigret`); the Docker image puts it on `PATH`. Falls back to `maigret` on `PATH`. |
| `LANGFUSE_PUBLIC_KEY` | No | Langfuse tracing |
| `LANGFUSE_SECRET_KEY` | No | Langfuse tracing |

## Stack

- **Agent**: LangGraph
- **LLM**: LiteLLM gateway → Claude (Sonnet/Haiku) via `OPENAI_API_KEY`
- **UI**: Gradio 5 (dark theme, PWA)
- **Knowledge**: SQLite + sqlite-vec + FTS5 (hybrid search: vector similarity + BM25 keyword, RRF fusion)
- **Observability**: Langfuse tracing, Prometheus metrics, JSONL audit
- **Container**: Docker with seccomp, read-only root, tmpfs workspace

## Part of protoLabs

protoPen is part of the [protoLabs](https://protolabs.studio) autonomous development studio.

| Agent | Role |
|---|---|
| **Ava** | Chief of Staff — orchestration and strategy |
| **Quinn** | QA Engineer — verification and release management |
| **protoPen** | Security — threat intelligence, pen testing, and security research |
