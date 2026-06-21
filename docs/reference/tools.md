# Tools

The agent loads its tools from a single registry (`get_combined_tools()`). The
catalog below is generated straight from that registry by
`scripts/gen_tool_docs.py`, so it always reflects exactly what the agent can
call — adding or removing a tool updates this page (CI fails if it drifts).

Each entry is the tool's own one-line description. For deeper, task-oriented
walkthroughs see the [Tutorials](/tutorials/) and [How-To Guides](/guides/);
for the engagement-mode gating that controls when each tool is allowed, see
[Engagement Modes](/reference/engagement-modes).

<!-- BEGIN GENERATED TOOLS — run: python scripts/gen_tool_docs.py -->

_89 tools, generated from the live registry — do not edit by hand._

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
| `telecom_attack` | Telecom security testing — SIP (SIPVicious) + IMSI detection (gr-gsm) |
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
| `wait` | Yield this turn and get re-invoked later — instead of busy-waiting |
| `memory_list` | List durable semantic facts, each prefixed with its #id so you can target one for forget_memory |
| `forget_memory` | Delete exactly ONE durable fact by its id (from memory_list) — for pruning a stale, superseded, or duplicate fact |
| `recent_activity` | Read-only digest of recent tool activity (the audit log) — what the agent has been doing lately |
| `create_task` | Track a long-running or multi-step task in the persistent tracker (beads) |
| `list_tasks` | List tracked tasks |
| `update_task` | Advance or re-prioritize a tracked task — set its status (open → in_progress → closed, or blocked) and/or its priority |
| `close_task` | Mark a tracked task done/closed once its work is complete |
| `set_goal` | Commit to an autonomous goal — keep working across turns until a verifier confirms it's met (or the iteration budget runs out) |
| `request_user_input` | Pause and ask the operator for input, then STOP and wait — do not continue until they respond |
| `request_approval` | Pause for the operator's approval of a specific action, then STOP and wait |

<!-- END GENERATED TOOLS -->

## Hardware notes

### PortaPack / HackRF on SteamOS — USB enumeration quirk

PortaPack Mayhem firmware enumerates as `1d50:6018`. The `lsusb` database mislabels this as "Black Magic Debug Probe" — it is not. Confirm with `lsusb -v -d 1d50:6018 | grep iProduct` → `PortaPack Mayhem`.

Stock `libhackrf` (from `pacman -S hackrf`) only recognises `1d50:6089` (HackRF One) and will report "No HackRF boards found." even with the device connected. Two fixes are required:

**1. Custom udev rule** — gives the `deck` user access to the device node:

```bash
echo 'ATTR{idVendor}=="1d50", ATTR{idProduct}=="6018", SYMLINK+="hackrf-portapack-%k", TAG+="uaccess"' | \
  sudo tee /etc/udev/rules.d/53-hackrf-portapack.rules
sudo udevadm control --reload-rules && sudo udevadm trigger --attr-match=idVendor=1d50
```

**2. Patched libhackrf** — see [Steam Deck Setup → HackRF / PortaPack](../tutorials/steam-deck-setup#hackrf-portapack) for the full build procedure. After patching, `hackrf_info` shows `Found HackRF`. The `hackrf_board_id_read() failed: Pipe error` messages are expected — Mayhem intercepts some USB control transfers; SDR software using SoapyHackRF works normally.

**OS update persistence** — add to `/etc/atomic-update.conf.d/protopen-keep.conf`:
```
/etc/udev/rules.d/53-hackrf-portapack.rules
/usr/lib/libhackrf.so.0.10.0
/usr/lib/libhackrf.so.0
/usr/lib/libhackrf.so
/usr/bin/hackrf_info
```
After an OS update, re-run `~/hackrf-portapack-src/reinstall.sh` to rebuild and reinstall the patched library.
