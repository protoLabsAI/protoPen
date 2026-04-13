# protoPen — Project Status

**Last updated**: 2026-04-13
**Branch**: `main`
**All changes pushed**: ✅

---

## Phase Status

| Phase | Status | Commit | Summary |
|-------|--------|--------|---------|
| **1. Enforcement** | ✅ Done | `77d98c1`→`de5b55b` | Scope/phase/rate validators, middleware, engagement store, shell lockdown |
| **2. Pentest Toolkit** | ✅ Done | `059bd4f`→`ee27a08` | 22 tools: recon, enum, vuln scan, exploitation, post-exploit, cleanup |
| **3. Web/API Testing** | ✅ Done | `ee27a08` | 6 tools: JWT, SSRF, auth/BOLA, rate limit, GraphQL, technique library |
| **4. Blue Team** | ✅ Done | `ce1492f` | 5 tools: CIS audit, net monitor, hardening, IR toolkit, purple team |
| **5. Integration** | ✅ Done | `612215b`→`72bfea9` | Parsers, playbooks, tests, auto-ingest, `/purple` command |

## Test Suite

**511 tests passing** (2026-04-13)

| Area | Tests | File |
|------|-------|------|
| Enforcement | 38 | scope_validator, rate_limiter, kill_chain, engagement_store |
| Pentest tools | 187 | blackarch, dns_enum, subdomain, osint, flipper, marauder, portapack |
| Phase 3 web/api | 68 | phase3_tools |
| Blue team | 80 | blue_team, blue_team_parsers |
| Parsers | 82 | parser_nmap, parser_bettercap, parser_wiring, parser_e2e, parsers_dispatch |
| Knowledge | 12 | knowledge_ingest, enforcement_middleware |
| Playbook integration | 17 | playbook_integration |
| `/purple` command | 8 | purple_command |
| Target store | 19 | target_store, target_intel, engagement_autoupsert |

## Tool Inventory

### Security Intel (7 tools)
cve_search, security_feeds, github_trending, browser, lab_monitor, security_memory, discord_feed

### Pentest — Red Team (~28 tools)
device_manager, portapack, flipper, marauder, blackarch, engagement, target_intel,
dns_enum, subdomain_discovery, osint_recon, web_enum, service_enum, ssl_audit, api_enum,
vuln_scan, sql_test, web_vuln, cve_match, msf_exploit, credential_attack, hashcat_rules,
priv_esc, lateral_move, data_exfil, persistence, cleanup,
jwt_tool, ssrf_detect, auth_test, rate_limit, graphql_test,
technique_library, playbook, chain_planner

### Blue Team — Defensive (5 tools, 23 actions)
| Tool | Actions |
|------|---------|
| `cis_audit` | ssh_audit, tls_audit, firewall_audit, patch_check, port_baseline |
| `net_monitor` | traffic_baseline, host_discovery, service_diff, dns_monitor, protocol_anomaly |
| `hardening_check` | ssh_harden, nginx_harden, apache_harden, docker_harden, k8s_harden |
| `ir_toolkit` | log_search, ioc_scan, auth_log_analyze, timeline_build, containment_recommend |
| `purple_team` | coverage_matrix, detection_gap, exercise_report |

## Subagents (9)

| Domain | Subagent | Tools |
|--------|----------|-------|
| Intel | threat_scanner | cve_search, security_feeds, github_trending, browser, security_memory |
| Intel | vuln_analyst | cve_search, browser, security_memory, target_intel |
| Intel | intel_reporter | security_memory, discord_feed |
| Red | recon | device_manager, portapack, flipper, marauder, blackarch, engagement |
| Red | exploit | device_manager, portapack, flipper, marauder, blackarch, engagement |
| Red | reporter | engagement, security_memory, discord_feed |
| Blue | defender | cis_audit, hardening_check, engagement |
| Blue | incident_responder | ir_toolkit, net_monitor, engagement, security_memory |
| Blue | purple_team | purple_team, cis_audit, net_monitor, ir_toolkit, engagement, security_memory |

## Playbooks (6)

| Playbook | Steps | Tags |
|----------|-------|------|
| `full_recon` | 6 | recon, nmap, dns, web |
| `web_vuln_assessment` | 5 | web, vuln, nikto, gobuster |
| `smb_enum` | 3 | smb, enum, shares |
| `defensive_assessment` | 6 | blue-team, defensive, cis, hardening |
| `incident_response` | 5 | blue-team, ir, forensics |
| `purple_team_exercise` | 9 | purple-team, red-team, blue-team, mitre-attack |

## Chat Commands

| Command | Description |
|---------|-------------|
| `/new` | Clear chat history + session |
| `/clear` | Clear chat display |
| `/think <level>` | Set reasoning effort (low/medium/high/off) |
| `/compact` | Force memory consolidation |
| `/model` | Show current model |
| `/tools` | List registered tools |
| `/topics` | Show tracked security topics |
| `/agenda` | Show security intelligence agenda with stats |
| `/cves [query]` | Search stored CVEs and advisories |
| `/recent [n]` | Show recent findings |
| `/audit [n]` | Show recent audit log entries |
| `/lab on\|off\|status` | Toggle lab mode (GPU experiment runner) |
| `/intel` | Generate security intelligence digest and publish to Discord |
| `/purple <scope>` | Run purple team exercise (red+blue+ATT&CK report) |

## Infrastructure Updates (2026-04-13)

- **Discord Webhook** — Created `protoPen Security Reports` webhook for channel `1493168494945243227`. Used for publishing engagement reports as color-coded severity embeds.
- **Infisical** — `DISCORD_WEBHOOK_URL` added to protoPen `prod` vault. Auto-exported at startup via `start.sh`.
- **A2A Protocol** — Verified end-to-end: JSON-RPC `message/send` and `message/sendStream` working for agent-to-agent delegation. Used to orchestrate a full LAN red team engagement remotely.
- **Engagement Reports** — `engagement generate_report` saves full markdown report to `<workspace_dir>/<engagement_name>/report.md` (default: `/home/deck/engagements/`).

## Bugfixes (2026-04-13)

- **EnforcementMiddleware ToolMessage fix** (`1635616`) — Blocked tool calls returned raw strings instead of `ToolMessage` objects, breaking the Anthropic API's `tool_use`/`tool_result` pairing. Fixed with `_blocked_response()` that wraps all blocked messages in `ToolMessage` with the correct `tool_call_id`.
- **A2A context_id collision** (`1635616`) — Fallback context IDs used `rpc_id` (often `1`, `2`, `3`), causing session collisions. Changed to UUID4.
- **Wireshark group** — `deck` user added to `wireshark` group for tshark/dumpcap packet capture access.

## Known Issues

- Integration tests (`test_integration.py`) skip on macOS — they require the full LangChain/nanobot runtime on the Deck
- `/purple` correlation step passes empty `red_results`/`blue_results` to the matrix — needs result piping between steps (future enhancement)
- Prefer `http://steamdeck:7870` (Tailscale) over SSH for A2A calls
