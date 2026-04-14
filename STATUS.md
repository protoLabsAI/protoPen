# protoPen — Project Status

**Last updated**: 2026-04-13 (evening)
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

**655 tests passing** (2026-04-13)

| Area | Tests | File |
|------|-------|------|
| Enforcement | 38 | scope_validator, rate_limiter, kill_chain, engagement_store |
| Pentest tools | 187 | blackarch, dns_enum, subdomain, osint, flipper, marauder, portapack |
| Phase 3 web/api | 68 | phase3_tools |
| Blue team | 85 | blue_team, blue_team_parsers |
| Attack normalizer | 38 | attack_normalizer |
| Parsers | 82 | parser_nmap, parser_bettercap, parser_wiring, parser_e2e, parsers_dispatch |
| Knowledge | 12 | knowledge_ingest, enforcement_middleware |
| Playbook integration | 30 | playbook_integration (step refs, ATT&CK normalization, end-to-end) |
| `/purple` command | 14 | purple_command (code fence stripping, scope substitution, callbacks) |
| Target store | 19 | target_store, target_intel, engagement_autoupsert |
| Container audit | 31 | test_container_audit, test_container_audit_parsers |
| WebSocket testing | 23 | test_websocket_test, test_websocket_test_parsers |

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

### Blue Team — Defensive (7 tools, 36 actions)
| Tool | Actions |
|------|---------|
| `cis_audit` | ssh_audit, tls_audit, firewall_audit, patch_check, port_baseline |
| `net_monitor` | traffic_baseline, host_discovery, service_diff, dns_monitor, protocol_anomaly |
| `hardening_check` | ssh_harden, nginx_harden, apache_harden, docker_harden, k8s_harden |
| `ir_toolkit` | log_search, ioc_scan, auth_log_analyze, timeline_build, containment_recommend |
| `purple_team` | coverage_matrix, detection_gap, exercise_report |
| `container_audit` | kube_hunter, kube_hunter_internal, kube_bench, kube_bench_target, deepce, cdk_evaluate, cdk_exploit, trivy_image, trivy_k8s, trivy_fs |
| `websocket_test` | auth_bypass, cswsh, injection |

## Subagents (9)

| Domain | Subagent | Tools |
|--------|----------|-------|
| Intel | threat_scanner | cve_search, security_feeds, github_trending, browser, security_memory |
| Intel | vuln_analyst | cve_search, browser, security_memory, target_intel |
| Intel | intel_reporter | security_memory, discord_feed |
| Red | recon | device_manager, portapack, flipper, marauder, blackarch, engagement |
| Red | exploit | device_manager, portapack, flipper, marauder, blackarch, websocket_test, engagement |
| Red | reporter | engagement, security_memory, discord_feed |
| Blue | defender | cis_audit, hardening_check, container_audit, engagement |
| Blue | incident_responder | ir_toolkit, net_monitor, engagement, security_memory |
| Blue | purple_team | purple_team, cis_audit, container_audit, net_monitor, ir_toolkit, engagement, security_memory |

## Playbooks (8)

| Playbook | Steps | Tags |
|----------|-------|------|
| `full_recon` | 6 | recon, nmap, dns, web |
| `web_vuln_assessment` | 5 | web, vuln, nikto, gobuster |
| `smb_enum` | 3 | smb, enum, shares |
| `defensive_assessment` | 6 | blue-team, defensive, cis, hardening |
| `incident_response` | 5 | blue-team, ir, forensics |
| `purple_team_exercise` | 9 | purple-team, red-team, blue-team, mitre-attack |
| `container_security_assessment` | 5 | container, k8s, cis, trivy, security |
| `websocket_assessment` | 3 | websocket, web, security |

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
- **CIS audit inline scripts** — Extracted `python3 -c` inline scripts to standalone files in `tools/scripts/` (ssh_audit.py, tls_audit.py, port_baseline.py, ssh_harden.py). Inline scripts broke on Python 3.12 with f-string/escape changes. Standalone scripts are testable and maintainable.
- **Port baseline scan range** — Was scanning all 65535 ports (timeout guaranteed). Now scans 1–1024 + expected high ports. Uses spec timeout (300s) instead of `min(caller, spec)`.
- **Timeout bug across all 19+ tools** — Every `BasePentestTool` subclass used `min(timeout, spec_timeout)` which let callers (playbook YAML `timeout: 30`) clamp the spec-defined timeout. Fixed to use spec timeout directly.
- **Direct tool dispatch for playbooks** — `/purple` was routing each playbook step through the LLM agent, which wrapped/summarized raw tool output. Now dispatches directly to tools, preserving structured JSON.
- **Detection rate formatting** — `detection_rate_pct` (50.0) was formatted with `:.0%` producing "5000%". Fixed to `:.0f%`.
- **Coverage matrix false gaps** — Only successful attacks now count in the detection rate denominator. Failed attacks (e.g. nikto on a non-web target) downgraded from "high" to "info" severity.

## Live Validation (Steam Deck, 2026-04-13)

| Playbook | Steps | Result |
|----------|-------|--------|
| `purple_team_exercise` | 9/9 ✅ | 100% detection rate, GOOD rating |
| `defensive_assessment` | 6/6 ✅ | All tools produce valid JSON |
| `incident_response` | 5/5 ✅ | Log search, IOC, auth, timeline, containment |
| `full_recon` | 6/6 ✅ | nmap + DNS working, others graceful fallback |

**A2A endpoint verified**: `/purple 192.168.4.1` → 9/9 steps, GOOD rating, clean Markdown response.

## Known Issues

- Integration tests (`test_integration.py`) skip on macOS — they require the full LangChain/nanobot runtime on the Deck
- Prefer `http://steamdeck:7870` (Tailscale) over SSH for A2A calls
- `full_recon` steps 3–6 (subfinder, theharvester, gobuster, ssl_audit) need their binaries installed on the Deck
