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
| **5. Integration** | 🔶 Partial | `612215b`→`0494e0b` | Parsers ✅, playbooks ✅, tests ✅, auto-ingest ✅, `/purple` command ⬜ |

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

## What's Next — Phase 5

See `handoffs/001-phase5-integration.md` for full details.

1. **Tests** — unit tests for purple_team computation, IR containment, technique library, chain planner
2. **Parsers** — blue-team output parsers in `tools/parsers/` (cis_audit, net_monitor, hardening_check, ir_toolkit)
3. **Playbooks** — defensive assessment, incident response, purple team exercise YAMLs
4. **Auto-ingest** — KnowledgeIngestMiddleware to pipe findings into security_memory
5. **`/purple` command** — end-to-end chat command for purple team exercises

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

- `/purple` chat command not yet implemented (last Phase 5 item)
- Integration tests (`test_integration.py`) skip on macOS — they require the full LangChain/nanobot runtime on the Deck
- Prefer `http://steamdeck:7870` (Tailscale) over SSH for A2A calls
