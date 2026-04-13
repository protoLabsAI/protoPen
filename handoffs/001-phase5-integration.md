# Handoff: Phase 5 — Integration, Tests, and Purple Team Workflow

**Date**: 2026-04-12
**Handoff Number**: 001

---

## Overview/Summary

Phases 1–4 of the protoPen red/blue team architecture are shipped to `main`. This session built 40+ tools across enforcement, recon, exploitation, web app testing, and blue team domains. The next session picks up **Phase 5** — the integration layer that ties everything together: output parsers for blue-team tools, playbook wiring, comprehensive tests, knowledge store auto-ingest, and an end-to-end `/purple` chat command.

## Background/Context

### Architecture (3 domains, 9 subagents, 40+ tools)

| Domain | Subagents | Tool Count |
|--------|-----------|------------|
| Security Intel | threat_scanner, vuln_analyst, intel_reporter | 7 tools |
| Pentest (Red) | recon, exploit, reporter | ~28 tools |
| Blue Team | defender, incident_responder, purple_team | 5 tools |

### Key decisions already made
- All pentest/blue tools inherit from `BasePentestTool` (`tools/base.py`) — provides subprocess execution, timeout handling, action-based dispatch
- Tools are wrapped as LangChain `@tool` functions in `tools/lg_tools.py` — single source of truth for registration
- Lazy singleton initialization via `_init_pentest_singletons()` — reads `config/engagement-config.json`
- Parsers live in `tools/parsers/` and normalize subprocess output into structured findings
- Playbooks are YAML-defined multi-step sequences in `playbooks/library/`
- Blue-team tools use the same `BasePentestTool` pattern but don't need `_target_store` injection (they're defensive)

### What shipped in this session (4 commits)

| Commit | Phase | Content |
|--------|-------|---------|
| `059bd4f` | Phase 2A | Recon tools — dns_enum, subdomain_discovery, osint_recon + enhanced nmap/hashcat |
| `ee27a08` | Phase 2B+3 | Vuln/exploit/post-exploit tools, web app testing (JWT, SSRF, auth, rate limit, GraphQL), technique library |
| `de5b55b` | (earlier) | EnforcementMiddleware wired into agent graph |
| `ce1492f` | Phase 4 | Blue team — cis_audit, net_monitor, hardening_check, ir_toolkit, purple_team |

## Current State

### Completed ✅
- [x] Phase 1: Enforcement foundation (scope validator, kill chain phases, rate limiter, middleware, engagement store, shell lockdown)
- [x] Phase 2: Full pentest toolkit (recon → enum → vuln assessment → exploitation → post-exploitation → cleanup)
- [x] Phase 3: Web/API testing (JWT, SSRF, auth/BOLA, rate limit, GraphQL, technique library)
- [x] Phase 4: Blue team (CIS audit, network monitoring, hardening checks, IR toolkit, purple team correlation)
- [x] Parsers for all Phase 2–3 tools (`tools/parsers/`)
- [x] Playbook system with 3 example playbooks
- [x] Blue-team skill file (`skills/blue-team/SKILL.md`)
- [x] README updated with all tools, subagents, architecture
- [x] All pushed to `origin/main`

### Remaining — Phase 5 ⬜
- [ ] **5.1** Output parsers for blue-team tools (cis_audit, net_monitor, hardening_check, ir_toolkit results → normalized findings)
- [ ] **5.2** Playbook integration for blue-team (defensive assessment playbook, IR playbook, purple team exercise playbook in `playbooks/library/`)
- [ ] **5.3** Unit tests for computational tools (purple_team matrix/gap/report, IR containment_recommend, technique library CRUD, chain_planner)
- [ ] **5.4** Knowledge store auto-ingest (blue-team tool findings → `security_memory` via middleware or post-execution hook)
- [ ] **5.5** `/purple` chat command — end-to-end workflow: run pentest → collect findings → run defensive checks → ATT&CK coverage report

## Technical Approach

### 5.1 Blue-Team Parsers

Add to `tools/parsers/`:
- `cis_audit.py` — parse JSON output into `{check, passed, severity, remediation}` findings
- `net_monitor.py` — parse traffic baselines, host discovery, DNS monitoring into anomaly findings
- `hardening_check.py` — parse per-service check results into pass/fail findings
- `ir_toolkit.py` — parse log search, IOC matches, auth analysis into incident findings

Pattern to follow: see any existing parser (e.g., `tools/parsers/dns_enum.py`). Each parser takes raw JSON string, returns list of normalized finding dicts.

### 5.2 Blue-Team Playbooks

Add YAML playbooks to `playbooks/library/`:
- `defensive_assessment.yaml` — CIS audit SSH+TLS+firewall → hardening checks → patch check → port baseline
- `incident_response.yaml` — log search → IOC scan → auth log analysis → timeline → containment
- `purple_team_exercise.yaml` — run pentest recon → run defensive checks → purple_team coverage_matrix → exercise_report

Pattern: see `playbooks/library/full_recon.yaml` for the YAML schema.

### 5.3 Tests

Priority test targets (no live infrastructure needed):
- `purple_team.py` — `_coverage_matrix()`, `_detection_gap()`, `_exercise_report()` are pure computation
- `ir_toolkit.py` — `_containment_recommend()` is pure computation
- `knowledge/technique_library.py` — CRUD operations on SQLite
- `knowledge/chain_planner.py` — rule-based suggestion engine

Test pattern: see `tests/test_phase3_tools.py` for how existing tool tests are structured (mock subprocess, assert JSON output).

### 5.4 Knowledge Store Auto-Ingest

Two approaches (pick one):
1. **Post-execution middleware** in `graph/middleware/` — intercept tool results, parse via parser, store in `security_memory`
2. **In-tool hook** — each blue-team tool calls `security_memory.store()` after execution

Approach 1 is cleaner and consistent with how `EnforcementMiddleware` already works. Add a `KnowledgeIngestMiddleware` that checks if a tool result contains findings, parses them, and stores to the knowledge store.

### 5.5 `/purple` Chat Command

Add to `server.py` command handler (see existing `/topics`, `/agenda`, `/cves` patterns):
1. Parse target scope from user input
2. Run pentest recon tools, collect findings with technique IDs
3. Run blue-team defensive checks
4. Feed both result sets into `purple_team exercise_report`
5. Format and return the ATT&CK coverage report

## Key Files and Documentation

| File | Purpose |
|------|---------|
| `tools/lg_tools.py` | **Central tool registry** — all @tool adapters, `get_pentest_tools()`, `get_combined_tools()` |
| `tools/base.py` | `BasePentestTool` base class with `_run()` subprocess execution |
| `tools/parsers/__init__.py` | Parser dispatch — maps tool names to parser modules |
| `graph/subagents/config.py` | 9 subagent definitions with tool allowlists |
| `graph/prompts.py` | System prompt builder — loads SOUL.md, skills, subagent instructions |
| `graph/agent.py` | LangGraph agent builder — `create_researcher_graph()` |
| `graph/middleware/enforcement.py` | EnforcementMiddleware — mode/scope/phase/rate enforcement |
| `playbooks/` | YAML playbook system — schema, loader, runner, tool adapter |
| `knowledge/technique_library.py` | SQLite store for successful attack techniques |
| `knowledge/chain_planner.py` | Rule-based next-step suggestion engine |
| `skills/blue-team/SKILL.md` | Blue team methodology for the agent's system prompt |
| `skills/pentest/SKILL.md` | Pentest methodology for the agent's system prompt |
| `server.py` | FastAPI server — chat commands at ~line 500+, tool init at ~line 100 |
| `config/engagement-config.json` | Device/engagement config consumed by `_init_pentest_singletons()` |

## Acceptance Criteria

- [ ] All 5 blue-team tools have corresponding parsers in `tools/parsers/`
- [ ] At least 3 defensive playbooks exist and can be loaded by the playbook system
- [ ] Tests pass for purple_team, ir_toolkit containment, technique_library, and chain_planner
- [ ] Blue-team tool findings auto-flow into security_memory when a knowledge store is active
- [ ] `/purple <scope>` in chat produces a full ATT&CK coverage report
- [ ] All new code passes `python3 -c "import ast; ast.parse(open(f).read())"` syntax check
- [ ] No regressions in existing tests (`pytest tests/`)

## Open Questions/Considerations

1. **Parser granularity**: Should blue-team parsers normalize into the same finding schema as red-team parsers? Probably yes — unified findings enable cross-correlation in purple_team.
2. **Auto-ingest scope**: Should ALL tool output be auto-ingested, or only findings above a severity threshold? Suggest: ingest everything, let the knowledge store's hybrid search handle relevance.
3. **`/purple` orchestration**: Should it be a synchronous multi-tool call (simple but slow), or should it delegate to the purple_team subagent (async, more robust)? Recommend subagent delegation for robustness.
4. **Test infrastructure**: The existing tests use mocked subprocess calls. Blue-team parser tests should follow the same pattern. The purple_team computational tests don't need mocking at all.

## Next Steps

1. Start with **5.3 Tests** — lowest risk, validates what's already built, no new files to wire
2. Then **5.1 Parsers** — follow existing parser patterns, one file per tool
3. Then **5.2 Playbooks** — YAML definitions, minimal code
4. Then **5.4 Auto-ingest** — middleware approach, hooks into existing graph pipeline
5. Finally **5.5 `/purple` command** — ties everything together, highest complexity
