# Handoff: Goals — the Autonomy Layer

**Date**: 2026-06-01
**Handoff Number**: 002
**Status**: Shipped to `main` and deployed to the Deck.

---

## Overview/Summary

protoPen now has a **goals / autonomy layer** — the top of the
[control stack](../docs/explanation/control-stack.md). A goal re-invokes whole
agent turns toward a **verifier-backed finish condition** until the verifier
passes, the iteration budget runs out, or the goal is flagged unreachable. It owns
*when to stop*; it defines no steps.

It's deliberately **bespoke** to protoPen's tight profile — verifiers are
**read-only, no-shell** (the divergence from protoAgent's command/test/ci
verifiers, which execute on the host). Goals can be set by the **operator**
(`/goal` in chat or the JSON spec) or by the **agent itself** (`set_goal` tool).

## What shipped

| PR | Slice | Content |
|---|---|---|
| #116 | Engine | `graph/goals/` — `GoalState`/`store`/`verifiers`/`controller`; config keys; 11 tests |
| #118 | Integration + UI | `/goal` chat hook + the re-invocation loop in `_chat_langgraph_stream`; `GET /api/goals` + `DELETE /api/goal/{id}`; **Goals** console tab |
| #120 | Follow-ups | agent `set_goal` tool (+ per-turn session contextvar); `targets` + `task` verifiers |
| (this branch) | Handoff polish | `program_set`→`start_goal`; `set_goal` `target` arg for task-by-id; **SOUL.md loader fix** (see below); goals reference doc; README/sidebar/chat-commands; this handoff |

## Architecture

```
graph/goals/
  types.py        GoalState (condition + verifier spec + status/iteration/streak), VerifyResult
  store.py        per-session JSON persistence (GOAL_PATH → /sandbox/goals → ~/.protopen/goals)
  verifiers.py    findings | targets | task | llm  — read-only, no shell. VERIFIERS registry + run_verifier
  controller.py   parse_control (/goal …) · start_goal (programmatic) · evaluate → Decision(continue|done)
  context.py      contextvar carrying the turn's session_id to the set_goal tool
```

- **The loop lives in `server.py`** (`_chat_langgraph_stream`): it wraps
  `astream_events` in a `while True:` that, after each turn, calls
  `controller.evaluate(...)`; on `continue` it re-invokes the same thread with the
  continuation prompt, on `done` it finishes. An absolute `hard_cap = 30` backstops
  the goal's own `max_iterations`.
- **`set_goal` tool** (`tools/lg_tools.py`) reads the session_id from
  `graph/goals/context.py` (set by the server at both graph-invoke sites), builds a
  verifier spec, and calls `controller.start_goal`. Wired via `set_goal_controller()`.
- **Verifiers** read existing stores only via lazy accessors: `_active_findings`
  (`get_engagement_manager`), `_search_hosts` (`get_target_store`), `_list_tasks`
  (`get_beads_handle`), and `create_llm` for the judge.

See the [Goals reference](../docs/reference/goals.md) for the verifier spec table,
the loop's terminal states, config, API, and the **"adding a verifier"** recipe.

## ⚠️ Latent bug fixed in this handoff — SOUL.md was never loaded

`build_system_prompt` read `{workspace}/SOUL.md` (default `/sandbox/SOUL.md`), but
**nothing copies SOUL there** — native `start.sh` symlinks `/sandbox` and copies no
SOUL; the Docker entrypoint copies `skills/` but not SOUL. So the agent silently
ran on a **3-line stub identity**: none of SOUL.md's engagement modes, opsec
mandates, response structure, or tool inventory reached the model. Verified live on
the Deck (system prompt was 3680 chars, did not contain "I am protoPen").

**Fix:** `graph/prompts.py` now resolves SOUL from `{workspace}/SOUL.md` → falls
back to the repo's `config/SOUL.md` (`_REPO_ROOT/config/SOUL.md`, which exists in
both Docker at `/opt/protopen/config` and native at `~/protoPen/config`).
`tests/test_prompts.py` guards it. The agent's goal guidance (the *Autonomous Goal
Pursuit* section + `/goal`) was added to `config/SOUL.md`, so this fix is what
makes that guidance — and the rest of SOUL — actually reach the agent.

> Not changed: the legacy `build_system_prompt` reads of `/sandbox/skills/*/SKILL.md`.
> Those are superseded by the `skills.db` FTS5 retrieval middleware (PR #87); they're
> effectively no-ops and fixing them would risk duplicating the middleware injection.

## Current state

### Done ✅
- [x] Engine + verifiers (findings/targets/task/llm), per-session persistence
- [x] Operator `/goal` (set/status/clear) + JSON specs; **Goals** console tab; `/api/goals` + clear (auth-gated)
- [x] Agent `set_goal` tool (operator-set *and* agent-set paths)
- [x] SOUL.md teaches goal mode; SOUL loader fixed so it (and all of SOUL) reaches the agent
- [x] Docs: control-stack, configuration, chat-commands, README, dedicated Goals reference
- [x] 19 tests (goals + prompts), langchain-free, green on 3.9; CI green; deployed to Deck

### Open / next
- **Verifier ideas** (all read-only, fit the profile): `credentials` (creds captured
  for a host), `engagement_phase` (kill-chain phase reached), `coverage` (hosts with
  ≥1 finding / scope). The registry + UI are verifier-agnostic — see the reference recipe.
- **Subagent goals**: `set_goal` is lead-agent only today (session-keyed). Subagent
  self-direction would need session propagation into the subagent context.
- **Scheduled-turn goals**: the contextvar is set on the two chat paths; a goal set
  during a scheduler-fired turn would need the same `set_current_session` call there.
- **Deploy hygiene** (optional): `start.sh`/`entrypoint.sh` could copy `config/SOUL.md`
  into the workspace so the workspace copy (not just the repo fallback) is populated —
  the code fallback already covers correctness, so this is cosmetic.

## Testing

```bash
python -m pytest tests/test_goals.py tests/test_prompts.py -q   # 19 passing, no langchain needed
```

`tests/test_goals.py` monkeypatches the verifier store accessors
(`_active_findings`, `_search_hosts`, `_list_tasks`) so the verifiers, controller
decisions (achieved/continue/exhausted/giveup/no-progress), `start_goal`, and the
store roundtrip are all covered without a live engagement. `tests/test_prompts.py`
guards the SOUL fallback.

## Deploy notes

Backend + docs only (UI shipped in #118). On the Deck: `git pull`, restart the
`protopen` user service (no web rebuild needed unless `apps/web` changed). Verify:

```bash
curl -s -H "X-API-Key: $KEY" http://127.0.0.1:7870/api/runtime/status | jq .goal
.venv/bin/python -c "from graph.prompts import build_system_prompt as b; \
  print('I am protoPen' in b(include_subagents=False))"   # must be True after the SOUL fix
```
