# Goals (Autonomy)

Goal mode is the top of protoPen's [control stack](../explanation/control-stack.md):
it re-invokes whole agent turns toward a **testable finish condition** until a
verifier confirms it's met, the iteration budget runs out, or the goal is flagged
unreachable. It owns *when to stop* — it defines no steps of its own.

Everything here is **read-only and no-shell**, in line with the tight engagement
profile: verifiers assert over existing stores, they never execute commands.

## Setting a goal

**Operator — in chat:**

```text
/goal find a critical vuln on the in-scope host      # fuzzy (llm verifier)
/goal {"condition":"≥2 criticals","verifier":{"type":"findings","severity":"critical","min":2}}
/goal                                                 # show current goal + status
/goal clear                                           # stop the active goal
```

A plain-text goal uses the `llm` verifier. A JSON goal takes a full
`verifier` spec (and an optional `max_iterations`).

**Agent — via the `set_goal` tool:** the agent commits to a goal itself when an
operator asks for a multi-turn outcome. After the turn, the loop re-invokes it
with a continuation prompt until the verifier passes. See the
[`set_goal` tool](tools.md) and the *Autonomous Goal Pursuit* section of
`config/SOUL.md`.

> **Goal vs. watch.** A goal *drives* — it re-invokes turns to reach a finish
> line, then stops. To **supervise a standing condition** in parallel (react when
> something becomes true, on its own cadence) use a **watch** instead — see
> [Autonomy → watch](../explanation/autonomy.md). Watches replaced the old
> monitor-goal mode, so a goal has no "monitor" mode; it always drives.

## Completion contract (optional)

Beyond the `verifier` (which decides *when* the goal is done), a JSON goal may
carry a **completion contract** — four optional fields that steer *how* the agent
pursues it. They are **directive-only**: re-stated in the continuation prompt
every drive turn, but the verifier — not the contract — still decides DONE. A
contract-less goal renders nothing extra (its prompt is byte-for-byte the plain
one).

| Field | Type | Injected each turn as | Use for |
|---|---|---|---|
| `outcome` | string | `Required outcome: …` | what "done" should concretely look like |
| `constraints` | string[] | `Constraint (must hold): …` | conditions that must stay true while working |
| `boundaries` | string[] | `Boundary (do NOT): …` | hard "do not" limits |
| `stop_when` | string | `STOP and hand back when: …` | a condition that should halt and return to the operator (agent emits `<goal_unachievable/>`) |

```text
/goal {"condition":"find a critical vuln on the lab subnet",
       "verifier":{"type":"findings","severity":"critical","min":1},
       "outcome":"at least one verified critical with a repro path",
       "constraints":["log every finding as you go"],
       "boundaries":["stay on 10.0.9.0/24","no exploitation without approval"],
       "stop_when":"any action would fall outside the engagement scope"}
```

The `set_goal` tool takes the same four fields as arguments, so the agent can
attach a contract to a goal it sets itself.

## Verifiers

| Type | Met when… | Spec fields | Reads |
|---|---|---|---|
| `findings` | ≥ `min` findings match | `severity` (≥ level), `category` (substring), `min` | engagement-logged findings **+** target-store (parser) findings since the engagement started — so OSINT hits (`osint-account`, `osint-phone`, …) and scan results both count |
| `targets` | ≥ `min` discovered hosts match | `query` (host free-text), `device_type`, `min` | `TargetStore` |
| `task` | the selected beads task(s) are done | `id` (exact) **or** `title` (substring); `status` (default: any done-state) | beads tracker |
| `llm` | an aux-model judge rules the condition met | `condition` (defaults to the goal text) | engagement summary + last message |

`findings`, `targets`, and `task` are precise, no-LLM checks. `llm` is the fuzzy
fallback for goals with no hard signal; it's deliberately conservative
(defaults to *not met* when evidence is thin) and can never mark a goal met on an
evaluator error.

> The `set_goal` tool maps its arguments onto these specs: `severity`/`category`/
> `min_count` for `findings`, `category`→`query` + `min_count` for `targets`, and
> `target`→`id`-or-`title` for `task` (a beads-id shape like `protopen-15t` is
> matched exactly, otherwise as a title substring).

## The loop

After each turn the [controller](../explanation/control-stack.md) runs the
verifier (ground truth — it overrides the model's self-assessment):

1. **Met** → finish, status `achieved`.
2. **Agent gave up** (`<goal_unachievable reason="…"/>` in the reply) → finish,
   status `unachievable`.
3. **Not met** → capture the `<goal_plan>…</goal_plan>` checklist, track progress,
   and **continue** with a continuation prompt — unless a cap trips:
   - `iteration ≥ max_iterations` → `exhausted`
   - no-progress streak ≥ `goals_no_progress_limit` (the verifier's
     reason+evidence signature stops changing) → `unachievable`

The server caps total re-invocations with an absolute `hard_cap` (30) above the
goal's own `max_iterations`, as a backstop.

### Agent protocol

The continuation prompt (and `config/SOUL.md`) instruct the agent to, each turn:

- keep a running checklist inside `<goal_plan>…</goal_plan>` (updated every turn),
- take one concrete step — never stall, repeat, or self-declare completion,
- emit `<goal_unachievable reason="…"/>` to stop if it's impossible/out of scope.

Engagement scope and mode are still enforced on every turn — goal mode never
bypasses them.

## Configuration

```yaml
goals:
  enabled: true          # off → /goal + set_goal return a graceful "unavailable"
  max_iterations: 10      # per-goal re-invocation budget
  no_progress_limit: 4    # consecutive no-progress turns before giving up
```

See [Configuration](configuration.md). Goals persist per session as JSON under
`GOAL_PATH` → `/sandbox/goals` → `~/.protopen/goals`, so they survive the graph
rebuilds the server does on config reload.

## Console & API

The operator console's **Goals** tab (top of the Agents stack) lists active and
past goals and can clear an active one. On the chat-first (handheld/Deck) shell a
goal set in a chat tab surfaces there as a **drive** — the tab shows its
condition, iteration, and verifier, with **Detach** / **Stop**, and the Goals
surface can **Attach** to a drive it isn't already showing.

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/goals` | `{enabled, goals[]}` across sessions |
| `DELETE` | `/api/goal/{session_id}` | clear a session's goal |
| `POST` | `/api/goal/{session_id}/detach` | hand the drive to the scheduler → keeps iterating **headless** |
| `GET` | `/api/chat/{session_id}/history` | the session's durable transcript (used to **attach** to a drive) |

These are auth-gated. Runtime status (`/api/runtime/status`) reports
`goal.{enabled, controller_loaded, max_iterations, no_progress_limit}`.

### Headless drives (detach / attach)

A goal only advances while a turn runs on its session, so a drive normally needs
a console (or a caller) holding the stream. **Detach** removes that requirement:
it enqueues a one-shot scheduler job on the same session (`context_id`), which
fires back through the agent's own A2A endpoint with `origin="scheduler"`, runs
the goal loop to a verdict server-side, and pushes the result over the
`chat.resumed` event — so a console that re-**attaches** to the session sees the
turn land live. Clearing a goal also cancels any pending detached continuation.

> **Ops note:** a headless drive keeps running only while the host is awake. On a
> Steam Deck, that means [suspend must be disabled](../guides/deploy-updates.md)
> or the drive stalls when the device sleeps.

## Extending — adding a verifier

Verifiers live in `graph/goals/verifiers.py`. To add one:

1. Write `async def _verify_<name>(spec: dict, ctx: VerifyContext) -> VerifyResult`.
   Read existing stores only (lazy-import the accessor, e.g. `get_target_store`,
   `get_beads_handle`, `get_engagement_manager`) — **no shell, no host execution**.
2. Set `reason == evidence` to a value that changes as progress is made, so the
   controller's no-progress streak resets on advancement (see the existing ones).
3. Register it in the `VERIFIERS` map.
4. Optionally surface it in the `set_goal` tool args + this table.

That's the whole contract — the controller, store, loop, and UI are
verifier-agnostic.
