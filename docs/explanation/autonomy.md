# Autonomy & Self-Driving

protoPen is built to run an engagement **unattended** — to keep working toward an
objective across many turns, pause without burning its budget, delegate long work
in the background, and clean up after itself — while staying inside the rules of
engagement. This page explains the self-driving primitives and how they fit
together. For the day-to-day controls see [Goals](/reference/goals),
[Chat Commands](/reference/chat-commands), and the
[Control Stack](/explanation/control-stack).

## Goals — knowing when to stop

A **goal** is a finish line plus a verifier. Set one with the `set_goal` tool or
the `/goal` command; after each turn the verifier decides whether the goal is met,
and if not the agent is re-invoked on the same thread with a continuation prompt —
until the verifier passes, the iteration budget runs out, or the agent flags it
unachievable.

Verifiers are **read-only / LLM-judge only** (`findings`, `targets`, `task`,
`llm`) — never shell or `eval` — so goal mode can't be used to smuggle code
execution past the engagement gates. See [Goals](/reference/goals).

A goal drives toward a finish line through the agent's own turns. For supervising a
condition that some *external* process moves — a scan finishing, a host coming online
— use a **watch** (below) rather than a goal.

## watch — supervise a condition in parallel

A **watch** polls a condition on its own cadence and, when it **trips**, runs a
follow-up turn in the same session so the agent reacts. Set one with the `watch` tool;
run many at once, each with its own interval and reaction:

```
watch(condition="the nmap scan finished", on_trip="analyze /sandbox/scan.txt and log findings", interval_s=60)
```

Watches reuse the same read-only verifier set as goals (`findings`, `targets`, `task`,
`llm`) — never shell or `eval`. Each carries its own `interval_s` (how often to check),
optional `deadline_s` (expire quietly if it never trips), and `stall_after_s` (wake you
to reassess if it hasn't tripped in time). A watch is one-shot: it fires its reaction
once, then stops. `list_watches` / `cancel_watch` manage them. The manager is enabled by
`watch.enabled` and polls every `watch.poll_interval_s` seconds, evaluating each watch
only when *its own* cadence is due.

Watches supersede the older monitor-goal mode: instead of one global cadence re-checking
every long-horizon goal, each watch runs on its own clock and drives its own reaction.

## working state — the OODA loop

So the agent can self-drive rather than lose track between turns, each turn is prefixed
with a **`<working_state>`** snapshot: the active goal and its plan, live watches, and
pending scheduled turns for this session — plus the operating doctrine (when work is
running out of band, *yield* to a watch/`wait` and end the turn; *resume* on the trip
and reorient from this block). It's injected only when there's live state, so idle turns
carry no extra tokens. Controlled by `watch.working_state` (default on).

## wait — yield instead of polling

When there's nothing to do until time passes (a scan is running, a payload needs
to land, a rate-limit window must elapse), the agent calls **`wait(seconds, then)`**.
The current turn **ends immediately** — it does not block — and the scheduler
re-invokes the agent later, **in the same conversation with history intact**, using
`then` as the new instruction. This is strictly better than looping/polling, which
burns the recursion budget.

```
wait(seconds=120, then="check whether the nmap scan in /tmp/scan.txt finished and analyze it")
```

## Background sub-agents — delegate without blocking

A foreground delegation blocks the turn. For long work, the agent calls
**`task(run_in_background=True)`**: the sub-agent runs detached and the call returns a
job id immediately. When the job finishes, two things happen (ADR 0070):

- **Push** — with `background.auto_resume` on (the default), a finished job schedules a
  self-briefing turn into its origin session, so the agent proactively briefs you rather
  than waiting for the session's next organic turn. A burst of jobs finishing together
  coalesces into a **single** briefing.
- **Durability** — the full result is indexed into the knowledge base keyed to the
  origin session, so it survives even though the in-memory job row does not.

The agent is told "done" instead of polling, and should never re-poll or spawn a
duplicate. (Notifications are delivered exactly once.)

## Mid-turn steering & cancellation

While a turn is streaming you can **steer** it without stopping it:

- `POST /api/chat/sessions/{id}/steer` queues a message that's folded into the run
  at the next model call; `DELETE …/steer/{msg_id}` cancels a still-pending steer.
- `POST /api/delegations/{tool_call_id}/cancel` aborts **one** in-flight sub-agent
  delegation without killing the whole turn (`GET /api/delegations` lists them).

Together these are the "steer" half of the operator's steer/approve loop.

## Memory hygiene — the dream pass

Facts accumulate across engagements, so stale, superseded, and duplicate ones pile
up and degrade recall. The **`dream`** sub-agent is a periodic
memory-consolidation pass: it inventories facts (`memory_list`), prunes the bad
ones **one id at a time** (`forget_memory`), and consolidates where it helps. It is
deliberately scoped — **no shell, no raw SQL** — so a consolidation pass can never
corrupt the store.

Run it on demand with **`/dream`**, or set a cadence with `goals.dream_cadence_cron`
(a 5-field cron; blank = off) to seed a recurring `/dream` job at startup.

## Resilience

Unattended operation needs to survive restarts and stalls:

- The **scheduler** takes a self-healing owner-lock (it retries rather than giving
  up, so a restart/redeploy never silently stops `wait`-resumes or scheduled jobs)
  and recovers missed fires on boot.
- `graph/sdk.py` ships a host-free **`Supervisor`** (a watchdog that re-kicks a
  crashed background loop and restarts a stalled one) plus a **`DecisionLog` /
  telemetry** envelope for provenance and a **`Knobs`** surface for bounded,
  reversible tuning. These are building blocks for long-running engine plugins.

## How it composes

A typical self-driving run: set a **goal** → work toward it, reorienting each turn from
the **`<working_state>`** block → delegate long scans as **background sub-agents** (which
**push** a briefing back when they finish) and **`wait`** on slow steps or set a
**watch** on a condition instead of polling → the operator **steers** when scope shifts →
a scheduled **`/dream`** keeps memory clean. Everything stays inside the engagement's mode
and scope (see [Security Model](/explanation/security-model)).
