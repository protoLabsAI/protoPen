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

### Drive vs. monitor goals

- **Drive** goals (the default) progress through the agent's own turns.
- **Monitor** goals (`mode: "monitor"`) track a metric moved by an *external*
  process — they're evaluated **out of band on a cadence with no agent turn**, and
  only fire their hooks when the condition is met. The cadence is the
  `goals.monitor_interval_s` config (default 60s; `≤0` disables it). This lets a
  long-horizon objective progress even when nothing is actively chatting.

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
**`task(run_in_background=True)`**: the sub-agent runs detached, the call returns a
job id immediately, and the result is folded into the *originating conversation's
next turn* as a `<task-notification>` — the agent is told "done" instead of
polling. The agent should never re-poll or spawn a duplicate. (Notifications are
delivered exactly once.)

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

A typical self-driving run: set a **goal** → work toward it, delegating long scans
as **background sub-agents** and **`wait`**-ing on slow steps instead of polling →
the operator **steers** when scope shifts → a scheduled **`/dream`** keeps memory
clean → the **monitor-goal** cadence (or `on_achieved` hook) closes the loop when
the objective is met. Everything stays inside the engagement's mode and scope (see
[Security Model](/explanation/security-model)).
