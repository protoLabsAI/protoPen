# Scheduler

protoPen runs a **local scheduler** — a bundled sqlite + asyncio backend that
fires scheduled prompts at the agent's own `/a2a` endpoint. It's the only
scheduler backend (protoPen is intentionally local-only; there's no remote
Workstacean backend as in protoAgent).

## How it works

- Jobs live in a sqlite database under `/sandbox/scheduler/<agent_name>/jobs.db`,
  namespaced by `AGENT_NAME` so two instances sharing a path can't cross-fire.
- A polling coroutine starts on the server's startup hook and ticks once a
  second; due jobs fire via an HTTP `message/send` to `/a2a` (same audit/auth
  path as any real caller).
- A **cron** schedule (5-field, e.g. `0 9 * * 1-5`) reschedules after each fire.
  An **ISO-8601 datetime** (e.g. `2026-06-15T14:00:00+00:00`) is a one-shot —
  deleted after it fires.
- On startup, jobs whose `next_fire` is in the past but within 24h fire
  immediately (missed-fire recovery); older misses are rescheduled forward
  without firing.

The runtime status reports `scheduler.backend: "local"` when it's active.

## The agent schedules its own jobs

The agent has three tools bound to the live scheduler, so it can schedule work
mid-conversation (and a scheduled prompt that fires can schedule follow-ups):

| Tool | Description |
|---|---|
| `schedule_task(prompt, when, job_id?)` | Persist a future invocation. `when` is cron (`"0 9 * * 1-5"`) or ISO-8601 (`"2026-05-01T15:00:00"`). The agent receives `prompt` as a fresh turn when it fires. |
| `list_schedules()` | List current jobs (id · next fire · schedule · prompt preview). |
| `cancel_schedule(job_id)` | Cancel a job by id. |

E.g. "every weekday at 9am, summarize new critical CVEs and post to Discord" →
the agent calls `schedule_task("summarize new critical CVEs…", "0 9 * * 1-5")`.

## Managing jobs from the console

The operator console's **Schedule** surface lists jobs (schedule · next fire ·
prompt), lets you create one (a prompt plus a cron-or-ISO `when`), and cancel
any job. It loads on open and after each change.

## API

See the [Operator Console API](../reference/api-endpoints.md#operator-console-api):

| Method / Path | Description |
|---|---|
| `GET /api/scheduler/jobs` | List jobs + the active `backend`. |
| `POST /api/scheduler/jobs` | Create a job — `{prompt, schedule, job_id?}`. Malformed `schedule` → `400`. |
| `DELETE /api/scheduler/jobs/{id}` | Cancel a job → `{canceled: bool}`. |

When no scheduler is wired, the routes return an empty list / `409` rather than
erroring.
