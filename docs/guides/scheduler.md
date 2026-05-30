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
