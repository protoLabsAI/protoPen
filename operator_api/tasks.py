"""Read-only view of the durable A2A task store for the operator (#339).

The scheduler surface has ``/api/scheduler/jobs`` and subagent runs have
``/api/agents``, but the turns themselves — what the agent is working on right
now — had no operator surface at all. During the #337 runaway,
``/api/agents`` and ``/api/delegations`` both read empty while ~2,000 turns were
executing, because those track subagent runs and delegations rather than A2A
tasks. Establishing what was actually running meant reading the sqlite file over
ssh.

Two deliberate choices, both learned from that incident:

- **Read the sqlite file the SDK writes, not ``DatabaseTaskStore.list``.** The
  store's list filters by an owner resolved from a ``ServerCallContext`` the
  operator API has no natural value for, and an owner mismatch would return an
  empty list — precisely the "everything looks idle while it isn't" failure this
  endpoint exists to prevent. A forensics surface must not be able to quietly
  return nothing.
- **Always report the state histogram**, not just the page of rows. The runaway
  was legible in one number (2,030 tasks in ``TASK_STATE_WORKING``); a paginated
  list of the newest 100 would have hidden it.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Cap the page so a pathological store can't blow up a console request.
MAX_LIMIT = 500


def _db_path() -> str:
    from a2a_stores import resolve_task_db_path

    return resolve_task_db_path()


def list_tasks(
    limit: int = 100,
    state: str | None = None,
    context_id: str | None = None,
) -> dict[str, Any]:
    """Recent A2A tasks, newest first, plus a full count by state.

    ``state`` accepts either the wire form (``TASK_STATE_WORKING``) or the bare
    suffix (``working``) — an operator reaching for this in a hurry shouldn't
    have to remember which. Never raises: a missing or unreadable store returns
    an empty result with ``available: False`` rather than a 500, because this is
    the surface you reach for when things are already broken.
    """
    limit = max(1, min(int(limit or 100), MAX_LIMIT))
    path = _db_path()
    if not Path(path).exists():
        return {"tasks": [], "count": 0, "counts_by_state": {}, "db": path, "available": False}

    wanted = _normalize_state(state)
    try:
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        try:
            rows = db.execute("SELECT id, context_id, status, last_updated FROM tasks").fetchall()
        finally:
            db.close()
    except sqlite3.DatabaseError:
        log.exception("[tasks] could not read the A2A task store at %s", path)
        return {"tasks": [], "count": 0, "counts_by_state": {}, "db": path, "available": False}

    counts: dict[str, int] = {}
    matched: list[dict[str, Any]] = []
    for row in rows:
        task_state, timestamp = _read_status(row["status"])
        counts[task_state] = counts.get(task_state, 0) + 1
        if wanted and task_state != wanted:
            continue
        if context_id and row["context_id"] != context_id:
            continue
        matched.append(
            {
                "id": row["id"],
                "context_id": row["context_id"],
                "state": task_state,
                "status_timestamp": timestamp,
                "last_updated": row["last_updated"],
            }
        )

    # Newest first. The status timestamp is what moves when a task changes state
    # (last_updated can be NULL on older rows), so sort on it and fall back.
    matched.sort(key=lambda t: (t["status_timestamp"] or "", t["last_updated"] or ""), reverse=True)
    return {
        "tasks": matched[:limit],
        "count": len(matched),  # total matching the filter, not the page size
        "counts_by_state": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
        "db": path,
        "available": True,
    }


def _normalize_state(state: str | None) -> str | None:
    if not state or not state.strip():
        return None
    raw = state.strip().upper()
    return raw if raw.startswith("TASK_STATE_") else f"TASK_STATE_{raw}"


def _read_status(status: Any) -> tuple[str, str | None]:
    """Pull ``(state, timestamp)`` out of the store's JSON status column."""
    try:
        parsed = json.loads(status) if isinstance(status, str | bytes) else (status or {})
        if isinstance(parsed, dict):
            return str(parsed.get("state") or "UNKNOWN"), parsed.get("timestamp")
    except (ValueError, TypeError):
        pass
    return "UNKNOWN", None
