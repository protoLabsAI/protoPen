"""Cancellable in-flight delegations (protopen-1hw.12).

A per-tool-call registry of running foreground ``task`` delegations so the operator
can cancel ONE subagent run mid-turn without killing the whole turn (the Tier-2
control of the steer/approve loop). The task tool registers its run here keyed by
the LangGraph tool-call id; the cancel endpoint cancels that asyncio.Task and flags
it user-initiated, so the tool body returns a graceful "cancelled" string instead
of propagating CancelledError (a parent-turn cancel, which is NOT flagged here, is
re-raised as normal).

Both the tool body and the cancel endpoint run on the same asyncio event loop, so a
plain dict needs no lock.
"""

from __future__ import annotations

import asyncio

_TASKS: dict[str, asyncio.Task] = {}
_CANCELLED: set[str] = set()
_META: dict[str, dict] = {}


def register(
    tool_call_id: str, task: asyncio.Task, *, session_id: str = "", subagent_type: str = "", description: str = ""
) -> None:
    if not tool_call_id:
        return
    _TASKS[tool_call_id] = task
    _META[tool_call_id] = {
        "session_id": session_id,
        "subagent_type": subagent_type,
        "description": description,
    }


def unregister(tool_call_id: str) -> None:
    _TASKS.pop(tool_call_id, None)
    _META.pop(tool_call_id, None)
    _CANCELLED.discard(tool_call_id)


def cancel(tool_call_id: str) -> bool:
    """Cancel one running delegation (operator-initiated). Returns True if a live
    task was cancelled."""
    task = _TASKS.get(tool_call_id)
    if task is None or task.done():
        return False
    _CANCELLED.add(tool_call_id)
    task.cancel()
    return True


def was_cancelled(tool_call_id: str) -> bool:
    """True if this delegation was cancelled via :func:`cancel` (operator), vs a
    parent-turn cancel that the tool body should re-raise."""
    return tool_call_id in _CANCELLED


def pending(session_id: str | None = None) -> list[dict]:
    """Live delegations, optionally scoped to a session."""
    out = []
    for tcid, meta in _META.items():
        task = _TASKS.get(tcid)
        if task is None or task.done():
            continue
        if session_id is not None and meta.get("session_id") != session_id:
            continue
        out.append({"tool_call_id": tcid, **meta})
    return out
