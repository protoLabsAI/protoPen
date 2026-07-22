"""Drives — detaching a goal's drive loop from the console that started it.

A **drive** is an active goal bound to a chat session: the agent loops toward the
goal's verifier, one turn per iteration, on that session's thread. Today those
iterations are pumped by whoever holds the stream — the console tab that sent the
message. Close the tab and the drive stalls with the goal still set, which reads
as "the agent quietly gave up".

Detaching fixes that without teaching the goal engine to self-pump: enqueue a
one-shot scheduler job on the same session. The scheduler POSTs it back through
the agent's own A2A endpoint with ``origin="scheduler"``, so the turn (a) runs the
goal loop to a verdict server-side, and (b) pushes its answer over ``chat.resumed``
— a console that re-attaches to the session sees it land live (protopen-1hw.11).

See docs/plans/2026-07-22-chat-first-deck-ui.md (P2).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

# How far out the continuation job is scheduled. Long enough for the console's
# aborted stream to unwind (and release the per-thread turn lock), short enough
# that "detach" feels immediate.
DETACH_DELAY_S = 10

# What the detached drive is woken with. Deliberately content-free: the goal's own
# continuation prompt (built by the controller after the first evaluation) carries
# the objective, constraints, and progress.
DETACH_PROMPT = "Continue working autonomously toward your active goal. Report what you did and what you found."


def job_id_for(session_id: str) -> str:
    """Deterministic job id for a session's detached drive — so a second detach
    replaces the pending job instead of stacking one (add_job rejects a dup id)."""
    return f"goal-drive-{re.sub(r'[^A-Za-z0-9_.-]', '_', session_id or '')[:64]}"


def detach_drive(controller: Any, scheduler: Any, session_id: str) -> dict[str, Any]:
    """Hand this session's drive to the scheduler. Returns the console payload.

    No active goal → ``{"detached": False}`` with a reason rather than an error:
    the operator closing a plain chat tab is the common case, not a fault.
    """
    if controller is None:
        raise RuntimeError("goal mode is not loaded")
    goal = controller.active_goal(session_id)
    if goal is None:
        return {"detached": False, "reason": "no active goal for this session"}

    job_id = job_id_for(session_id)
    scheduler.cancel_job(job_id)  # replace any detach still pending for this session
    fire_at = (datetime.now(UTC) + timedelta(seconds=DETACH_DELAY_S)).isoformat()
    job = scheduler.add_job(DETACH_PROMPT, fire_at, job_id=job_id, context_id=session_id)
    return {"detached": True, "job": job.as_dict(), "condition": goal.condition}


def cancel_detach(scheduler: Any, session_id: str) -> bool:
    """Drop a session's pending continuation job. MUST run whenever the goal is
    cleared: otherwise the job outlives the goal and fires "continue toward your
    active goal" at an agent that no longer has one — a stray autonomous turn on
    a session the operator thought they'd stopped."""
    if scheduler is None:
        return False
    return bool(scheduler.cancel_job(job_id_for(session_id)))
