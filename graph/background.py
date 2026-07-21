"""Background subagents + reactive notification (ADR 0050 Phase 1, protopen-1hw.4).

The lead agent calls ``task(run_in_background=True)`` to delegate long work without
blocking its own turn: the subagent runs as a detached asyncio task, the call
returns immediately with a job id, and the result is folded back into the
*originating* conversation's NEXT turn as a ``<task-notification>`` — so the agent
is told "done" instead of polling (which burns the recursion budget).

This is protoPen's in-process adaptation of ADR 0050. Jobs live in memory (lost on
restart), but ADR 0070 (h34.9) fills that durability gap two ways on completion:

1. PUSH delivery — a terminal job schedules a self-A2A "briefing" wake into the
   origin session (via the local scheduler) so the agent proactively briefs the
   operator instead of only folding results into the session's *next* organic turn.
   A fan-out of near-simultaneous completions coalesces into ONE wake (stable job
   id + debounce); that briefing turn drains ALL pending notifications at once.
   Gated by ``background.auto_resume`` (default on).
2. DURABILITY — a completed job's full result is indexed into the KB keyed to the
   origin session, so it stays durable/searchable even though the in-memory job row
   is volatile (full job-row persistence is a separate follow-up). Trust-tier
   tagging lands with the KB trust-tier migration (h34.13); until then the
   ``background_job`` source_type marks its provenance.

The event-bus ``background.completed`` publish is retained so a console can react.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from time import time
from typing import Any, Awaitable, Callable

log = logging.getLogger(__name__)

# Coalesce a burst of near-simultaneous completions (a fan-out) into a single
# briefing wake: a short debounce plus a stable per-session wake id (#1766).
_BRIEFING_DEBOUNCE_S = 3

_BRIEFING_PROMPT = (
    "A background job you delegated has finished. Its result may be attached above as a "
    "<task-notification>. Review what came back, brief the operator concisely on the outcome "
    "and any recommended next step, and act on it if warranted. If it was already handled, "
    "just acknowledge briefly."
)


@dataclass
class BackgroundJob:
    id: str
    subagent_type: str
    description: str
    origin_session: str
    status: str = "running"  # running | completed | failed
    result: str | None = None
    error: str | None = None
    notified: bool = False
    created_at: float = field(default_factory=time)
    finished_at: float | None = None


class BackgroundManager:
    def __init__(self, *, event_bus=None):
        self._jobs: dict[str, BackgroundJob] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._bus = event_bus
        self._scheduler = None
        self._knowledge = None
        self._auto_resume = True

    def set_event_bus(self, bus) -> None:
        self._bus = bus

    def set_scheduler(self, scheduler) -> None:
        """Wire the local scheduler used to self-A2A-wake the origin session (ADR 0070)."""
        self._scheduler = scheduler

    def set_knowledge_store(self, store) -> None:
        """Wire the KB the completed result is indexed into for durability (ADR 0070)."""
        self._knowledge = store

    def set_auto_resume(self, enabled: bool) -> None:
        """Toggle the push briefing wake; KB indexing still happens either way."""
        self._auto_resume = bool(enabled)

    def spawn(
        self,
        factory: Callable[[], Awaitable[str]],
        *,
        origin_session: str,
        subagent_type: str,
        description: str,
    ) -> str:
        """Start a detached subagent run; return its job id immediately."""
        job_id = f"bg-{uuid.uuid4().hex[:12]}"
        self._jobs[job_id] = BackgroundJob(
            id=job_id,
            subagent_type=subagent_type,
            description=description,
            origin_session=origin_session or "",
        )
        self._tasks[job_id] = asyncio.create_task(self._run(job_id, factory), name=f"bg.{job_id}")
        return job_id

    async def _run(self, job_id: str, factory: Callable[[], Awaitable[str]]) -> None:
        job = self._jobs[job_id]
        try:
            job.result = await factory()
            job.status = "completed"
        except asyncio.CancelledError:
            job.status = "failed"
            job.error = "cancelled"
            raise
        except Exception as exc:  # noqa: BLE001
            job.status = "failed"
            job.error = str(exc)
            log.exception("[background] job %s failed", job_id)
        finally:
            job.finished_at = time()
            self._tasks.pop(job_id, None)
            self._announce(job)
            # Durability + push (ADR 0070). Skip on cancellation — the loop is
            # unwinding and must not await new work while propagating CancelledError.
            if not (job.status == "failed" and job.error == "cancelled"):
                await self._on_complete(job)

    async def _on_complete(self, job: BackgroundJob) -> None:
        """Index the result for durability and push a coalesced briefing wake."""
        await self._index_to_kb(job)
        await self._schedule_briefing(job)

    async def _index_to_kb(self, job: BackgroundJob) -> None:
        """Store a completed job's full result in the KB, keyed to its origin session."""
        if self._knowledge is None or job.status != "completed":
            return
        content = (job.result or "").strip()
        if not content:
            return
        try:
            await asyncio.to_thread(
                self._knowledge.add_fact,
                content,
                job.origin_session or None,  # namespace = origin session
                f"background:{job.id}",  # source
                "background_job",  # source_type (provenance; trust tier comes with h34.13)
            )
        except Exception:  # noqa: BLE001 — durability is best-effort, never break the job
            log.exception("[background] KB index failed for %s", job.id)

    async def _schedule_briefing(self, job: BackgroundJob) -> None:
        """Schedule a self-A2A wake so the agent briefs the operator on the result.

        One pending wake per session: a stable ``bg-wake:{session}`` job id means a
        fan-out of near-simultaneous completions supersedes into a SINGLE wake, and
        the briefing turn drains every pending notification at once (#1766).
        """
        if not self._auto_resume or self._scheduler is None:
            return
        session = job.origin_session or ""
        if not session:
            return
        wake_id = f"bg-wake:{session}"
        fire_at = (datetime.now(UTC) + timedelta(seconds=_BRIEFING_DEBOUNCE_S)).isoformat()
        try:
            await asyncio.to_thread(self._scheduler.cancel_job, wake_id)
        except Exception:  # noqa: BLE001 — a stale/absent prior wake must not block the new one
            pass
        try:
            await asyncio.to_thread(
                self._scheduler.add_job,
                _BRIEFING_PROMPT,
                fire_at,
                job_id=wake_id,
                context_id=session,
            )
        except Exception:  # noqa: BLE001 — push is best-effort; the pull-drain still delivers
            log.exception("[background] briefing wake schedule failed for %s", job.id)

    def _announce(self, job: BackgroundJob) -> None:
        if self._bus is None:
            return
        try:
            self._bus.publish(
                "background.completed",
                {
                    "job_id": job.id,
                    "subagent_type": job.subagent_type,
                    "description": job.description,
                    "status": job.status,
                    "origin_session": job.origin_session,
                },
            )
        except Exception:  # noqa: BLE001
            log.exception("[background] failed to publish completion for %s", job.id)

    def drain_notifications(self, origin_session: str) -> list[BackgroundJob]:
        """Completed/failed jobs for this session not yet reported. Marks them notified."""
        out: list[BackgroundJob] = []
        for job in self._jobs.values():
            if (
                job.origin_session == (origin_session or "")
                and job.status in ("completed", "failed")
                and not job.notified
            ):
                job.notified = True
                out.append(job)
        return out

    def get(self, job_id: str) -> BackgroundJob | None:
        return self._jobs.get(job_id)

    def status(self) -> list[dict[str, Any]]:
        return [
            {
                "id": j.id,
                "subagent_type": j.subagent_type,
                "description": j.description,
                "status": j.status,
                "origin_session": j.origin_session,
            }
            for j in self._jobs.values()
        ]


def render_task_notifications(jobs: list[BackgroundJob]) -> str:
    """Format completed background jobs as a <task-notification> block to prepend."""
    if not jobs:
        return ""
    lines = ["<task-notification>"]
    for j in jobs:
        if j.status == "completed":
            body = (j.result or "").strip() or "(no output)"
            lines.append(f"[{j.id} · {j.subagent_type} done] {j.description}\n{body}")
        else:
            lines.append(f"[{j.id} · {j.subagent_type} FAILED] {j.description}: {j.error or 'unknown error'}")
    lines.append("</task-notification>")
    return "\n".join(lines)


# Process-wide singleton — the task tool spawns into it; the chat path drains it.
_MANAGER = BackgroundManager()


def get_background_manager() -> BackgroundManager:
    return _MANAGER
