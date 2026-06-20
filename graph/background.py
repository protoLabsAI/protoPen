"""Background subagents + reactive notification (ADR 0050 Phase 1, protopen-1hw.4).

The lead agent calls ``task(run_in_background=True)`` to delegate long work without
blocking its own turn: the subagent runs as a detached asyncio task, the call
returns immediately with a job id, and the result is folded back into the
*originating* conversation's NEXT turn as a ``<task-notification>`` — so the agent
is told "done" instead of polling (which burns the recursion budget).

This is protoPen's in-process adaptation of ADR 0050: jobs live in memory (lost on
restart — the underlying artifact, e.g. a scan file, persists and can be
re-analyzed), and the Phase-2 "autonomous wake" is an event-bus publish rather
than the inbox protoPen dropped for its tight security profile. On completion the
manager publishes ``background.completed`` so a console can react; the durable
self-POST/A2A variant is a possible future enhancement.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from time import time
from typing import Any, Awaitable, Callable

log = logging.getLogger(__name__)


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

    def set_event_bus(self, bus) -> None:
        self._bus = bus

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
