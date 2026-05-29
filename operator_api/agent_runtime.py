"""In-process registry for manually launched subagents.

protoPen's ``run_manual_subagent`` is fire-and-await — once launched there's no
handle, status, or cancel. This registry wraps a launch coroutine in an
``asyncio.Task`` on the running loop, tracks its lifecycle, and exposes UI-safe
snapshots plus cancellation so the operator console can monitor and stop work.

Process-local (single-server assumption). Completed tasks are retained up to
``max_history`` so the console can show recent output, then the oldest finished
entries are pruned.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

# Terminal states — these can be pruned once history is full.
_DONE_STATES = {"done", "error", "cancelled"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _AgentRun:
    __slots__ = (
        "id",
        "type",
        "description",
        "status",
        "started_at",
        "ended_at",
        "output",
        "error",
        "task",
    )

    def __init__(self, run_id: str, agent_type: str, description: str) -> None:
        self.id = run_id
        self.type = agent_type
        self.description = description
        self.status = "running"
        self.started_at = _now()
        self.ended_at: str = ""
        self.output: str = ""
        self.error: str = ""
        self.task: asyncio.Task | None = None

    def snapshot(self) -> dict[str, Any]:
        """UI-safe view — never exposes the asyncio.Task handle."""
        duration_ms = 0
        if self.ended_at:
            try:
                start = datetime.fromisoformat(self.started_at)
                end = datetime.fromisoformat(self.ended_at)
                duration_ms = int((end - start).total_seconds() * 1000)
            except ValueError:
                duration_ms = 0
        return {
            "id": self.id,
            "type": self.type,
            "description": self.description,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": duration_ms,
            "output": self.output,
            "error": self.error,
        }


class AgentRegistry:
    """Tracks manually launched subagent runs and supports cancellation."""

    def __init__(self, max_history: int = 50) -> None:
        self._runs: dict[str, _AgentRun] = {}
        self._order: list[str] = []  # insertion order, for pruning + listing
        self._max_history = max_history

    def launch(
        self,
        factory: Callable[[], Awaitable[str]],
        *,
        agent_type: str,
        description: str,
    ) -> str:
        """Schedule ``factory()`` as a tracked background task; return its id.

        Must be called from within the running event loop (FastAPI request
        handlers satisfy this).
        """
        run_id = uuid.uuid4().hex[:12]
        run = _AgentRun(run_id, agent_type, description or "(no description)")
        self._runs[run_id] = run
        self._order.append(run_id)
        self._prune()

        run.task = asyncio.create_task(self._supervise(run, factory))
        return run_id

    async def _supervise(self, run: _AgentRun, factory: Callable[[], Awaitable[str]]) -> None:
        try:
            run.output = await factory()
            run.status = "done"
        except asyncio.CancelledError:
            run.status = "cancelled"
            run.ended_at = _now()
            raise  # propagate so the task is properly marked cancelled
        except Exception as exc:  # noqa: BLE001 — surface any failure to the UI
            run.status = "error"
            run.error = str(exc)
        finally:
            if not run.ended_at:
                run.ended_at = _now()

    def cancel(self, run_id: str) -> bool:
        run = self._runs.get(run_id)
        if run is None or run.task is None or run.status != "running":
            return False
        return run.task.cancel()

    def get(self, run_id: str) -> dict[str, Any] | None:
        run = self._runs.get(run_id)
        return run.snapshot() if run else None

    def snapshot(self) -> list[dict[str, Any]]:
        """All tracked runs, newest first."""
        return [self._runs[rid].snapshot() for rid in reversed(self._order) if rid in self._runs]

    def _prune(self) -> None:
        """Drop the oldest finished runs once over the history cap."""
        while len(self._order) > self._max_history:
            for idx, rid in enumerate(self._order):
                run = self._runs.get(rid)
                if run is None or run.status in _DONE_STATES:
                    self._order.pop(idx)
                    self._runs.pop(rid, None)
                    break
            else:
                # No finished run to evict (all still running) — stop pruning.
                break


# Process-wide registry shared by the operator routes.
agent_registry = AgentRegistry()
