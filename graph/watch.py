"""WatchManager — N concurrent condition-watches (ADR 0067, h34.7).

Supersedes the monitor-goal ticker (ADR 0030). A *watch* polls a condition on its
OWN cadence and, when it trips, runs a follow-up turn in the origin session (via the
local scheduler's self-A2A path) so the agent reacts — many watches per instance,
each with its own ``interval_s`` / ``deadline_s`` / ``stall_after_s``. It reuses the
safe verifier set (findings / targets / task / llm), so a watch can never run shell
or ``eval`` — the same no-code-exec guarantee goal mode has.

Per-watch cadence is the #1753 fix: the retired ticker evaluated *every* monitor goal
on one global interval, which fired spurious "stalled" reactions overnight. Here each
watch carries its own ``next_check_at`` and is evaluated only when it is due.

Watches are one-shot: a trip fires its reaction and stops re-checking. They live in
memory (like the background manager) — operational supervision that doesn't need to
survive a restart; durable long-horizon objectives are drive goals.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import time

from graph.goals.verifiers import VerifyContext, run_verifier

log = logging.getLogger(__name__)

_STALL_PROMPT = (
    "A watch you set has not tripped within its stall window: {condition!r}. It may be "
    "stuck, or the expected event isn't coming — reassess and decide whether to keep "
    "waiting (set a fresh watch), change approach, or drop it."
)


@dataclass
class Watch:
    """A single condition-watch. ``verifier`` is a spec dict (same shape as a goal's:
    ``{"type": "findings", "severity": "critical", "min": 1}``); the watch tool
    validates its type against ``AGENT_SAFE_VERIFIERS`` before it ever reaches here."""

    id: str
    session_id: str  # origin session — where on_trip runs
    condition: str
    on_trip: str  # self-contained instruction to run when the condition trips
    verifier: dict = field(default_factory=lambda: {"type": "llm"})
    interval_s: float = 60.0
    deadline_s: float | None = None  # absolute lifetime; expire (silently) if not tripped
    stall_after_s: float | None = None  # fire a "stalled" reaction if no trip within this
    status: str = "active"  # active | tripped | expired | stalled | cancelled
    created_at: float = field(default_factory=time)
    next_check_at: float = 0.0
    last_checked_at: float | None = None
    tripped_at: float | None = None
    checks: int = 0
    last_reason: str = ""

    @property
    def active(self) -> bool:
        return self.status == "active"

    def summary(self) -> dict:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "condition": self.condition,
            "verifier": self.verifier.get("type", "llm"),
            "interval_s": self.interval_s,
            "status": self.status,
            "checks": self.checks,
            "last_reason": self.last_reason,
        }


class WatchManager:
    def __init__(self, *, config=None, event_bus=None, poll_interval_s: float = 5.0):
        self._watches: dict[str, Watch] = {}
        self._config = config
        self._bus = event_bus
        self._scheduler = None
        self._poll = float(poll_interval_s)
        self._task: asyncio.Task | None = None
        self._stopping = False

    def set_config(self, config) -> None:
        self._config = config

    def set_event_bus(self, bus) -> None:
        self._bus = bus

    def set_scheduler(self, scheduler) -> None:
        """Wire the local scheduler used to run the follow-up turn on a trip."""
        self._scheduler = scheduler

    def set_poll_interval_s(self, seconds: float) -> None:
        """How often the loop wakes to evaluate due watches (not the per-watch cadence)."""
        self._poll = max(1.0, float(seconds))

    # ── control surface ──────────────────────────────────────────────────────

    def add_watch(
        self,
        *,
        session_id: str,
        condition: str,
        on_trip: str,
        verifier: dict | None = None,
        interval_s: float = 60.0,
        deadline_s: float | None = None,
        stall_after_s: float | None = None,
    ) -> Watch:
        interval = max(1.0, float(interval_s or 60.0))
        w = Watch(
            id=f"watch-{uuid.uuid4().hex[:12]}",
            session_id=session_id or "",
            condition=condition,
            on_trip=on_trip,
            verifier=dict(verifier) if verifier else {"type": "llm"},
            interval_s=interval,
            deadline_s=float(deadline_s) if deadline_s else None,
            stall_after_s=float(stall_after_s) if stall_after_s else None,
            next_check_at=time() + interval,  # first check after one interval, not immediately
        )
        self._watches[w.id] = w
        return w

    def cancel_watch(self, watch_id: str) -> bool:
        w = self._watches.get(watch_id)
        if w and w.active:
            w.status = "cancelled"
            return True
        return False

    def list_watches(self, session_id: str | None = None) -> list[Watch]:
        return [w for w in self._watches.values() if session_id is None or w.session_id == session_id]

    def get(self, watch_id: str) -> Watch | None:
        return self._watches.get(watch_id)

    # ── poll loop ────────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopping = False
        self._task = asyncio.create_task(self._loop(), name="watch.manager")
        log.info("[watch] manager started (poll every %.0fs)", self._poll)

    async def stop(self) -> None:
        self._stopping = True
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001
            log.exception("[watch] manager raised during stop")
        self._task = None

    async def _loop(self) -> None:
        while not self._stopping:
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("[watch] tick failed")
            try:
                await asyncio.sleep(self._poll)
            except asyncio.CancelledError:
                return

    async def tick(self) -> list[str]:
        """Evaluate every DUE watch once. Returns the ids that tripped this tick.

        Each watch's cadence, deadline, and stall window are anchored to that watch's
        own ``created_at`` / ``next_check_at`` — never a shared global tick (#1753).
        """
        tripped: list[str] = []
        now = time()
        for w in list(self._watches.values()):
            if not w.active:
                continue
            # Lifetime bounds take precedence over a due check.
            if w.deadline_s is not None and now - w.created_at >= w.deadline_s:
                w.status = "expired"
                self._publish("watch.expired", w)
                continue
            if w.stall_after_s is not None and now - w.created_at >= w.stall_after_s:
                w.status = "stalled"
                self._publish("watch.stalled", w)
                await self._fire(w.session_id, _STALL_PROMPT.format(condition=w.condition))
                continue
            if now < w.next_check_at:
                continue

            w.checks += 1
            w.last_checked_at = now
            w.next_check_at = now + w.interval_s
            try:
                ctx = VerifyContext(config=self._config, condition=w.condition, last_text="", tool_summary="")
                result = await run_verifier(w.verifier, ctx)
            except Exception:  # noqa: BLE001 — a flaky verifier must not kill the loop
                log.exception("[watch] verifier failed for %s", w.id)
                continue
            w.last_reason = result.reason
            if result.met:
                w.status = "tripped"
                w.tripped_at = now
                tripped.append(w.id)
                self._publish("watch.tripped", w)
                await self._fire(w.session_id, w.on_trip)
        return tripped

    async def _fire(self, session: str, prompt: str) -> None:
        """Run a follow-up turn in the origin session via the scheduler self-A2A path."""
        if self._scheduler is None or not session or not prompt:
            return
        fire_at = datetime.now(UTC).isoformat()
        try:
            await asyncio.to_thread(self._scheduler.add_job, prompt, fire_at, job_id=None, context_id=session)
        except Exception:  # noqa: BLE001 — reaction delivery is best-effort
            log.exception("[watch] could not schedule follow-up turn for session %s", session)

    def _publish(self, event: str, w: Watch) -> None:
        log.info("[watch] %s (%s) %s", event, w.id, w.condition)
        if self._bus is None:
            return
        try:
            self._bus.publish(
                event,
                {
                    "watch_id": w.id,
                    "session_id": w.session_id,
                    "condition": w.condition,
                    "status": w.status,
                    "reason": w.last_reason,
                },
            )
        except Exception:  # noqa: BLE001
            log.exception("[watch] publish failed for %s", w.id)


# Process-wide singleton — the watch tool creates into it; the server starts its loop.
_MANAGER = WatchManager()


def get_watch_manager() -> WatchManager:
    return _MANAGER
