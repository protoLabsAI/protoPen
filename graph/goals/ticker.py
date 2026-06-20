"""MonitorGoalTicker — out-of-band evaluation of monitor goals (ADR 0030 D2.1).

A *monitor* goal's metric is moved by an external process, not the agent's own
turns. The drive-mode loop re-checks after each turn; a monitor goal would only
be re-evaluated when some unrelated turn happens to run the goal loop — so a
long-horizon objective could sit unchecked indefinitely while fully autonomous.

This ticker closes that gap: on a cadence (default 60s) it runs each active
monitor goal's verifier with NO agent turn. ``GoalController.evaluate`` transitions
the goal to ``achieved`` when the verifier passes (verifiers read live state —
engagement findings, target counts — not the turn transcript, so an empty
``last_text`` is correct here). On achievement it announces via the event bus and
the Activity thread so the operator/console sees it.
"""

from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)


class MonitorGoalTicker:
    def __init__(self, controller, *, interval_s: float = 60.0, event_bus=None):
        self._controller = controller
        self._interval = float(interval_s)
        self._bus = event_bus
        self._task: asyncio.Task | None = None
        self._stopping = False

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopping = False
        self._task = asyncio.create_task(self._loop(), name="goals.monitor.ticker")
        log.info("[goals] monitor-goal ticker started (every %.0fs)", self._interval)

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
            log.exception("[goals] monitor ticker raised during stop")
        self._task = None

    async def _loop(self) -> None:
        while not self._stopping:
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("[goals] monitor tick failed")
            try:
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                return

    async def tick(self) -> list[str]:
        """Evaluate every active monitor goal once. Returns achieved session ids."""
        achieved: list[str] = []
        try:
            states = self._controller.store.all()
        except Exception:  # noqa: BLE001
            log.exception("[goals] could not list goals for monitor tick")
            return achieved
        for state in states:
            if not getattr(state, "active", False) or getattr(state, "mode", "drive") != "monitor":
                continue
            decision = await self._controller.evaluate(state.session_id, last_text="")
            if decision is not None and decision.action == "done":
                achieved.append(state.session_id)
                self._announce(state, decision)
        return achieved

    def _announce(self, state, decision) -> None:
        # decision.state is the post-evaluate state (evaluate's _finish already
        # transitioned status to achieved/exhausted and persisted it).
        gs = getattr(decision, "state", None) or state
        log.info("[goals] monitor goal (%s) %s", gs.session_id, decision.note)
        if self._bus is None:
            return
        try:
            self._bus.publish(
                "goal.achieved",
                {
                    "session_id": gs.session_id,
                    "status": gs.status,
                    "condition": gs.condition,
                    "note": decision.note,
                },
            )
            # Also surface it in the Activity thread so a console sees it live.
            self._bus.publish(
                "activity.message",
                {"role": "system", "text": f"Monitor {decision.note}", "context_id": "system:activity"},
            )
        except Exception:  # noqa: BLE001
            log.exception("[goals] failed to publish monitor-goal achievement")
