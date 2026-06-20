"""MonitorGoalTicker — out-of-band monitor-goal evaluation (ADR 0030 D2.1, protopen-2w0)."""

from __future__ import annotations

import asyncio

from graph.goals.controller import Decision
from graph.goals.ticker import MonitorGoalTicker
from graph.goals.types import GoalState


class _FakeStore:
    def __init__(self, states):
        self._states = states

    def all(self):
        return list(self._states)


class _FakeController:
    def __init__(self, states, results):
        self.store = _FakeStore(states)
        self._results = results  # session_id -> Decision | None
        self.evaluated: list[str] = []

    async def evaluate(self, session_id, *, last_text="", tool_summary=""):
        self.evaluated.append(session_id)
        return self._results.get(session_id)


class _FakeBus:
    def __init__(self):
        self.events = []

    def publish(self, event, data=None):
        self.events.append((event, data))


def _goal(session_id, *, mode="monitor", status="active"):
    return GoalState(session_id=session_id, condition="cond", mode=mode, status=status)


def test_tick_only_evaluates_active_monitor_goals():
    states = [
        _goal("mon-active"),
        _goal("drive-active", mode="drive"),
        _goal("mon-done", status="achieved"),  # inactive
    ]
    ctrl = _FakeController(states, results={})
    ticker = MonitorGoalTicker(ctrl, interval_s=999)
    achieved = asyncio.run(ticker.tick())
    assert ctrl.evaluated == ["mon-active"]  # only the active monitor goal
    assert achieved == []


def test_tick_announces_achieved_monitor_goal():
    # evaluate's _finish transitions the state to achieved before returning.
    decision = Decision(
        action="done", state=_goal("s1", status="achieved"), note="✓ goal achieved: 1 critical finding"
    )
    ctrl = _FakeController([_goal("s1")], results={"s1": decision})
    bus = _FakeBus()
    ticker = MonitorGoalTicker(ctrl, interval_s=999, event_bus=bus)
    achieved = asyncio.run(ticker.tick())
    assert achieved == ["s1"]
    kinds = [e for e, _ in bus.events]
    assert "goal.achieved" in kinds
    assert "activity.message" in kinds
    payload = dict(bus.events)["goal.achieved"]
    assert payload["session_id"] == "s1" and payload["status"] == "achieved"


def test_tick_not_met_does_not_announce():
    ctrl = _FakeController([_goal("s1")], results={"s1": None})
    bus = _FakeBus()
    ticker = MonitorGoalTicker(ctrl, interval_s=999, event_bus=bus)
    assert asyncio.run(ticker.tick()) == []
    assert bus.events == []


def test_start_stop_lifecycle():
    ctrl = _FakeController([], results={})

    async def scenario():
        t = MonitorGoalTicker(ctrl, interval_s=999)
        await t.start()
        running = t._task is not None and not t._task.done()
        await t.stop()
        return running, t._task is None

    started, stopped = asyncio.run(scenario())
    assert started is True
    assert stopped is True
