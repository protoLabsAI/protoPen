"""WatchManager — N concurrent condition-watches (ADR 0067, h34.7, protopen-h34.7).

Covers the primitive that supersedes the retired monitor-goal ticker: per-watch
cadence (the #1753 fix), trip → follow-up turn via the scheduler self-A2A path,
deadline expiry, stall reaction, cancel, and verifier isolation. The verifier is
faked so tests are host-free and deterministic; ``tick()`` is driven directly.
"""

from __future__ import annotations

import asyncio

from graph.goals.types import VerifyResult
import graph.watch as watch_mod
from graph.watch import WatchManager


class _FakeScheduler:
    def __init__(self):
        self.added: list[dict] = []

    def add_job(self, prompt, schedule, *, job_id=None, context_id=None):
        self.added.append({"prompt": prompt, "schedule": schedule, "job_id": job_id, "context_id": context_id})
        return type("J", (), {"id": job_id or "gen"})()


class _FakeBus:
    def __init__(self):
        self.events: list[tuple] = []

    def publish(self, event, data=None):
        self.events.append((event, data))


def _verifier(met, reason="checking"):
    async def fake(spec, ctx):
        return VerifyResult(met=met() if callable(met) else met, reason=reason, evidence="")

    return fake


def _mgr(monkeypatch, met, *, scheduler=None, bus=None):
    monkeypatch.setattr(watch_mod, "run_verifier", _verifier(met))
    m = WatchManager(event_bus=bus)
    if scheduler is not None:
        m.set_scheduler(scheduler)
    return m


# ── add / control surface ─────────────────────────────────────────────────────


def test_add_watch_is_active_with_future_first_check(monkeypatch):
    m = _mgr(monkeypatch, met=False)
    w = m.add_watch(session_id="a2a:s1", condition="scan done", on_trip="analyze it", interval_s=30)
    assert w.active and w.id.startswith("watch-")
    assert w.interval_s == 30
    assert w.next_check_at > 0  # first check is one interval out, not immediate


def test_cancel_watch(monkeypatch):
    m = _mgr(monkeypatch, met=True, scheduler=_FakeScheduler())
    w = m.add_watch(session_id="a2a:s1", condition="c", on_trip="react", interval_s=10)
    assert m.cancel_watch(w.id) is True
    assert m.get(w.id).status == "cancelled"
    assert m.cancel_watch(w.id) is False  # already cancelled
    # A cancelled watch is never evaluated even when due.
    m.get(w.id).next_check_at = 0
    assert asyncio.run(m.tick()) == []


# ── tick: cadence + trip ──────────────────────────────────────────────────────


def test_not_due_watch_is_not_evaluated(monkeypatch):
    calls = {"n": 0}

    async def counting(spec, ctx):
        calls["n"] += 1
        return VerifyResult(met=True, reason="", evidence="")

    monkeypatch.setattr(watch_mod, "run_verifier", counting)
    m = WatchManager()
    w = m.add_watch(session_id="s", condition="c", on_trip="go", interval_s=999)
    # next_check_at is ~999s out → not due this tick.
    assert asyncio.run(m.tick()) == []
    assert calls["n"] == 0 and w.status == "active"


def test_due_and_met_trips_and_fires_follow_up_turn(monkeypatch):
    sched = _FakeScheduler()
    m = _mgr(monkeypatch, met=True, scheduler=sched)
    w = m.add_watch(session_id="a2a:s1", condition="host up", on_trip="enumerate 10.0.0.5", interval_s=60)
    w.next_check_at = 0  # force due

    tripped = asyncio.run(m.tick())

    assert tripped == [w.id]
    assert m.get(w.id).status == "tripped"
    assert len(sched.added) == 1
    a = sched.added[0]
    assert a["prompt"] == "enumerate 10.0.0.5"  # the on_trip instruction runs the follow-up turn
    assert a["context_id"] == "a2a:s1"  # into the origin session


def test_due_and_not_met_reschedules_without_firing(monkeypatch):
    sched = _FakeScheduler()
    m = _mgr(monkeypatch, met=False, scheduler=sched)
    w = m.add_watch(session_id="a2a:s1", condition="c", on_trip="go", interval_s=45)
    w.next_check_at = 0

    assert asyncio.run(m.tick()) == []
    assert w.status == "active"
    assert w.checks == 1
    assert w.next_check_at > 0  # advanced by one interval
    assert sched.added == []


def test_per_watch_cadence_only_evaluates_due_watches(monkeypatch):
    """#1753: watches are evaluated on their OWN next_check_at, not a global tick."""
    seen: list[str] = []

    async def recording(spec, ctx):
        seen.append(ctx.condition)
        return VerifyResult(met=False, reason="", evidence="")

    monkeypatch.setattr(watch_mod, "run_verifier", recording)
    m = WatchManager()
    due = m.add_watch(session_id="s", condition="DUE", on_trip="x", interval_s=10)
    not_due = m.add_watch(session_id="s", condition="NOT_DUE", on_trip="x", interval_s=10)
    due.next_check_at = 0  # due
    # not_due keeps its ~10s-out next_check_at

    asyncio.run(m.tick())
    assert seen == ["DUE"]  # only the due watch was evaluated


# ── lifetime bounds ───────────────────────────────────────────────────────────


def test_deadline_expires_without_firing(monkeypatch):
    sched = _FakeScheduler()
    m = _mgr(monkeypatch, met=True, scheduler=sched)
    w = m.add_watch(session_id="s", condition="c", on_trip="go", interval_s=10, deadline_s=1)
    w.created_at -= 5  # 5s old, past the 1s deadline

    assert asyncio.run(m.tick()) == []
    assert w.status == "expired"
    assert sched.added == []  # expiry is silent — no follow-up turn


def test_stall_fires_a_reassess_turn(monkeypatch):
    sched = _FakeScheduler()
    m = _mgr(monkeypatch, met=False, scheduler=sched)
    w = m.add_watch(
        session_id="a2a:s1", condition="capture handshake", on_trip="crack it", interval_s=10, stall_after_s=1
    )
    w.created_at -= 5  # past the stall window

    asyncio.run(m.tick())
    assert w.status == "stalled"
    assert len(sched.added) == 1
    assert sched.added[0]["context_id"] == "a2a:s1"
    assert "capture handshake" in sched.added[0]["prompt"]  # the stall prompt names the condition


# ── robustness ────────────────────────────────────────────────────────────────


def test_verifier_exception_keeps_watch_active(monkeypatch):
    async def boom(spec, ctx):
        raise RuntimeError("verifier down")

    monkeypatch.setattr(watch_mod, "run_verifier", boom)
    m = WatchManager()
    w = m.add_watch(session_id="s", condition="c", on_trip="go", interval_s=10)
    w.next_check_at = 0

    assert asyncio.run(m.tick()) == []  # no crash
    assert w.status == "active"
    assert w.next_check_at > 0  # still rescheduled


def test_trip_without_scheduler_is_safe(monkeypatch):
    m = _mgr(monkeypatch, met=True)  # no scheduler wired
    w = m.add_watch(session_id="s", condition="c", on_trip="go", interval_s=10)
    w.next_check_at = 0
    assert asyncio.run(m.tick()) == [w.id]  # trips, fire no-ops, no error
    assert w.status == "tripped"


def test_events_published_to_bus(monkeypatch):
    bus = _FakeBus()
    m = _mgr(monkeypatch, met=True, scheduler=_FakeScheduler(), bus=bus)
    w = m.add_watch(session_id="s", condition="c", on_trip="go", interval_s=10)
    w.next_check_at = 0
    asyncio.run(m.tick())
    assert any(e == "watch.tripped" and d["watch_id"] == w.id for e, d in bus.events)


def test_list_watches_is_session_scoped(monkeypatch):
    m = _mgr(monkeypatch, met=False)
    m.add_watch(session_id="a2a:s1", condition="a", on_trip="x", interval_s=10)
    m.add_watch(session_id="a2a:s2", condition="b", on_trip="x", interval_s=10)
    assert len(m.list_watches("a2a:s1")) == 1
    assert len(m.list_watches()) == 2  # all sessions
