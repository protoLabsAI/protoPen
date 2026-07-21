"""WorkingStateMiddleware — per-turn <working_state> injection (ADR 0079, h34.8).

The self-driving backbone: each turn's context gets a snapshot of the active goal +
plan, live watches, and pending scheduled turns, plus the yield/resume doctrine. It
appends to state["context"] (composing with KnowledgeMiddleware, not clobbering) and
stays silent on idle turns. Controllers are faked via the lg_tools module globals the
middleware reads lazily.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

import tools.lg_tools as lg_tools
from graph.middleware.working_state import WorkingStateMiddleware

_STATE = {"session_id": "a2a:s1"}


def _wire(monkeypatch, *, goal=None, watches=None, jobs=None):
    monkeypatch.setattr(lg_tools, "_goal_controller", NS(active_goal=lambda s: goal) if goal is not None else None)
    monkeypatch.setattr(
        lg_tools, "_watch_manager", NS(list_watches=lambda s: watches or []) if watches is not None else None
    )
    monkeypatch.setattr(lg_tools, "_scheduler_backend", NS(list_jobs=lambda: jobs or []) if jobs is not None else None)


def _goal(condition="find a critical", plan="- step 1\n- step 2"):
    return NS(status_line=lambda: f"goal [active] via llm: {condition!r} (iteration 2/10)", checklist=plan)


def _watch(wid="watch-abc", condition="scan done", interval_s=30):
    return NS(active=True, id=wid, condition=condition, interval_s=interval_s, verifier={"type": "llm"})


def _job(jid="wait:a2a:s1", session="a2a:s1", nxt="2026-07-21T10:00:00", prompt="analyze the scan"):
    return NS(context_id=session, next_fire=nxt, id=jid, prompt=prompt)


# ── emits when there is live state ────────────────────────────────────────────


def test_active_goal_is_rendered(monkeypatch):
    _wire(monkeypatch, goal=_goal())
    out = WorkingStateMiddleware().before_model(_STATE, None)
    ctx = out["context"]
    assert ctx.startswith("<working_state>") and ctx.endswith("</working_state>")
    assert "Active goal: goal [active]" in ctx
    assert "find a critical" in ctx
    assert "Plan:" in ctx and "step 1" in ctx
    assert "self-drive" in ctx  # the doctrine


def test_live_watches_and_schedules_rendered(monkeypatch):
    _wire(monkeypatch, watches=[_watch(condition="host up")], jobs=[_job(prompt="enumerate 10.0.0.5")])
    ctx = WorkingStateMiddleware().before_model(_STATE, None)["context"]
    assert "Live watches:" in ctx and "host up" in ctx and "every 30s" in ctx
    assert "Pending scheduled turns:" in ctx and "enumerate 10.0.0.5" in ctx


def test_appends_to_existing_context(monkeypatch):
    _wire(monkeypatch, goal=_goal())
    state = {"session_id": "a2a:s1", "context": "# retrieved knowledge\nfoo"}
    ctx = WorkingStateMiddleware().before_model(state, None)["context"]
    assert ctx.startswith("# retrieved knowledge\nfoo")  # knowledge preserved
    assert "<working_state>" in ctx  # appended after


def test_schedules_are_session_scoped(monkeypatch):
    mine = _job(jid="wait:a2a:s1", session="a2a:s1", prompt="mine")
    other = _job(jid="wait:a2a:other", session="a2a:other", prompt="not mine")
    _wire(monkeypatch, jobs=[mine, other])
    ctx = WorkingStateMiddleware().before_model(_STATE, None)["context"]
    assert "mine" in ctx and "not mine" not in ctx


# ── silent when idle / unusable ───────────────────────────────────────────────


def test_idle_turn_injects_nothing(monkeypatch):
    _wire(monkeypatch, goal=None, watches=[], jobs=[])  # controllers present, nothing live
    assert WorkingStateMiddleware().before_model(_STATE, None) is None


def test_no_controllers_injects_nothing(monkeypatch):
    _wire(monkeypatch)  # all None
    assert WorkingStateMiddleware().before_model(_STATE, None) is None


def test_no_session_injects_nothing(monkeypatch):
    _wire(monkeypatch, goal=_goal())
    assert WorkingStateMiddleware().before_model({}, None) is None


def test_render_failure_is_swallowed(monkeypatch):
    def _boom(_s):
        raise RuntimeError("controller exploded")

    monkeypatch.setattr(lg_tools, "_goal_controller", NS(active_goal=_boom))
    monkeypatch.setattr(lg_tools, "_watch_manager", None)
    monkeypatch.setattr(lg_tools, "_scheduler_backend", None)
    # _goal swallows its own failure → no live state → None (never raises).
    assert WorkingStateMiddleware().before_model(_STATE, None) is None


def test_many_watches_are_capped(monkeypatch):
    watches = [_watch(wid=f"watch-{i}", condition=f"c{i}") for i in range(12)]
    _wire(monkeypatch, watches=watches)
    ctx = WorkingStateMiddleware().before_model(_STATE, None)["context"]
    assert "and 4 more" in ctx  # 12 - 8 cap
