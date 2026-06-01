"""Goal engine — control parsing, the findings verifier, and the decision loop.

Pure (no graph/LLM calls): the findings verifier reads `_active_findings`, which
we monkeypatch; the llm verifier is exercised separately. The server owns the
re-invocation; this covers the controller's continue/finish decisions + caps.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace as NS

from graph.goals import verifiers
from graph.goals.controller import GoalController
from graph.goals.store import GoalStore
from graph.goals.types import GoalState
from graph.goals.verifiers import (
    VerifyContext,
    _verify_findings,
    _verify_targets,
    _verify_task,
    run_verifier,
)


def _ctrl(tmp_path, **cfg):
    base = {"goals_max_iterations": 10, "goals_no_progress_limit": 4}
    base.update(cfg)
    return GoalController(NS(**base), GoalStore(str(tmp_path)))


def _run(coro):
    return asyncio.run(coro)


# ── control parsing ───────────────────────────────────────────────────────────


def test_parse_set_text_defaults_to_llm(tmp_path):
    c = _ctrl(tmp_path)
    assert "Goal set" in _run(c.parse_control("/goal find a critical vuln", "s"))
    g = c.active_goal("s")
    assert g.condition == "find a critical vuln" and g.verifier == {"type": "llm"} and g.max_iterations == 10


def test_parse_set_json_findings_spec(tmp_path):
    c = _ctrl(tmp_path)
    _run(
        c.parse_control('/goal {"condition":"crit","verifier":{"type":"findings","severity":"critical","min":2}}', "s")
    )
    g = c.active_goal("s")
    assert g.verifier["type"] == "findings" and g.verifier["min"] == 2


def test_parse_status_and_clear(tmp_path):
    c = _ctrl(tmp_path)
    assert "No active goal" in _run(c.parse_control("/goal", "s"))
    _run(c.parse_control("/goal do x", "s"))
    assert "via llm" in _run(c.parse_control("/goal", "s"))
    assert _run(c.parse_control("/goal clear", "s")) == "Goal cleared."
    assert c.active_goal("s") is None


def test_parse_non_goal_message_returns_none(tmp_path):
    assert _run(_ctrl(tmp_path).parse_control("hello there", "s")) is None


# ── findings verifier ─────────────────────────────────────────────────────────


def test_findings_verifier_severity_and_category(monkeypatch):
    monkeypatch.setattr(
        verifiers,
        "_active_findings",
        lambda: [
            {"severity": "critical", "category": "rce"},
            {"severity": "high", "category": "xss"},
            {"severity": "low", "category": "info"},
        ],
    )
    # sev≥high → critical + high = 2
    assert _run(_verify_findings({"severity": "high", "min": 2}, VerifyContext())).met
    # category substring
    assert _run(_verify_findings({"category": "rce", "min": 1}, VerifyContext())).met
    # not enough criticals
    assert not _run(_verify_findings({"severity": "critical", "min": 2}, VerifyContext())).met


# ── targets verifier ──────────────────────────────────────────────────────────


def test_targets_verifier_min_and_device_type(monkeypatch):
    monkeypatch.setattr(
        verifiers,
        "_search_hosts",
        lambda q="": [
            {"ip": "10.0.0.1", "device_type": "router"},
            {"ip": "10.0.0.2", "device_type": "camera"},
            {"ip": "10.0.0.3", "device_type": "camera"},
        ],
    )
    assert _run(_verify_targets({"min": 3}, VerifyContext())).met
    assert not _run(_verify_targets({"min": 4}, VerifyContext())).met
    # device_type filter narrows the set
    assert _run(_verify_targets({"min": 2, "device_type": "camera"}, VerifyContext())).met
    assert not _run(_verify_targets({"min": 2, "device_type": "router"}, VerifyContext())).met


# ── task verifier ─────────────────────────────────────────────────────────────


def test_task_verifier_by_id_and_all(monkeypatch):
    monkeypatch.setattr(
        verifiers,
        "_list_tasks",
        lambda: [
            {"id": "protopen-1", "title": "web assessment", "status": "closed"},
            {"id": "protopen-2", "title": "smb follow-up", "status": "open"},
        ],
    )
    # specific id that's closed → met
    assert _run(_verify_task({"id": "protopen-1"}, VerifyContext())).met
    # specific id still open → not met
    assert not _run(_verify_task({"id": "protopen-2"}, VerifyContext())).met
    # title substring
    assert _run(_verify_task({"title": "web"}, VerifyContext())).met
    # no selector → all must be done (one is open) → not met
    assert not _run(_verify_task({}, VerifyContext())).met
    # unknown id → not met, explains no match
    r = _run(_verify_task({"id": "nope"}, VerifyContext()))
    assert not r.met and "no tracked task" in r.reason


def test_run_verifier_dispatches_new_types(monkeypatch):
    monkeypatch.setattr(verifiers, "_search_hosts", lambda q="": [{"ip": "1.1.1.1"}])
    assert _run(run_verifier({"type": "targets", "min": 1}, VerifyContext())).met
    assert not _run(run_verifier({"type": "bogus"}, VerifyContext())).met


def test_start_goal_uses_config_cap(tmp_path):
    c = _ctrl(tmp_path, goals_max_iterations=7)
    state = c.start_goal("s", "enumerate the subnet", {"type": "targets", "min": 5})
    assert state.condition == "enumerate the subnet"
    assert state.verifier == {"type": "targets", "min": 5}
    assert state.max_iterations == 7
    assert c.active_goal("s") is not None
    # missing type defaults to llm
    assert c.start_goal("t", "vague goal").verifier == {"type": "llm"}


# ── decision loop ─────────────────────────────────────────────────────────────


def test_evaluate_achieved(tmp_path, monkeypatch):
    monkeypatch.setattr(verifiers, "_active_findings", lambda: [{"severity": "critical", "category": "x"}])
    c = _ctrl(tmp_path)
    _run(
        c.parse_control('/goal {"condition":"crit","verifier":{"type":"findings","severity":"critical","min":1}}', "s")
    )
    d = _run(c.evaluate("s", last_text="done"))
    assert d.action == "done" and d.state.status == "achieved"


def test_evaluate_continues_then_exhausts(tmp_path, monkeypatch):
    monkeypatch.setattr(verifiers, "_active_findings", lambda: [])  # never met
    c = _ctrl(tmp_path)
    _run(c.parse_control('/goal {"condition":"x","verifier":{"type":"findings","min":1},"max_iterations":2}', "s"))
    d1 = _run(c.evaluate("s", last_text="working <goal_plan>step 1</goal_plan>"))
    assert d1.action == "continue" and "continuation" in d1.message
    assert c.active_goal("s").checklist == "step 1"  # plan captured
    d2 = _run(c.evaluate("s", last_text="still"))
    assert d2.action == "done" and d2.state.status == "exhausted"


def test_evaluate_agent_giveup_is_unachievable(tmp_path, monkeypatch):
    monkeypatch.setattr(verifiers, "_active_findings", lambda: [])
    c = _ctrl(tmp_path)
    _run(c.parse_control('/goal {"condition":"x","verifier":{"type":"findings","min":1}}', "s"))
    d = _run(c.evaluate("s", last_text='nope <goal_unachievable reason="out of scope"/>'))
    assert d.action == "done" and d.state.status == "unachievable" and "out of scope" in d.state.last_reason


def test_evaluate_no_progress_gives_up(tmp_path, monkeypatch):
    monkeypatch.setattr(verifiers, "_active_findings", lambda: [])  # evidence never changes
    c = _ctrl(tmp_path, goals_no_progress_limit=2, goals_max_iterations=20)
    _run(c.parse_control('/goal {"condition":"x","verifier":{"type":"findings","min":1}}', "s"))
    d = None
    for _ in range(6):
        d = _run(c.evaluate("s", last_text="same output"))
        if d.action == "done":
            break
    assert d.state.status == "unachievable"


def test_no_evaluate_without_active_goal(tmp_path):
    assert _run(_ctrl(tmp_path).evaluate("s", last_text="x")) is None


# ── store ─────────────────────────────────────────────────────────────────────


def test_store_roundtrip(tmp_path):
    store = GoalStore(str(tmp_path))
    store.set(GoalState(session_id="s", condition="x"))
    assert store.get("s").condition == "x"
    assert [g.session_id for g in store.all()] == ["s"]
    assert store.clear("s") and store.get("s") is None
