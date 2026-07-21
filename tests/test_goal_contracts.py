"""Goal completion contracts (ADR 0073) — outcome/constraints/boundaries/stop_when.

Directive-only: they shape the continuation prompt; the deterministic verifier stays
the sole arbiter of DONE. A contract-less goal is byte-for-byte unchanged.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace as NS

from graph.goals.controller import GoalController
from graph.goals.store import GoalStore
from graph.goals.types import GoalState, coerce_str_list


def _ctrl(tmp_path, **cfg):
    base = {"goals_max_iterations": 10, "goals_no_progress_limit": 4}
    base.update(cfg)
    return GoalController(NS(**base), GoalStore(str(tmp_path)))


def _run(coro):
    return asyncio.run(coro)


def _result(reason="not met", evidence=""):
    return NS(reason=reason, evidence=evidence)


def test_coerce_str_list_forms():
    assert coerce_str_list(None) == []
    assert coerce_str_list(["a", " b ", ""]) == ["a", "b"]
    assert coerce_str_list("one; two\nthree") == ["one", "two", "three"]


def test_has_contract():
    assert GoalState(session_id="s", condition="c").has_contract is False
    assert GoalState(session_id="s", condition="c", stop_when="before exploit").has_contract is True
    assert GoalState(session_id="s", condition="c", constraints=["stay in scope"]).has_contract is True


def test_contractless_continuation_is_unchanged():
    """A goal with no contract must append nothing — backward-compat."""
    c = _ctrl("/tmp")  # store dir unused for this pure call
    state = GoalState(session_id="s", condition="enumerate the subnet", iteration=1, max_iterations=5)
    base = c._continuation_base(state, _result())
    full = c._continuation(state, _result())
    assert full == base  # byte-for-byte identical


def test_contract_shapes_the_continuation():
    c = _ctrl("/tmp")
    state = GoalState(
        session_id="s",
        condition="find a critical vuln",
        iteration=1,
        max_iterations=5,
        outcome="one confirmed critical with a repro",
        constraints=["stay on in-scope hosts"],
        boundaries=["no destructive actions"],
        stop_when="before running any exploit",
    )
    out = c._continuation(state, _result())
    assert "[goal contract]" in out
    assert "one confirmed critical with a repro" in out
    assert "stay on in-scope hosts" in out
    assert "no destructive actions" in out
    assert "before running any exploit" in out
    # The base continuation is still present (contract is appended, not a replacement).
    assert "The goal is NOT yet met." in out
    # And it is framed as directive-only, not a DONE override.
    assert "the verifier, not this block, decides" in out.lower() or "verifier" in out.lower()


def test_goal_json_parses_contract_fields(tmp_path):
    c = _ctrl(tmp_path)
    reply = _run(
        c.parse_control(
            '/goal {"condition":"find a crit","verifier":{"type":"findings","min":1},'
            '"outcome":"a confirmed critical","constraints":["stay in scope"],'
            '"boundaries":["no destructive actions"],"stop_when":"before exploiting"}',
            "s",
        )
    )
    assert "Goal set" in reply
    state = c.active_goal("s")
    assert state.outcome == "a confirmed critical"
    assert state.constraints == ["stay in scope"]
    assert state.boundaries == ["no destructive actions"]
    assert state.stop_when == "before exploiting"
    assert state.has_contract is True


def test_start_goal_accepts_contract(tmp_path):
    c = _ctrl(tmp_path)
    state = c.start_goal(
        "s",
        "enumerate the subnet",
        {"type": "targets", "min": 5},
        outcome="every live host mapped",
        constraints="passive only; stay in scope",  # scalar string → coerced
        stop_when="if a prod host appears",
    )
    assert state.outcome == "every live host mapped"
    assert state.constraints == ["passive only", "stay in scope"]
    assert state.stop_when == "if a prod host appears"


def test_contract_survives_persist_roundtrip(tmp_path):
    """GoalState.to_dict/from_dict carries the contract (store persists as dict)."""
    state = GoalState(
        session_id="s",
        condition="c",
        outcome="o",
        constraints=["a"],
        boundaries=["b"],
        stop_when="s",
    )
    restored = GoalState.from_dict(state.to_dict())
    assert restored.outcome == "o"
    assert restored.constraints == ["a"]
    assert restored.boundaries == ["b"]
    assert restored.stop_when == "s"
