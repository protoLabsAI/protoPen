"""set_goal verifier-type safety (ADR 0028, protopen-1hw.9).

protoPen's goal mode is intentionally no-code-exec: there is NO shell/eval verifier
in the registry, and the agent-facing set_goal tool may only create the four
read-only / LLM-judge verifier types. These tests lock that invariant so a future
change can't add a code-execution verifier and silently expose it to the model.
"""

from __future__ import annotations

import asyncio

from graph.goals.verifiers import AGENT_SAFE_VERIFIERS, VERIFIERS
from tools import lg_tools


_DANGEROUS = {"command", "test", "ci", "shell", "exec", "eval", "data", "python"}


def test_registry_has_no_code_execution_verifier():
    assert set(VERIFIERS) & _DANGEROUS == set()


def test_agent_safe_set_is_subset_of_registry_and_safe():
    assert AGENT_SAFE_VERIFIERS <= set(VERIFIERS)
    assert AGENT_SAFE_VERIFIERS & _DANGEROUS == set()
    assert AGENT_SAFE_VERIFIERS == {"findings", "targets", "task", "llm"}


def _call_set_goal(verifier: str) -> str:
    from graph.goals.context import set_current_session

    started = []

    class _Ctrl:
        def start_goal(self, session_id, condition, spec):
            started.append(spec)

            class _S:
                pass

            s = _S()
            s.condition = condition
            s.max_iterations = 10
            return s

    lg_tools.set_goal_controller(_Ctrl())
    set_current_session("test-sess")
    try:
        out = asyncio.run(lg_tools.set_goal.coroutine(condition="do a thing", verifier=verifier))
    finally:
        lg_tools.set_goal_controller(None)
        set_current_session(None)
    return out, started


def test_set_goal_rejects_shell_and_eval_verifiers():
    for bad in ("command", "test", "ci", "eval", "data", "bogus"):
        out, started = _call_set_goal(bad)
        assert out.startswith("Error:"), f"{bad} should be rejected"
        assert "unsafe" in out or "unknown" in out
        assert started == [], f"{bad} must not reach the goal controller"


def test_set_goal_accepts_a_safe_verifier():
    out, started = _call_set_goal("findings")
    assert out.startswith("Goal set")
    assert started and started[0]["type"] == "findings"
