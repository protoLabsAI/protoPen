"""wait / yield / resume (ADR 0053, protopen-1hw.3).

The `wait` tool schedules a one-shot resume into the same conversation and ends
the turn (via WaitYieldMiddleware) instead of busy-polling. These tests cover the
tool contract, the middleware's trailing-block detection, an end-to-end yield
driven by a fake model, and the scheduler's context_id routing.
"""

from __future__ import annotations

import asyncio

import pytest
from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from graph.middleware.wait_yield import WaitYieldMiddleware, _trailing_wait_yield
from graph.state import WAIT_YIELD_MARKER, ResearcherState
from scheduler import LocalScheduler
from tools.lg_tools import set_scheduler, wait


# ── middleware detection ─────────────────────────────────────────────────────


def _yield_tm():
    return ToolMessage(content=f"{WAIT_YIELD_MARKER} for 5s — ...", name="wait", tool_call_id="c1")


def test_detects_trailing_wait_yield():
    assert _trailing_wait_yield([HumanMessage(content="go"), _yield_tm()]) is True


def test_error_wait_does_not_yield():
    err = ToolMessage(content="Error: scheduler unavailable", name="wait", tool_call_id="c2")
    assert _trailing_wait_yield([HumanMessage(content="go"), err]) is False


def test_wait_not_in_trailing_block_does_not_yield():
    # A resumed turn: the old wait result is behind the new human message.
    assert _trailing_wait_yield([_yield_tm(), HumanMessage(content="resumed")]) is False


def test_middleware_before_model_jumps_to_end():
    mw = WaitYieldMiddleware()
    out = mw.before_model({"messages": [HumanMessage(content="go"), _yield_tm()]}, None)
    assert out == {"jump_to": "end"}
    assert mw.before_model({"messages": [HumanMessage(content="go")]}, None) is None


# ── the wait tool ────────────────────────────────────────────────────────────


def test_wait_without_scheduler_errors_and_does_not_yield():
    set_scheduler(None)
    try:
        out = asyncio.run(wait.coroutine(seconds=5, then="check scan", state={"session_id": "s"}))
    finally:
        set_scheduler(None)
    assert out.startswith("Error:")
    assert WAIT_YIELD_MARKER not in out


def test_wait_validates_args(tmp_path):
    s = LocalScheduler(agent_name="protopen-test", invoke_url="http://x", db_dir=str(tmp_path))
    set_scheduler(s)
    try:
        assert asyncio.run(wait.coroutine(seconds=0, then="x", state={})).startswith("Error:")
        assert asyncio.run(wait.coroutine(seconds=5, then="  ", state={})).startswith("Error:")
    finally:
        set_scheduler(None)


def test_wait_schedules_one_shot_into_originating_session(tmp_path):
    s = LocalScheduler(agent_name="protopen-test", invoke_url="http://x", db_dir=str(tmp_path))
    set_scheduler(s)
    try:
        out = asyncio.run(wait.coroutine(seconds=5, then="check the nmap scan", state={"session_id": "a2a:sess1"}))
        assert WAIT_YIELD_MARKER in out
        jobs = s.list_jobs()
        assert len(jobs) == 1
        assert jobs[0].prompt == "check the nmap scan"
        assert jobs[0].context_id == "a2a:sess1"  # resumes in the same thread
    finally:
        set_scheduler(None)


# ── end-to-end: a turn that calls wait ends after the tool ───────────────────


class _CallsWaitModel(BaseChatModel):
    calls: int = 0

    @property
    def _llm_type(self) -> str:
        return "fake-calls-wait"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        self.calls += 1
        if self.calls == 1:
            msg = AIMessage(
                content="",
                tool_calls=[{"name": "wait", "args": {"seconds": 5, "then": "check scan"}, "id": "call-1"}],
            )
        else:
            # Should never be reached — the turn yields after the wait tool.
            msg = AIMessage(content="should not happen")
        return ChatResult(generations=[ChatGeneration(message=msg)])


def test_turn_yields_after_wait_no_second_model_call(tmp_path):
    s = LocalScheduler(agent_name="protopen-test", invoke_url="http://x", db_dir=str(tmp_path))
    set_scheduler(s)
    model = _CallsWaitModel()
    try:
        agent = create_agent(
            model=model,
            tools=[wait],
            middleware=[WaitYieldMiddleware()],
            state_schema=ResearcherState,
        )
        # The graph runs async in protoPen (astream_events); wait is async-only.
        result = asyncio.run(agent.ainvoke({"messages": [("user", "do it")], "session_id": "a2a:sess9"}))
    finally:
        set_scheduler(None)
    # Model called exactly once: it emitted the wait tool call, then the turn
    # yielded (jump_to end) instead of calling the model again.
    assert model.calls == 1
    # The wait result is the last message and the resume was scheduled.
    assert any(isinstance(m, ToolMessage) and WAIT_YIELD_MARKER in str(m.content) for m in result["messages"])
    jobs = s.list_jobs()
    assert len(jobs) == 1 and jobs[0].context_id == "a2a:sess9"
