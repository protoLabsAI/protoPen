"""Cancellable in-flight delegations (protopen-1hw.12)."""

from __future__ import annotations

import asyncio

import graph.agent as agent_mod
from graph import delegations
from graph.config import LangGraphConfig


# ── registry ─────────────────────────────────────────────────────────────────


def test_registry_cancel_marks_and_cancels():
    async def scenario():
        async def slow():
            await asyncio.sleep(5)

        t = asyncio.create_task(slow())
        delegations.register("tc1", t, session_id="s", subagent_type="recon", description="d")
        assert [d["tool_call_id"] for d in delegations.pending("s")] == ["tc1"]
        assert delegations.pending("other") == []  # session-scoped
        ok = delegations.cancel("tc1")
        assert ok is True and delegations.was_cancelled("tc1") is True
        try:
            await t
        except asyncio.CancelledError:
            pass
        delegations.unregister("tc1")
        return delegations.cancel("tc1"), delegations.was_cancelled("tc1")

    cancelled_after, flagged_after = asyncio.run(scenario())
    assert cancelled_after is False  # unknown id
    assert flagged_after is False  # cleared on unregister


def test_cancel_unknown_is_false():
    assert delegations.cancel("nope") is False


# ── task tool cancel path ────────────────────────────────────────────────────


class _SleepingSubagent:
    async def ainvoke(self, *a, **k):
        await asyncio.sleep(5)
        return {"messages": []}


def test_task_delegation_cancelled_by_operator_returns_graceful(monkeypatch):
    # Subagent that sleeps, built with a fake model — so we can cancel it mid-run.
    monkeypatch.setattr(agent_mod, "create_llm", lambda *a, **k: object())
    monkeypatch.setattr(agent_mod, "create_agent", lambda **k: _SleepingSubagent())

    from langchain_core.tools import tool as _mktool

    def _mk(name):
        @_mktool(name)
        def _t() -> str:
            """dummy"""
            return "ok"

        return _t

    all_tools = [_mk(n) for n in ["cve_search", "security_feeds", "github_trending", "browser", "security_memory"]]
    task_tool = agent_mod._build_task_tool(LangGraphConfig(api_key="x"), all_tools)

    async def scenario():
        t = asyncio.create_task(
            task_tool.coroutine(
                description="long scan",
                prompt="go",
                subagent_type="threat_scanner",
                state={"session_id": "a2a:s"},
                tool_call_id="tc-99",
            )
        )
        # let it register + start the sleeping subagent
        for _ in range(50):
            await asyncio.sleep(0.01)
            if delegations.pending("a2a:s"):
                break
        assert delegations.cancel("tc-99") is True
        return await t

    out = asyncio.run(scenario())
    assert "cancelled by operator" in out
    assert delegations.pending() == []  # unregistered in finally
