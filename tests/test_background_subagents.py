"""Background subagents + reactive notification (ADR 0050 Phase 1, protopen-1hw.4).

Covers the in-process BackgroundManager (spawn → complete/fail → drain-once,
session-scoped, event-bus announce) and the task tool's run_in_background branch
(returns immediately with a job id; the detached run completes and drains).
"""

from __future__ import annotations

import asyncio

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool

from graph.background import BackgroundManager, render_task_notifications


async def _drain_when_done(mgr, job_id, session, timeout=2.0):
    waited = 0.0
    while mgr.get(job_id).status == "running" and waited < timeout:
        await asyncio.sleep(0.01)
        waited += 0.01
    return mgr.drain_notifications(session)


# ── manager ──────────────────────────────────────────────────────────────────


def test_spawn_completes_and_drains_once():
    async def scenario():
        mgr = BackgroundManager()

        async def work():
            return "3 hosts, 1 critical"

        jid = mgr.spawn(work, origin_session="a2a:s1", subagent_type="vuln_analyst", description="analyze")
        drained = await _drain_when_done(mgr, jid, "a2a:s1")
        return drained, mgr.drain_notifications("a2a:s1")  # second drain empty

    drained, second = asyncio.run(scenario())
    assert len(drained) == 1 and drained[0].status == "completed"
    assert drained[0].result == "3 hosts, 1 critical"
    assert second == []  # marked notified → not redelivered


def test_failed_job_is_reported():
    async def scenario():
        mgr = BackgroundManager()

        async def boom():
            raise RuntimeError("nmap not found")

        jid = mgr.spawn(boom, origin_session="a2a:s1", subagent_type="threat_scanner", description="scan")
        return await _drain_when_done(mgr, jid, "a2a:s1")

    drained = asyncio.run(scenario())
    assert len(drained) == 1 and drained[0].status == "failed"
    assert "nmap not found" in (drained[0].error or "")


def test_drain_is_session_scoped():
    async def scenario():
        mgr = BackgroundManager()

        async def work():
            return "ok"

        jid = mgr.spawn(work, origin_session="a2a:s1", subagent_type="vuln_analyst", description="d")
        await _drain_when_done(mgr, jid, "a2a:other")  # wrong session → nothing, not marked
        return mgr.drain_notifications("a2a:other"), mgr.drain_notifications("a2a:s1")

    other, mine = asyncio.run(scenario())
    assert other == [] and len(mine) == 1


def test_event_bus_announces_completion():
    events = []

    class _Bus:
        def publish(self, event, data=None):
            events.append((event, data))

    async def scenario():
        mgr = BackgroundManager(event_bus=_Bus())

        async def work():
            return "done"

        jid = mgr.spawn(work, origin_session="a2a:s1", subagent_type="vuln_analyst", description="d")
        await _drain_when_done(mgr, jid, "a2a:s1")

    asyncio.run(scenario())
    assert any(e == "background.completed" and d["status"] == "completed" for e, d in events)


def test_render_task_notifications_format():
    assert render_task_notifications([]) == ""
    mgr = BackgroundManager()

    async def scenario():
        async def work():
            return "result body"

        jid = mgr.spawn(work, origin_session="s", subagent_type="vuln_analyst", description="analyze scan")
        return await _drain_when_done(mgr, jid, "s")

    drained = asyncio.run(scenario())
    block = render_task_notifications(drained)
    assert block.startswith("<task-notification>") and block.endswith("</task-notification>")
    assert "vuln_analyst done" in block and "result body" in block


# ── task tool integration ────────────────────────────────────────────────────


class _FinalAnswerModel(BaseChatModel):
    """Subagent fake model: returns a final answer in one step (no tool calls)."""

    @property
    def _llm_type(self) -> str:
        return "fake-final"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="recon summary: 2 open ports"))])


def test_task_run_in_background_returns_immediately_and_notifies(monkeypatch):
    import graph.agent as agent_mod
    from graph.background import get_background_manager

    # Subagent uses a fake model (no gateway). Keep the real create_agent so the
    # subagent graph is genuinely built and driven.
    monkeypatch.setattr(agent_mod, "create_llm", lambda *a, **k: _FinalAnswerModel())

    # Dummy tools matching threat_scanner's allowlist so sub_tools is non-empty.
    def _mk(name):
        @tool(name)
        def _t() -> str:
            """dummy"""
            return "ok"

        return _t

    all_tools = [_mk(n) for n in ["cve_search", "security_feeds", "github_trending", "browser", "security_memory"]]
    from graph.config import LangGraphConfig

    task_tool = agent_mod._build_task_tool(LangGraphConfig(api_key="test-key"), all_tools)

    async def scenario():
        # Spawn AND drain in the SAME loop — a detached task dies if its loop
        # closes (in production both share the server's long-lived event loop).
        out = await task_tool.coroutine(
            description="scan feeds",
            prompt="scan",
            subagent_type="threat_scanner",
            run_in_background=True,
            state={"session_id": "a2a:sX"},
        )
        assert out.startswith("Background subagent started: bg-")  # returned immediately
        return out, await _collect(get_background_manager(), "a2a:sX")

    out, drained = asyncio.run(scenario())
    assert len(drained) == 1 and drained[0].status == "completed"
    assert "recon summary" in (drained[0].result or "")


async def _collect(mgr, session, timeout=2.0):
    waited = 0.0
    while waited < timeout:
        d = mgr.drain_notifications(session)
        if d:
            return d
        await asyncio.sleep(0.02)
        waited += 0.02
    return []
