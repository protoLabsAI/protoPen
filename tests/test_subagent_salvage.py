"""max_turns is a budget, not a bomb (graph/agent.py) — port protoAgent #1879.

A subagent that never terminates (always calls a tool) used to raise
GraphRecursionError at ``recursion_limit`` and lose the whole delegation. Both
runners now stream values and salvage the partial transcript on the limit instead
of detonating.
"""

from __future__ import annotations

import asyncio

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool


class _AlwaysCallsToolModel(BaseChatModel):
    """Subagent fake model that never finishes — always emits a tool call, so the
    react loop runs until the recursion limit."""

    @property
    def _llm_type(self) -> str:
        return "fake-loops"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        msg = AIMessage(
            content="",
            tool_calls=[{"name": "cve_search", "args": {}, "id": f"c{len(messages)}"}],
        )
        return ChatResult(generations=[ChatGeneration(message=msg)])


def _dummy_tools():
    names = ["cve_search", "security_feeds", "github_trending", "browser", "security_memory"]
    out = []
    for n in names:

        @tool(n)
        def _t() -> str:
            """dummy"""
            return "ok"

        out.append(_t)
    return out


def test_task_tool_salvages_at_recursion_limit_instead_of_erroring(monkeypatch):
    import graph.agent as agent_mod
    from graph.config import LangGraphConfig

    monkeypatch.setattr(agent_mod, "create_llm", lambda *a, **k: _AlwaysCallsToolModel())
    task_tool = agent_mod._build_task_tool(LangGraphConfig(api_key="test-key"), _dummy_tools())

    out = asyncio.run(
        task_tool.coroutine(
            description="scan",
            prompt="scan the feeds",
            subagent_type="threat_scanner",
            run_in_background=False,
            state={"session_id": "a2a:sSalvage"},
        )
    )
    # Pre-fix this returned "Error: Subagent 'threat_scanner' failed: <GraphRecursionError>".
    assert not out.startswith("Error:")
    assert "GraphRecursion" not in out
    assert "threat_scanner" in out  # a salvaged/hard-stopped marker, not a detonation


def test_run_manual_subagent_salvages_at_recursion_limit(monkeypatch):
    import graph.agent as agent_mod
    from graph.config import LangGraphConfig

    monkeypatch.setattr(agent_mod, "create_llm", lambda *a, **k: _AlwaysCallsToolModel())
    monkeypatch.setattr(agent_mod, "get_combined_tools", lambda *_a, **_k: _dummy_tools())

    out = asyncio.run(
        agent_mod.run_manual_subagent(
            LangGraphConfig(api_key="test-key"),
            description="scan",
            prompt="scan the feeds",
            subagent_type="threat_scanner",
        )
    )
    assert not out.startswith("Error:")
    assert "GraphRecursion" not in out
    assert "threat_scanner" in out
