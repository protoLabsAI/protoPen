"""F0 (protopen-1hw.1): the originating session_id must reach tool bodies.

`create_agent` is wired with ``state_schema=ResearcherState`` so ``session_id`` is
a real state channel. Tools read it via ``InjectedState`` because the tracing
contextvar reads **empty** inside a LangGraph tool node — the root cause of
protoAgent's wait/background "resumed in the wrong thread" class of bugs. These
tests guard the wiring (channel present) and the behavior (a tool sees the id).
"""

from __future__ import annotations

from typing import Annotated, Any

from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState

from graph.agent import create_researcher_graph
from graph.config import LangGraphConfig
from graph.state import ResearcherState, session_id_from_state

_CFG = LangGraphConfig(api_key="test-key")


# ── helper ──────────────────────────────────────────────────────────────────


def test_session_id_from_dict_state():
    assert session_id_from_state({"session_id": "gradio:abc"}) == "gradio:abc"


def test_session_id_missing_falls_back_to_empty():
    # No contextvar set in a bare test process → empty, not a crash.
    assert session_id_from_state({}) == ""
    assert session_id_from_state(None) == ""


# ── wiring: session_id is a declared channel on the real lead graph ──────────


def test_lead_graph_declares_session_id_channel():
    g = create_researcher_graph(_CFG)
    assert "session_id" in g.channels, "state_schema=ResearcherState not wired"
    # context channel must survive too (KnowledgeMiddleware writes it).
    assert "context" in g.channels


# ── behavior: a tool reads session_id from injected state ───────────────────


class _OneToolCallModel(BaseChatModel):
    """Fake model: first call emits one tool call, second call ends the turn."""

    calls: int = 0

    @property
    def _llm_type(self) -> str:
        return "fake-one-tool-call"

    def bind_tools(self, tools, **kwargs):  # create_agent calls this
        return self

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        self.calls += 1
        if self.calls == 1:
            msg = AIMessage(
                content="",
                tool_calls=[{"name": "echo_session", "args": {}, "id": "call-1"}],
            )
        else:
            msg = AIMessage(content="done")
        return ChatResult(generations=[ChatGeneration(message=msg)])


def test_tool_reads_injected_session_id():
    seen: dict[str, Any] = {}

    @tool
    def echo_session(state: Annotated[dict, InjectedState]) -> str:
        """Record the session id visible to the tool body."""
        seen["session_id"] = session_id_from_state(state)
        return "ok"

    agent = create_agent(
        model=_OneToolCallModel(),
        tools=[echo_session],
        state_schema=ResearcherState,
    )
    agent.invoke({"messages": [("user", "go")], "session_id": "a2a:xyz"})
    assert seen.get("session_id") == "a2a:xyz"
