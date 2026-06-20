"""ResearcherState — LangGraph state schema for protoPen.

Extends langchain's ``AgentState`` (the schema ``create_agent`` builds its graph
from) with protoPen-specific fields and custom reducers.

Wiring this as ``create_agent(state_schema=ResearcherState)`` makes ``session_id``
a first-class state channel, so tool bodies can read the originating session via
``InjectedState`` — the ``tracing`` contextvar reads **empty** inside a LangGraph
tool node, which silently breaks any tool that needs to know which chat it runs
in (e.g. ``wait`` resume, background-subagent notification). See F0 /
protopen-1hw.1.
"""

import operator
from typing import Annotated, NotRequired

from langchain.agents.middleware.types import AgentState


def merge_findings(existing: list[dict] | None, new: list[dict] | None) -> list[dict]:
    """Reducer: append new findings, no deduplication needed."""
    if existing is None:
        return new or []
    if new is None:
        return existing
    return existing + new


class ResearcherState(AgentState):
    """State schema for the protoPen LangGraph agent.

    Extends langchain's ``AgentState`` (which provides ``messages`` with the
    add_messages reducer, plus ``jump_to`` / ``structured_response``). Custom
    fields carry protoPen context through the graph.
    """

    # Originating chat/session id, stamped into the initial state at invocation
    # (server.chat) and read by tools via InjectedState. The contextvar is an
    # off-graph fallback only.
    session_id: NotRequired[str]

    # Knowledge context injected by KnowledgeMiddleware before LLM call
    research_context: NotRequired[str]

    # Volatile per-turn context (retrieved knowledge + learned skills) that
    # KnowledgeMiddleware.before_model writes and PromptCacheMiddleware delivers
    # into the system message at the model-call boundary (the static system
    # prompt can't read state, so this is how it reaches the LLM).
    context: NotRequired[str]

    # Accumulated research findings (append-only via reducer)
    findings: Annotated[list[dict], merge_findings]

    # Current research topic (set by user message analysis)
    current_topic: NotRequired[str | None]

    captured_messages: Annotated[list[str], operator.add]


def session_id_from_state(state) -> str:
    """Read the originating session id from injected graph state.

    Tools receive graph state via ``InjectedState``; this is the reliable source
    because ``tracing.current_session_id()`` reads empty inside a LangGraph tool
    body (the tool node runs outside the context where the contextvar was set).
    Falls back to the contextvar only when state carries no session id.
    """
    sid = ""
    if isinstance(state, dict):
        sid = state.get("session_id") or ""
    elif state is not None:
        sid = getattr(state, "session_id", "") or ""
    if not sid:
        try:
            import tracing

            getter = getattr(tracing, "current_session_id", None)
            if callable(getter):
                sid = getter() or ""
        except Exception:
            sid = ""
    return sid
