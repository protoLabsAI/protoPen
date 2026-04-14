"""ResearcherState — LangGraph state schema for protoPen.

Extends AgentState with research-specific fields and custom reducers.
"""

import operator
from typing import Annotated, NotRequired

from langgraph.prebuilt.chat_agent_executor import AgentState


def merge_findings(
    existing: list[dict] | None, new: list[dict] | None
) -> list[dict]:
    """Reducer: append new findings, no deduplication needed."""
    if existing is None:
        return new or []
    if new is None:
        return existing
    return existing + new


class ResearcherState(AgentState):
    """State schema for the protoPen LangGraph agent.

    Extends AgentState (which provides `messages` with add_messages reducer).
    Custom fields carry research context through the graph.
    """

    # Session tracking (Gradio session ID)
    session_id: NotRequired[str]

    # Knowledge context injected by KnowledgeMiddleware before LLM call
    research_context: NotRequired[str]

    # Accumulated research findings (append-only via reducer)
    findings: Annotated[list[dict], merge_findings]

    # Current research topic (set by user message analysis)
    current_topic: NotRequired[str | None]

    captured_messages: Annotated[list[str], operator.add]
