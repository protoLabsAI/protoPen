"""Regression: the agent graph must be compiled WITH the checkpointer so
multi-turn chats keep their history instead of starting fresh each message.

A checkpointer passed only in the invoke ``config`` is ignored by LangGraph — it
must be bound at compile time. Missing this gave the chat amnesia: every turn ran
with just the new message, so it couldn't resolve references to prior turns
("update it") or recall earlier context.
"""

from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver

from graph.agent import create_researcher_graph
from graph.config import LangGraphConfig

# Building the full graph constructs the LLM client, which needs a non-empty
# api_key (no network call happens at compile time). CI has no OPENAI_API_KEY,
# so pass a dummy key in the config.
_CFG = LangGraphConfig(api_key="test-key")


def test_graph_binds_checkpointer_at_compile_time():
    g = create_researcher_graph(_CFG, checkpointer=MemorySaver())
    assert g.checkpointer is not None


def test_graph_has_no_checkpointer_when_none_passed():
    assert create_researcher_graph(_CFG).checkpointer is None
