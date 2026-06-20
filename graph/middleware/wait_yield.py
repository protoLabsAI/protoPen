"""WaitYieldMiddleware — end the turn after a successful ``wait`` (ADR 0053).

The ``wait`` tool schedules a one-shot resume into the same conversation and
returns a marker string. Normally control would flow back to the model for
another step; this middleware intercepts at ``before_model``: if the trailing
tool-message block contains a successful ``wait`` result, it jumps straight to
``end`` so the turn yields cleanly (no extra model call). The scheduler re-invokes
the agent later in the same thread with the ``then`` instruction.

An ``Error:`` wait result carries no marker, so it does NOT yield — the agent
sees the error on the next model call and can react.
"""

from __future__ import annotations

import logging

from langchain.agents.middleware import AgentMiddleware, hook_config
from langchain_core.messages import ToolMessage

from graph.state import WAIT_YIELD_MARKER

log = logging.getLogger(__name__)


def _message_text(msg) -> str:
    content = getattr(msg, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
    return str(content)


def _trailing_wait_yield(messages: list) -> bool:
    """True if the most recent tool-message block holds a successful wait yield.

    Scans backwards over the contiguous run of trailing ToolMessages (the
    results of the AIMessage that just called tools). A wait can be called
    alongside other tools, so any wait-yield marker in that block counts.
    """
    for msg in reversed(messages):
        if not isinstance(msg, ToolMessage):
            break  # left the trailing tool block (hit the AIMessage / a human turn)
        name = getattr(msg, "name", "") or ""
        text = _message_text(msg)
        if (name == "wait" or WAIT_YIELD_MARKER in text) and WAIT_YIELD_MARKER in text:
            return True
    return False


class WaitYieldMiddleware(AgentMiddleware):
    """Jump to ``end`` once a successful ``wait`` result lands in the thread."""

    @hook_config(can_jump_to=["end"])
    def before_model(self, state, runtime) -> dict | None:
        messages = state.get("messages", []) if isinstance(state, dict) else getattr(state, "messages", [])
        if _trailing_wait_yield(messages or []):
            log.info("[wait] yielding turn — resume scheduled")
            return {"jump_to": "end"}
        return None

    async def abefore_model(self, state, runtime) -> dict | None:
        return self.before_model(state, runtime)
