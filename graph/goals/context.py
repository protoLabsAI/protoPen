"""Per-turn session context for goal-aware tools.

The agent's ``set_goal`` tool needs the current ``session_id`` to write a goal to
the right per-session store, but LangChain tools receive no session argument. The
server sets this contextvar at each graph-invocation site (both chat paths); the
tool reads it back. A contextvar (not a plain global) keeps concurrent sessions
isolated — each turn runs in its own copied context.
"""

from __future__ import annotations

import contextvars

_current_session: contextvars.ContextVar[str | None] = contextvars.ContextVar("protopen_goal_session", default=None)


def set_current_session(session_id: str | None) -> None:
    """Mark the session_id for the turn about to run (called by the server)."""
    _current_session.set(session_id)


def get_current_session() -> str | None:
    """The session_id of the running turn, or None outside a chat turn."""
    return _current_session.get()
