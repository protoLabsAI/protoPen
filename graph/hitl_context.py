"""Human-in-the-loop (HITL) plumbing for the chat turn.

Two pieces, both used by ``request_user_input`` / ``request_approval``:

1. **Interactivity gate** (``hitl_allowed``) — a contextvar set by the server
   per turn (parent→child, like ``graph/goals/context.py``). It is **off by
   default**: a headless / autonomous A2A or API run never parks for input, so
   full autonomy is preserved (the engagement-mode enforcement gate, not HITL,
   is what keeps autonomous runs safe). The web console — and any A2A sender that
   can answer — opts in via ``protolabs.interactive`` message metadata. When the
   gate is off, the HITL tools no-op (tell the agent to proceed) instead of
   parking.

2. **Pending registry** (``request/take_pending_hitl``) — the reverse signal.
   A tool runs deep inside the graph and must tell the server's chat-stream loop
   to PARK as input-required, but contextvars only flow parent→child. So the tool
   writes the ``hitl-v1`` payload to this module-level registry under the running
   ``session_id``; the stream loop pops it after the turn and emits
   ``("input_required", payload)``. At most one pending request per session.
"""

from __future__ import annotations

import contextvars
from typing import Any

# Off by default → headless/autonomous turns never block on input.
_hitl_allowed: contextvars.ContextVar[bool] = contextvars.ContextVar("protopen_hitl_allowed", default=False)

_pending: dict[str, dict[str, Any]] = {}


def set_hitl_allowed(allowed: bool) -> None:
    """Mark whether the turn about to run may pause for the operator (server)."""
    _hitl_allowed.set(bool(allowed))


def hitl_allowed() -> bool:
    """True when an operator/sender is available to answer a HITL request."""
    return _hitl_allowed.get()


def request_pending_hitl(session_id: str | None, payload: dict[str, Any]) -> None:
    """Record that the running turn for ``session_id`` should park awaiting the
    operator, carrying ``payload`` (a ``hitl-v1`` form / approval / question)."""
    if session_id:
        _pending[session_id] = payload


def take_pending_hitl(session_id: str | None) -> dict[str, Any] | None:
    """Pop and return the pending HITL payload for ``session_id`` (or None)."""
    if not session_id:
        return None
    return _pending.pop(session_id, None)


def clear_pending_hitl(session_id: str | None) -> None:
    """Drop any pending HITL request for ``session_id`` (e.g. on cancel)."""
    if session_id:
        _pending.pop(session_id, None)
