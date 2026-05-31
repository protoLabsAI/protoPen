"""ToolTimeoutMiddleware — per-tool execution backstop.

A hung tool (a broken/missing internal timeout, a dead network peer, a
subprocess that never returns) would otherwise wedge the entire agent turn
indefinitely — the exact failure that froze a console chat mid tool-call. This
wraps every tool call in ``asyncio.wait_for`` so any tool that blows the cap is
aborted and the model receives a ``[TIMEOUT]`` ToolMessage (keeping the
tool_use/tool_result pairing valid) and can carry on, instead of the run
freezing forever.

It is a BACKSTOP, not a tight bound: the cap is intentionally generous so it
never trips legitimately slow tools (full-port scans, all-sites OSINT sweeps,
which carry their own smaller timeouts). Tools that run long by design — notably
``task`` subagent delegation, which fans out into many tool calls — are exempt.

Place it LAST in the middleware chain so it wraps the tool execution most
tightly (innermost), and so EnforcementMiddleware (first/outermost) still blocks
disallowed calls before they ever reach the timer.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage

logger = logging.getLogger(__name__)

# Tools that legitimately run long and must never be capped. Subagent
# delegation (``task``) expands into a whole nested agent run.
_DEFAULT_EXEMPT = frozenset({"task"})


class ToolTimeoutMiddleware(AgentMiddleware):
    """Abort any single tool call that exceeds ``timeout_seconds``.

    Args:
        timeout_seconds: Per-tool wall-clock cap. <= 0 disables the backstop.
        exempt: Tool names to never cap (defaults to subagent delegation).
    """

    def __init__(self, timeout_seconds: int = 600, exempt: Optional[set[str]] = None):
        super().__init__()
        self._timeout = timeout_seconds
        self._exempt = frozenset(exempt) if exempt is not None else _DEFAULT_EXEMPT

    def _timeout_message(self, request) -> ToolMessage:
        """A ToolMessage keeps the tool_use/tool_result pairing valid."""
        tool_name = request.tool_call.get("name", "unknown")
        return ToolMessage(
            content=(
                f"[TIMEOUT] Tool '{tool_name}' exceeded the {self._timeout}s execution cap "
                f"and was aborted. It may be hung or the target unresponsive — narrow the "
                f"scope (smaller range, single site/host) or try a different approach."
            ),
            tool_call_id=request.tool_call.get("id", ""),
        )

    async def awrap_tool_call(self, request, handler):
        """Async gate — the path the agent actually runs through."""
        tool_name = request.tool_call.get("name", "")
        if self._timeout <= 0 or tool_name in self._exempt:
            return await handler(request)
        try:
            return await asyncio.wait_for(handler(request), timeout=self._timeout)
        except asyncio.TimeoutError:
            logger.warning("[timeout] tool '%s' exceeded %ds cap — aborted", tool_name, self._timeout)
            return self._timeout_message(request)

    def wrap_tool_call(self, request, handler):
        """Sync path: tools here are async, so there is nothing to bound — pass through."""
        return handler(request)
