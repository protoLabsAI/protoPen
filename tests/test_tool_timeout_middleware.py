"""ToolTimeoutMiddleware — per-tool execution backstop."""

from __future__ import annotations

import asyncio
import sys
from types import ModuleType, SimpleNamespace

# ── Stub langchain + langchain_core if not installed (mirrors
# test_enforcement_middleware.py so this runs locally and on CI) ──
if "langchain" not in sys.modules:
    _lc = ModuleType("langchain")
    _lc_agents = ModuleType("langchain.agents")
    _lc_mw = ModuleType("langchain.agents.middleware")

    class _AgentMiddleware:
        def __init__(self):
            pass

    _lc_mw.AgentMiddleware = _AgentMiddleware
    _lc_agents.middleware = _lc_mw
    _lc.agents = _lc_agents
    sys.modules["langchain"] = _lc
    sys.modules["langchain.agents"] = _lc_agents
    sys.modules["langchain.agents.middleware"] = _lc_mw

if "langchain_core" not in sys.modules:
    _lc_core = ModuleType("langchain_core")
    _lc_core.__path__ = []
    _lc_core_msgs = ModuleType("langchain_core.messages")

    class _ToolMessage:
        def __init__(self, content: str = "", tool_call_id: str = "", **kwargs):
            self.content = content
            self.tool_call_id = tool_call_id

    _lc_core_msgs.ToolMessage = _ToolMessage
    _lc_core.messages = _lc_core_msgs
    sys.modules["langchain_core"] = _lc_core
    sys.modules["langchain_core.messages"] = _lc_core_msgs

from langchain_core.messages import ToolMessage

from graph.middleware.timeout import ToolTimeoutMiddleware


def _req(name: str = "maigret", call_id: str = "call-1"):
    """A minimal stand-in for the middleware request object."""
    return SimpleNamespace(tool_call={"name": name, "id": call_id, "args": {}})


def test_slow_tool_times_out_to_toolmessage():
    mw = ToolTimeoutMiddleware(timeout_seconds=1)

    async def slow(_request):
        await asyncio.sleep(30)
        return ToolMessage(content="should never arrive", tool_call_id="call-1")

    result = asyncio.run(mw.awrap_tool_call(_req(), slow))
    assert isinstance(result, ToolMessage)
    assert "[TIMEOUT]" in result.content
    assert "maigret" in result.content
    # Pairing stays valid for the model.
    assert result.tool_call_id == "call-1"


def test_fast_tool_passes_through():
    mw = ToolTimeoutMiddleware(timeout_seconds=5)

    async def fast(_request):
        return ToolMessage(content="ok", tool_call_id="call-1")

    result = asyncio.run(mw.awrap_tool_call(_req(), fast))
    assert result.content == "ok"


def test_exempt_tool_is_not_capped():
    # `task` (subagent delegation) must run uncapped even past the cap.
    mw = ToolTimeoutMiddleware(timeout_seconds=1)

    async def exempt(_request):
        # Sleeps LONGER than the 1s cap — a non-exempt tool would return
        # [TIMEOUT] here, so completing proves the exemption bypassed wait_for.
        await asyncio.sleep(1.3)
        return ToolMessage(content="subagent done", tool_call_id="t-1")

    result = asyncio.run(mw.awrap_tool_call(_req(name="task", call_id="t-1"), exempt))
    assert result.content == "subagent done"


def test_zero_disables_the_backstop():
    mw = ToolTimeoutMiddleware(timeout_seconds=0)

    async def fast(_request):
        return ToolMessage(content="ok", tool_call_id="call-1")

    assert asyncio.run(mw.awrap_tool_call(_req(), fast)).content == "ok"
