"""Tests for EnforcementMiddleware — the central enforcement gate.

All tests mock the engagement_manager and handler to avoid needing
a real LangGraph agent. Stubs langchain since it's not installed locally.
"""
import sys
from types import ModuleType
from unittest.mock import MagicMock, AsyncMock

import pytest

# ── Stub langchain if not installed ──────────────────────────────
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

from graph.middleware.enforcement import EnforcementMiddleware
from enforcement.scope import ScopeValidator
from enforcement.phases import KillChainPhase
from enforcement.rate_limiter import RateLimiter


def _make_request(tool_name: str, args: dict = None):
    """Build a mock middleware request with tool_call dict."""
    req = MagicMock()
    req.tool_call = {"name": tool_name, "args": args or {}}
    return req


def _make_engagement_manager(active=True, mode_name="ACTIVE", mode_value=1):
    """Build a mock EngagementManager."""
    mgr = MagicMock()
    mgr.active_engagement = {"name": "test"} if active else None
    mgr.mode = MagicMock()
    mgr.mode.name = mode_name
    mgr.mode.value = mode_value
    mgr.is_allowed = MagicMock(return_value=True)
    return mgr


class TestNonPentestToolsPassThrough:
    @pytest.mark.asyncio
    async def test_generic_tool_passes(self):
        """Non-pentest tools pass through without engagement."""
        mgr = _make_engagement_manager(active=False)
        mw = EnforcementMiddleware(mgr)
        req = _make_request("knowledge_search", {"query": "log4j"})
        handler = AsyncMock(return_value="results")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once_with(req)
        assert result == "results"

    @pytest.mark.asyncio
    async def test_browser_passes(self):
        mgr = _make_engagement_manager(active=False)
        mw = EnforcementMiddleware(mgr)
        req = _make_request("browser", {"action": "open", "url": "https://example.com"})
        handler = AsyncMock(return_value="ok")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()
        assert result == "ok"


class TestEngagementRequired:
    @pytest.mark.asyncio
    async def test_nmap_blocked_without_engagement(self):
        mgr = _make_engagement_manager(active=False)
        mw = EnforcementMiddleware(mgr)
        req = _make_request("nmap_scan", {"target": "192.168.1.1"})
        handler = AsyncMock()
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_not_awaited()
        assert "BLOCKED" in result
        assert "engagement" in result.lower()

    @pytest.mark.asyncio
    async def test_engagement_tool_itself_is_exempt(self):
        mgr = _make_engagement_manager(active=False)
        mw = EnforcementMiddleware(mgr)
        req = _make_request("engagement", {"action": "start", "name": "test"})
        handler = AsyncMock(return_value="started")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()
        assert result == "started"


class TestModeEnforcement:
    @pytest.mark.asyncio
    async def test_mode_allows_tool(self):
        mgr = _make_engagement_manager()
        mgr.is_allowed.return_value = True
        mw = EnforcementMiddleware(mgr)
        req = _make_request("nmap_scan", {"target": "10.0.0.1"})
        handler = AsyncMock(return_value="scan results")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()
        assert result == "scan results"

    @pytest.mark.asyncio
    async def test_mode_blocks_tool(self):
        mgr = _make_engagement_manager()
        mgr.is_allowed.return_value = False
        mgr._tool_risk = {"wifi_deauth": 2}
        mw = EnforcementMiddleware(mgr)
        req = _make_request("wifi_deauth", {})
        handler = AsyncMock()
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_not_awaited()
        assert "BLOCKED" in result
        assert "mode" in result.lower()


class TestScopeEnforcement:
    @pytest.mark.asyncio
    async def test_target_in_scope_passes(self):
        mgr = _make_engagement_manager()
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        mw = EnforcementMiddleware(mgr, scope_validator=sv)
        req = _make_request("nmap_scan", {"target": "192.168.4.50"})
        handler = AsyncMock(return_value="scan output")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()
        assert result == "scan output"

    @pytest.mark.asyncio
    async def test_target_out_of_scope_blocked(self):
        mgr = _make_engagement_manager()
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        mw = EnforcementMiddleware(mgr, scope_validator=sv)
        req = _make_request("nmap_scan", {"target": "10.0.0.1"})
        handler = AsyncMock()
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_not_awaited()
        assert "BLOCKED" in result
        assert "scope" in result.lower()

    @pytest.mark.asyncio
    async def test_tool_without_target_skips_scope_check(self):
        mgr = _make_engagement_manager()
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        mw = EnforcementMiddleware(mgr, scope_validator=sv)
        req = _make_request("hashcat_crack", {"hash_file": "/tmp/hashes"})
        handler = AsyncMock(return_value="cracked")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()


class TestPhaseEnforcement:
    @pytest.mark.asyncio
    async def test_recon_tool_under_enum_ceiling(self):
        mgr = _make_engagement_manager()
        mw = EnforcementMiddleware(mgr, max_phase=KillChainPhase.ENUMERATION)
        req = _make_request("nmap_scan", {"target": "10.0.0.1"})
        handler = AsyncMock(return_value="scan")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_exploit_tool_blocked_by_enum_ceiling(self):
        mgr = _make_engagement_manager()
        mw = EnforcementMiddleware(mgr, max_phase=KillChainPhase.ENUMERATION)
        req = _make_request("wifi_deauth", {})
        handler = AsyncMock()
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_not_awaited()
        assert "BLOCKED" in result
        assert "phase" in result.lower()

    @pytest.mark.asyncio
    async def test_no_phase_ceiling_allows_all(self):
        mgr = _make_engagement_manager()
        mw = EnforcementMiddleware(mgr)
        req = _make_request("wifi_deauth", {})
        handler = AsyncMock(return_value="deauthed")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()


class TestRateLimitEnforcement:
    @pytest.mark.asyncio
    async def test_under_limit_passes(self):
        mgr = _make_engagement_manager()
        rl = RateLimiter({"nmap_scan": {"max": 10, "window_seconds": 3600}})
        mw = EnforcementMiddleware(mgr, rate_limiter=rl)
        req = _make_request("nmap_scan", {"target": "10.0.0.1"})
        handler = AsyncMock(return_value="result")
        result = await mw.awrap_tool_call(req, handler)
        handler.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_over_limit_blocked(self):
        mgr = _make_engagement_manager()
        rl = RateLimiter({"nmap_scan": {"max": 1, "window_seconds": 3600}})
        mw = EnforcementMiddleware(mgr, rate_limiter=rl)
        handler = AsyncMock(return_value="result")

        req1 = _make_request("nmap_scan", {"target": "10.0.0.1"})
        await mw.awrap_tool_call(req1, handler)
        req2 = _make_request("nmap_scan", {"target": "10.0.0.2"})
        result = await mw.awrap_tool_call(req2, handler)
        assert "BLOCKED" in result
        assert "rate" in result.lower()


class TestSyncMirror:
    def test_sync_passthrough(self):
        mgr = _make_engagement_manager(active=False)
        mw = EnforcementMiddleware(mgr)
        req = _make_request("knowledge_search", {"query": "test"})
        handler = MagicMock(return_value="results")
        result = mw.wrap_tool_call(req, handler)
        handler.assert_called_once_with(req)
        assert result == "results"

    def test_sync_blocks_pentest_without_engagement(self):
        mgr = _make_engagement_manager(active=False)
        mw = EnforcementMiddleware(mgr)
        req = _make_request("nmap_scan", {"target": "1.2.3.4"})
        handler = MagicMock()
        result = mw.wrap_tool_call(req, handler)
        handler.assert_not_called()
        assert "BLOCKED" in result


class TestEnforcementOrder:
    @pytest.mark.asyncio
    async def test_mode_checked_before_scope(self):
        """If mode blocks, scope is never checked."""
        mgr = _make_engagement_manager()
        mgr.is_allowed.return_value = False
        mgr._tool_risk = {"nmap_scan": 1}
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        mw = EnforcementMiddleware(mgr, scope_validator=sv)
        req = _make_request("nmap_scan", {"target": "192.168.4.1"})
        handler = AsyncMock()
        result = await mw.awrap_tool_call(req, handler)
        assert "BLOCKED" in result
        assert "mode" in result.lower()
