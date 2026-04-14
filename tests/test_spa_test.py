"""Tests for spa_test — mocked subprocess."""
from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.spa_test import SPATestTool


@pytest.fixture
def tool():
    return SPATestTool()


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "spa_test"

    def test_actions_defined(self, tool):
        expected = {
            "route_bypass", "state_inspect", "postmessage_scan",
            "token_leakage_audit", "dom_xss_scan", "js_source_map_check",
        }
        assert set(tool.ACTIONS.keys()) == expected


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


class TestRouteBypass:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_route_bypass(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"bypassed_routes":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("route_bypass", target="https://app.example.com")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "python3"
        assert "protopen_scripts.spa_route_bypass" in cmd
        assert "https://app.example.com" in cmd


class TestStateInspect:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_state_inspect(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"exposed_state":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("state_inspect", target="https://app.example.com", store_type="vuex")
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.spa_state" in cmd
        assert "vuex" in cmd


class TestPostmessageScan:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_postmessage_scan(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"handlers":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("postmessage_scan", target="https://app.example.com")
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.postmessage_scan" in cmd


class TestTokenLeakageAudit:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_token_leakage_audit(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"leaks":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("token_leakage_audit", target="https://app.example.com")
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.token_leakage" in cmd


class TestDomXssScan:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_dom_xss_scan(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"sinks":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("dom_xss_scan", target="https://app.example.com")
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.dom_xss" in cmd


class TestSourceMapCheck:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_js_source_map_check(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"exposed_maps":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("js_source_map_check", target="https://app.example.com")
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.sourcemap_check" in cmd


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("route_bypass", target="https://app.example.com")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
