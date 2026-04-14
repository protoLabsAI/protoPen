"""Tests for ipv6_attack — mocked subprocess."""
from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.ipv6_attack import IPv6AttackTool


@pytest.fixture
def tool():
    return IPv6AttackTool()


# ── Instantiation ────────────────────────────────────────────────────────────

class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "ipv6_attack"

    def test_actions_defined(self, tool):
        expected = {
            "alive6", "detect_sniffer6", "dos_new_ip6", "fake_router6",
            "flood_router6", "parasite6", "redir6", "nmap_ipv6", "thcping6",
        }
        assert set(tool.ACTIONS.keys()) == expected


# ── Dispatch ─────────────────────────────────────────────────────────────────

class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


# ── alive6 ───────────────────────────────────────────────────────────────────

class TestAlive6:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_alive6(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"fe80::1\nfe80::2\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("alive6", interface="eth0")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "alive6"
        assert "eth0" in cmd


# ── detect-sniffer6 ──────────────────────────────────────────────────────────

class TestDetectSniffer6:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_detect_sniffer6(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"No sniffers detected\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("detect_sniffer6", interface="eth0")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "detect-sniffer6"


# ── fake_router6 ─────────────────────────────────────────────────────────────

class TestFakeRouter6:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_fake_router6(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Sending RA...\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("fake_router6", interface="eth0", network="2001:db8::/64")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "fake_router6"
        assert "2001:db8::/64" in cmd


# ── redir6 ───────────────────────────────────────────────────────────────────

class TestRedir6:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_redir6(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Redirecting...\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "redir6", interface="eth0", target="fe80::1",
            router="fe80::ff", new_router="fe80::evil",
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "redir6"
        assert "fe80::1" in cmd
        assert "fe80::evil" in cmd


# ── nmap_ipv6 ────────────────────────────────────────────────────────────────

class TestNmapIPv6:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_nmap_ipv6(self, mock_exec, tool):
        xml = '<?xml version="1.0"?><nmaprun><host><address addr="::1" addrtype="ipv6"/></host></nmaprun>'
        proc = AsyncMock()
        proc.communicate.return_value = (xml.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("nmap_ipv6", target="::1")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "nmap"
        assert "-6" in cmd
        assert "::1" in cmd


# ── thcping6 ─────────────────────────────────────────────────────────────────

class TestThcping6:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_thcping6(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Reply from fe80::1\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("thcping6", interface="eth0", target="fe80::1")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "thcping6"
        assert "fe80::1" in cmd


# ── Binary not found ─────────────────────────────────────────────────────────

class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("alive6", interface="eth0")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
