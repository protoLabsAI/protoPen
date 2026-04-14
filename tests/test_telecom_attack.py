"""Tests for telecom_attack — mocked subprocess."""
from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.telecom_attack import TelecomAttackTool


@pytest.fixture
def tool():
    return TelecomAttackTool()


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "telecom_attack"

    def test_actions_defined(self, tool):
        expected = {
            "gtp_scan", "gtp_fuzzer", "sip_enum", "sip_crack",
            "ss7_scan", "diameter_audit", "imsi_detect",
            "sip_flood_test", "stir_shaken_verify",
        }
        assert set(tool.ACTIONS.keys()) == expected


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


class TestGTP:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_gtp_scan(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"results":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("gtp_scan", target="10.0.0.1", port=2123)
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "gtp-scan"
        assert "10.0.0.1" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_gtp_fuzzer(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"results":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("gtp_fuzzer", target="10.0.0.1", count=500)
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "gtp-fuzzer"
        assert "500" in cmd


class TestSIP:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_sip_enum(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'[{"host":"10.0.0.2"}]', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("sip_enum", target="10.0.0.2")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "sipvicious_svmap"

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_sip_crack(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'[]', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("sip_crack", target="10.0.0.2", username="admin")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "sipvicious_svcrack"
        assert "admin" in cmd


class TestSS7:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_ss7_scan(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"results":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("ss7_scan", target="10.0.0.3")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "ss7-tools"


class TestIMSI:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_imsi_detect(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"ARFCN: 100, freq: 935.2\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("imsi_detect", device_args="rtl=0")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "grgsm_scanner"


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("gtp_scan", target="10.0.0.1")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
