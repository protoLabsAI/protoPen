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
        expected = {"sip_enum", "sip_crack", "sip_flood_test", "imsi_detect"}
        assert set(tool.ACTIONS.keys()) == expected


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


class TestSIP:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_sip_enum(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("sip_enum", target="10.0.0.2")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "sipvicious_svmap"

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_sip_crack(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("sip_crack", target="10.0.0.2", username="admin")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "sipvicious_svcrack"
        assert "admin" in cmd


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
        result = await tool.execute("sip_enum", target="10.0.0.1")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
