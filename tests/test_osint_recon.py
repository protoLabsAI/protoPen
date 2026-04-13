"""Tests for OSINT recon tool — mocked subprocess."""
import pytest
from unittest.mock import patch, AsyncMock

from tools.osint_recon import OsintReconTool


@pytest.fixture
def tool():
    return OsintReconTool()


class TestTheHarvester:
    @patch("tools.osint_recon.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_theharvester(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"theHarvester output", b"")
        mock_proc.return_value = proc
        result = await tool.theharvester("example.com")
        call_args = mock_proc.call_args[0]
        assert "theHarvester" in call_args
        assert "-d" in call_args

    @patch("tools.osint_recon.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_theharvester_source(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"output", b"")
        mock_proc.return_value = proc
        await tool.theharvester("example.com", source="google")
        call_args = mock_proc.call_args[0]
        assert "google" in call_args


class TestWhois:
    @patch("tools.osint_recon.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_whois(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Registrar: Example Inc", b"")
        mock_proc.return_value = proc
        result = await tool.whois_lookup("example.com")
        assert "Registrar" in result
        call_args = mock_proc.call_args[0]
        assert "whois" in call_args


class TestDispatch:
    @patch("tools.osint_recon.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_dispatches(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"result", b"")
        mock_proc.return_value = proc
        result = await tool.execute(action="whois_lookup", target="example.com")
        assert "result" in result

    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute(action="bad", target="x")
        assert "Unknown action" in result

    def test_has_name(self, tool):
        assert tool.name == "osint_recon"
