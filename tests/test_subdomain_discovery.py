"""Tests for subdomain discovery tool — mocked subprocess."""
import pytest
from unittest.mock import patch, AsyncMock

from tools.subdomain_discovery import SubdomainDiscoveryTool


@pytest.fixture
def tool():
    return SubdomainDiscoveryTool()


class TestSubfinder:
    @patch("tools.subdomain_discovery.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_subfinder(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (
            b'{"host":"sub.example.com","ip":"1.2.3.4"}', b"",
        )
        mock_proc.return_value = proc
        result = await tool.subfinder("example.com")
        assert "sub.example.com" in result
        call_args = mock_proc.call_args[0]
        assert "subfinder" in call_args
        assert "-d" in call_args
        assert "-silent" in call_args


class TestAmass:
    @patch("tools.subdomain_discovery.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_amass_passive(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"name":"sub.example.com"}', b"")
        mock_proc.return_value = proc
        result = await tool.amass_passive("example.com")
        call_args = mock_proc.call_args[0]
        assert "amass" in call_args
        assert "-passive" in call_args


class TestDispatch:
    @patch("tools.subdomain_discovery.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_dispatches(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"results", b"")
        mock_proc.return_value = proc
        result = await tool.execute(action="subfinder", target="example.com")
        assert "results" in result

    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute(action="bad", target="x")
        assert "Unknown action" in result

    def test_has_name(self, tool):
        assert tool.name == "subdomain_discovery"
