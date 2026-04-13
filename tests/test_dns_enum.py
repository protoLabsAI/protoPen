"""Tests for DNS enumeration tool — mocked subprocess."""
import pytest
from unittest.mock import patch, AsyncMock

from tools.dns_enum import DnsEnumTool


@pytest.fixture
def tool():
    return DnsEnumTool()


class TestDigQuery:
    @patch("tools.dns_enum.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_basic_dig(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"example.com. 300 IN A 93.184.216.34", b"")
        mock_proc.return_value = proc
        result = await tool.dig_query("example.com")
        assert "93.184.216.34" in result
        call_args = mock_proc.call_args[0]
        assert "dig" in call_args
        assert "example.com" in call_args

    @patch("tools.dns_enum.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_dig_with_nameserver(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"result", b"")
        mock_proc.return_value = proc
        await tool.dig_query("example.com", nameserver="8.8.8.8")
        call_args = mock_proc.call_args[0]
        assert "@8.8.8.8" in call_args

    @patch("tools.dns_enum.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_dig_record_type(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"result", b"")
        mock_proc.return_value = proc
        await tool.dig_query("example.com", record_type="MX")
        call_args = mock_proc.call_args[0]
        assert "MX" in call_args


class TestZoneTransfer:
    @patch("tools.dns_enum.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_zone_transfer(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"AXFR records", b"")
        mock_proc.return_value = proc
        result = await tool.zone_transfer("example.com", nameserver="ns1.example.com")
        call_args = mock_proc.call_args[0]
        assert "AXFR" in call_args
        assert "@ns1.example.com" in call_args


class TestReverseLookup:
    @patch("tools.dns_enum.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_reverse_lookup(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"host.example.com", b"")
        mock_proc.return_value = proc
        result = await tool.reverse_lookup("93.184.216.34")
        call_args = mock_proc.call_args[0]
        assert "-x" in call_args
        assert "93.184.216.34" in call_args


class TestDnsBrute:
    @patch("tools.dns_enum.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_dns_brute(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"found subdomains", b"")
        mock_proc.return_value = proc
        result = await tool.dns_brute("example.com")
        call_args = mock_proc.call_args[0]
        assert "dnsrecon" in call_args
        assert "-d" in call_args


class TestExecuteDispatch:
    @patch("tools.dns_enum.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_dispatches(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"result", b"")
        mock_proc.return_value = proc
        result = await tool.execute(action="dig_query", target="example.com")
        assert "result" in result

    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute(action="nonexistent", target="x")
        assert "Unknown action" in result

    def test_has_name(self, tool):
        assert tool.name == "dns_enum"
