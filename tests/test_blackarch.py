"""Tests for BlackArch curated tool wrappers — mocked subprocess."""
import pytest
from unittest.mock import patch, AsyncMock

from tools.blackarch import BlackArchTool


@pytest.fixture
def tool():
    return BlackArchTool(wifi_interface="wlan1", monitor_interface="wlan1mon")


class TestNmap:
    @patch("tools.blackarch.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_nmap_scan(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"<nmaprun>...</nmaprun>", b"")
        proc.returncode = 0
        mock_proc.return_value = proc
        result = await tool.nmap_scan("192.168.1.0/24")
        assert "nmaprun" in result

    @patch("tools.blackarch.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_nmap_scan_with_ports(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"<nmaprun></nmaprun>", b"")
        proc.returncode = 0
        mock_proc.return_value = proc
        await tool.nmap_scan("192.168.1.1", ports="22,80,443")
        call_args = mock_proc.call_args[0]
        assert "-p" in call_args
        assert "22,80,443" in call_args


class TestAircrack:
    @patch("tools.blackarch.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_start_monitor(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"monitor mode enabled on wlan1mon", b"")
        proc.returncode = 0
        mock_proc.return_value = proc
        result = await tool.airmon_start()
        assert "monitor" in result

    @patch("tools.blackarch.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_stop_monitor(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"stopped", b"")
        proc.returncode = 0
        mock_proc.return_value = proc
        result = await tool.airmon_stop()
        assert "stopped" in result


class TestShellExec:
    @patch("tools.blackarch.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_shell_exec_allowed(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"output", b"")
        proc.returncode = 0
        mock_proc.return_value = proc
        result = await tool.shell_exec("tshark -i wlan1mon -c 10")
        assert "output" in result

    @pytest.mark.asyncio
    async def test_shell_exec_blocked_rm(self, tool):
        result = await tool.shell_exec("rm -rf /")
        assert "Blocked" in result

    @pytest.mark.asyncio
    async def test_shell_exec_blocked_dd(self, tool):
        result = await tool.shell_exec("dd if=/dev/zero of=/dev/sda")
        assert "Blocked" in result

    @pytest.mark.asyncio
    async def test_shell_exec_empty(self, tool):
        result = await tool.shell_exec("")
        assert "Empty" in result


class TestBettercap:
    @patch("tools.blackarch.asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_bettercap_recon(self, mock_proc, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"net.recon results", b"")
        proc.returncode = 0
        mock_proc.return_value = proc
        result = await tool.bettercap_recon("eth0")
        assert "net.recon" in result


class TestNanobotInterface:
    @pytest.mark.asyncio
    async def test_execute_dispatches(self, tool):
        with patch("tools.blackarch.asyncio.create_subprocess_exec") as mock_proc:
            proc = AsyncMock()
            proc.communicate.return_value = (b"<nmaprun></nmaprun>", b"")
            proc.returncode = 0
            mock_proc.return_value = proc
            result = await tool.execute(action="nmap_scan", target="192.168.1.1")
            assert "nmaprun" in result

    @pytest.mark.asyncio
    async def test_execute_unknown(self, tool):
        result = await tool.execute(action="nonexistent")
        assert "Unknown action" in result

    def test_has_name(self, tool):
        assert tool.name == "blackarch"
