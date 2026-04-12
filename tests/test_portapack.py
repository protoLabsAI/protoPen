"""Tests for PortaPack Mayhem serial bridge — mocked serial."""
import pytest
from unittest.mock import MagicMock

from tools.portapack import PortaPackTool
from tools.device_manager import DeviceConnection


@pytest.fixture
def mock_conn():
    conn = MagicMock(spec=DeviceConnection)
    conn.is_connected = True
    conn.name = "portapack"
    conn.prompt = "ch>"
    return conn


@pytest.fixture
def tool(mock_conn):
    return PortaPackTool(mock_conn)


class TestPortaPackCommands:
    def test_list_apps(self, tool, mock_conn):
        mock_conn.send.return_value = "recon\nscanner\nadsb_rx\npocsag_rx"
        result = tool.list_apps()
        mock_conn.send.assert_called_with("applist")
        assert "recon" in result

    def test_start_app(self, tool, mock_conn):
        mock_conn.send.return_value = "ok"
        tool.start_app("recon")
        mock_conn.send.assert_called_with("appstart recon")

    def test_set_frequency(self, tool, mock_conn):
        mock_conn.send.return_value = "ok"
        tool.set_frequency(433920000)
        mock_conn.send.assert_called_with("setfreq 433920000")

    def test_get_radio_info(self, tool, mock_conn):
        mock_conn.send.return_value = "Freq: 433920000\nBW: 1750000"
        info = tool.get_radio_info()
        mock_conn.send.assert_called_with("radioinfo")
        assert "433920000" in info

    def test_read_screen(self, tool, mock_conn):
        mock_conn.send.return_value = "Button: Start\nLabel: Recon"
        tool.read_screen()
        mock_conn.send.assert_called_with("accessibility_readall")

    def test_tap(self, tool, mock_conn):
        mock_conn.send.return_value = ""
        tool.tap(120, 160)
        mock_conn.send.assert_called_with("touch 120 160")

    def test_press_button(self, tool, mock_conn):
        mock_conn.send.return_value = ""
        tool.press_button(5)
        mock_conn.send.assert_called_with("button 5")

    def test_screenshot(self, tool, mock_conn):
        mock_conn.send.return_value = "AABBCC..."
        tool.screenshot()
        mock_conn.send.assert_called_with("screenframeshort")

    def test_system_info(self, tool, mock_conn):
        mock_conn.send.return_value = "Heap: 1234\nCPU: 45%"
        tool.system_info()
        mock_conn.send.assert_called_with("sysinfo")

    def test_send_command(self, tool, mock_conn):
        mock_conn.send.return_value = "ok"
        tool.send_command("custom_cmd")
        mock_conn.send.assert_called_with("custom_cmd")

    def test_file_list(self, tool, mock_conn):
        mock_conn.send.return_value = "file1.txt\nfile2.bin"
        tool.file_list("/SD")
        mock_conn.send.assert_called_with("ls /SD")

    def test_inject_gps(self, tool, mock_conn):
        mock_conn.send.return_value = "ok"
        tool.inject_gps(37.7749, -122.4194, 10, 5)
        mock_conn.send.assert_called_with("gotgps 37.7749 -122.4194 10 5")


class TestPortaPackNanobotInterface:
    @pytest.mark.asyncio
    async def test_execute_dispatches(self, tool, mock_conn):
        mock_conn.send.return_value = "recon\nscanner"
        result = await tool.execute(action="list_apps")
        assert "recon" in result

    @pytest.mark.asyncio
    async def test_execute_unknown_action(self, tool):
        result = await tool.execute(action="nonexistent")
        assert "Unknown action" in result

    def test_has_name(self, tool):
        assert tool.name == "portapack"

    def test_has_description(self, tool):
        assert "PortaPack" in tool.description
