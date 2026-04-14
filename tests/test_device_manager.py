"""Tests for device manager — USB device discovery, connection lifecycle, health checks."""

import pytest
from unittest.mock import patch, MagicMock
import json

from tools.device_manager import DeviceManager, DeviceConnection, DeviceStatus


@pytest.fixture
def config():
    with open("config/engagement-config.json") as f:
        return json.load(f)


@pytest.fixture
def manager(config):
    return DeviceManager(config["devices"])


class TestDeviceDiscovery:
    def test_list_known_devices(self, manager):
        devices = manager.list_devices()
        assert "portapack" in devices
        assert "flipper" in devices
        assert "marauder" in devices
        assert "wifi_adapter" in devices

    @patch("tools.device_manager.serial.Serial")
    def test_connect_serial_device(self, mock_serial, manager):
        mock_serial.return_value.is_open = True
        conn = manager.connect("portapack")
        assert conn is not None
        assert conn.is_connected

    @patch("tools.device_manager.serial.Serial")
    def test_connect_nonexistent_device_raises(self, mock_serial, manager):
        with pytest.raises(KeyError):
            manager.connect("nonexistent")

    @patch("tools.device_manager.serial.Serial")
    def test_disconnect(self, mock_serial, manager):
        mock_serial.return_value.is_open = True
        manager.connect("portapack")
        manager.disconnect("portapack")
        assert not manager.is_connected("portapack")

    @patch("tools.device_manager.serial.Serial")
    def test_health_check_connected(self, mock_serial, manager):
        mock_serial.return_value.is_open = True
        mock_serial.return_value.read_until.return_value = b"ch>"
        manager.connect("portapack")
        status = manager.health_check("portapack")
        assert status.connected is True

    def test_health_check_disconnected(self, manager):
        status = manager.health_check("portapack")
        assert status.connected is False


class TestDeviceStatus:
    def test_status_dataclass(self):
        status = DeviceStatus(name="portapack", connected=True, port="/dev/ttyACM0", error=None)
        assert status.name == "portapack"
        assert status.connected is True

    def test_all_devices_status(self, manager):
        statuses = manager.all_status()
        assert len(statuses) == 4
        assert all(s.connected is False for s in statuses)


class TestDeviceConnection:
    def test_is_connected_true(self):
        mock_ser = MagicMock()
        mock_ser.is_open = True
        conn = DeviceConnection(name="test", port="/dev/tty0", ser=mock_ser, prompt=">")
        assert conn.is_connected is True

    def test_is_connected_false_none(self):
        conn = DeviceConnection(name="test", port="/dev/tty0", ser=None, prompt=">")
        assert conn.is_connected is False

    def test_send_strips_echo_and_prompt(self):
        mock_ser = MagicMock()
        mock_ser.is_open = True
        mock_ser.read_until.return_value = b"mycommand\r\nsome output\r\n>"
        conn = DeviceConnection(name="test", port="/dev/tty0", ser=mock_ser, prompt=">")
        result = conn.send("mycommand")
        mock_ser.write.assert_called_with(b"mycommand\r\n")
        assert "some output" in result

    def test_close(self):
        mock_ser = MagicMock()
        mock_ser.is_open = True
        conn = DeviceConnection(name="test", port="/dev/tty0", ser=mock_ser)
        conn.close()
        mock_ser.close.assert_called_once()
