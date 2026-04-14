"""Tests for iot_protocol — mocked subprocess."""

from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.iot_protocol import IoTProtocolTool


@pytest.fixture
def tool():
    return IoTProtocolTool()


# ── Instantiation ────────────────────────────────────────────────────────────


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "iot_protocol"

    def test_actions_defined(self, tool):
        expected = {
            "mqtt_discover",
            "mqtt_pub_test",
            "mqtt_bruteforce",
            "coap_discover",
            "coap_get",
            "modbus_scan",
            "modbus_read",
            "bacnet_scan",
            "upnp_discover",
            "zigbee_sniff",
        }
        assert set(tool.ACTIONS.keys()) == expected


# ── Dispatch ─────────────────────────────────────────────────────────────────


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


# ── MQTT ─────────────────────────────────────────────────────────────────────


class TestMQTT:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_mqtt_discover(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"sensors/temp 23.5\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("mqtt_discover", target="192.168.1.100")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "mosquitto_sub"
        assert "192.168.1.100" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_mqtt_pub_test(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("mqtt_pub_test", target="192.168.1.100", topic="test/topic", message="hello")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "mosquitto_pub"
        assert "test/topic" in cmd
        assert "hello" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_mqtt_bruteforce(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Discovered credentials\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("mqtt_bruteforce", target="192.168.1.100", username="admin")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "ncrack"
        assert "mqtt://192.168.1.100" in cmd


# ── CoAP ─────────────────────────────────────────────────────────────────────


class TestCoAP:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_coap_discover(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"</temp>;rt=sensor,</light>;rt=sensor", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("coap_discover", target="192.168.1.50")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "coap-client"
        assert "coap://192.168.1.50/.well-known/core" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_coap_get(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"23.5", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("coap_get", target="192.168.1.50", resource="temp")
        cmd = mock_exec.call_args[0]
        assert "coap://192.168.1.50/temp" in cmd


# ── Modbus ───────────────────────────────────────────────────────────────────


class TestModbus:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_modbus_scan(self, mock_exec, tool):
        xml = '<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5"/><ports><port portid="502" protocol="tcp"><state state="open"/><script id="modbus-discover" output="Modbus device found"/></port></ports></host></nmaprun>'
        proc = AsyncMock()
        proc.communicate.return_value = (xml.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("modbus_scan", target="10.0.0.5")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "nmap"
        assert "502" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_modbus_read(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"100\n200\n300\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("modbus_read", target="10.0.0.5", slave_id=1, register=0, count=3)
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "modbus-cli"


# ── BACnet / UPnP ───────────────────────────────────────────────────────────


class TestBACnetUPnP:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_bacnet_scan(self, mock_exec, tool):
        xml = '<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.10"/></host></nmaprun>'
        proc = AsyncMock()
        proc.communicate.return_value = (xml.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("bacnet_scan", target="10.0.0.10")
        cmd = mock_exec.call_args[0]
        assert "47808" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_upnp_discover(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'<?xml version="1.0"?><nmaprun></nmaprun>', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("upnp_discover", target="192.168.1.0/24")
        cmd = mock_exec.call_args[0]
        assert "1900" in cmd


# ── Zigbee ───────────────────────────────────────────────────────────────────


class TestZigbee:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_zigbee_sniff(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Capturing on channel 15...\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("zigbee_sniff", channel=15, path="/tmp/cap.pcap")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "zbdump"
        assert "15" in cmd


# ── Binary not found ─────────────────────────────────────────────────────────


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("mqtt_discover", target="192.168.1.1")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
