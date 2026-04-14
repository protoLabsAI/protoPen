"""Tests for iot_protocol parsers."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from tools.parsers.iot_protocol import (
    parse_mqtt_discover,
    parse_mqtt_pub,
    parse_mqtt_bruteforce,
    parse_coap_discover,
    parse_coap_get,
    parse_modbus_scan,
    parse_modbus_read,
    parse_bacnet_scan,
    parse_upnp_discover,
    parse_zigbee_sniff,
)


@pytest.fixture
def store():
    return MagicMock()


# ── MQTT discover ────────────────────────────────────────────────────────────

class TestParseMqttDiscover:
    def test_messages(self, store):
        raw = "sensors/temp 23.5\nsensors/humidity 65\n"
        entities = parse_mqtt_discover(raw, store)
        assert len(entities) == 2
        assert entities[0]["type"] == "iot_finding"
        assert entities[0]["topic"] == "sensors/temp"
        assert entities[0]["payload"] == "23.5"

    def test_empty(self, store):
        assert parse_mqtt_discover("", store) == []


# ── MQTT pub ─────────────────────────────────────────────────────────────────

class TestParseMqttPub:
    def test_success(self, store):
        entities = parse_mqtt_pub("", store)
        assert len(entities) == 1
        assert "succeeded" in entities[0]["value"]
        assert entities[0]["severity"] == "medium"

    def test_error(self, store):
        entities = parse_mqtt_pub("Error: Connection refused", store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "info"


# ── MQTT bruteforce ──────────────────────────────────────────────────────────

class TestParseMqttBruteforce:
    def test_creds_found(self, store):
        raw = "Discovered credentials for mqtt://192.168.1.1\nadmin password: secret\n"
        entities = parse_mqtt_bruteforce(raw, store)
        assert len(entities) >= 1
        assert entities[0]["severity"] == "critical"

    def test_no_creds(self, store):
        assert parse_mqtt_bruteforce("Scan complete\n", store) == []


# ── CoAP discover ────────────────────────────────────────────────────────────

class TestParseCoapDiscover:
    def test_resources(self, store):
        raw = "</temp>;ct=0;rt=sensor,</light>;ct=0"
        entities = parse_coap_discover(raw, store)
        assert len(entities) == 2
        assert entities[0]["resource"] == "/temp"
        assert entities[1]["resource"] == "/light"

    def test_empty(self, store):
        assert parse_coap_discover("", store) == []


# ── CoAP get ─────────────────────────────────────────────────────────────────

class TestParseCoapGet:
    def test_response(self, store):
        entities = parse_coap_get("23.5", store)
        assert len(entities) == 1
        assert entities[0]["value"] == "23.5"

    def test_empty(self, store):
        assert parse_coap_get("", store) == []


# ── Modbus scan ──────────────────────────────────────────────────────────────

class TestParseModbusScan:
    def test_nmap_xml(self, store):
        raw = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5"/>
    <ports>
      <port portid="502" protocol="tcp">
        <state state="open"/>
        <script id="modbus-discover" output="Modbus device ID: PLC-01"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        entities = parse_modbus_scan(raw, store)
        assert len(entities) == 1
        assert entities[0]["protocol"] == "modbus"
        assert "PLC-01" in entities[0]["value"]

    def test_invalid_xml(self, store):
        assert parse_modbus_scan("not xml", store) == []


# ── Modbus read ──────────────────────────────────────────────────────────────

class TestParseModbusRead:
    def test_registers(self, store):
        raw = "100\n200\n300\n"
        entities = parse_modbus_read(raw, store)
        assert len(entities) == 3

    def test_empty(self, store):
        assert parse_modbus_read("", store) == []


# ── BACnet scan ──────────────────────────────────────────────────────────────

class TestParseBacnetScan:
    def test_device_found(self, store):
        raw = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.10"/>
    <ports>
      <port portid="47808" protocol="udp">
        <state state="open"/>
        <script id="bacnet-info" output="BACnet device: HVAC Controller"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        entities = parse_bacnet_scan(raw, store)
        assert len(entities) == 1
        assert entities[0]["protocol"] == "bacnet"

    def test_invalid(self, store):
        assert parse_bacnet_scan("not xml", store) == []


# ── UPnP discover ────────────────────────────────────────────────────────────

class TestParseUpnpDiscover:
    def test_device(self, store):
        raw = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1"/>
    <ports>
      <port portid="1900" protocol="udp">
        <state state="open"/>
        <script id="upnp-info" output="UPnP device: Router"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        entities = parse_upnp_discover(raw, store)
        assert len(entities) == 1
        assert entities[0]["protocol"] == "upnp"


# ── Zigbee sniff ─────────────────────────────────────────────────────────────

class TestParseZigbeeSniff:
    def test_capture_info(self, store):
        entities = parse_zigbee_sniff("Capturing on channel 15...", store)
        assert len(entities) == 1
        assert entities[0]["protocol"] == "zigbee"

    def test_empty(self, store):
        assert parse_zigbee_sniff("", store) == []
