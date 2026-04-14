"""Parser for IoT protocol testing output — MQTT, CoAP, Modbus, BACnet, UPnP, Zigbee."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_mqtt_discover(raw: str, store: "TargetStore") -> list[dict]:
    """Parse mosquitto_sub -v output: 'topic payload' per line."""
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        topic = parts[0] if parts else ""
        payload = parts[1] if len(parts) > 1 else ""
        entities.append({
            "type": "iot_finding",
            "protocol": "mqtt",
            "check": "mqtt_discover",
            "topic": topic,
            "payload": payload[:200],
            "severity": "info",
        })
    return entities


def parse_mqtt_pub(raw: str, store: "TargetStore") -> list[dict]:
    """Parse mosquitto_pub output (usually empty on success)."""
    entities: list[dict] = []
    raw = raw.strip()
    if not raw or "Error" not in raw:
        entities.append({
            "type": "iot_finding",
            "protocol": "mqtt",
            "check": "mqtt_pub_test",
            "severity": "medium",
            "value": "Publish succeeded — broker accepts unauthenticated writes" if not raw else raw,
        })
    else:
        entities.append({
            "type": "iot_finding",
            "protocol": "mqtt",
            "check": "mqtt_pub_test",
            "severity": "info",
            "value": raw,
        })
    return entities


def parse_mqtt_bruteforce(raw: str, store: "TargetStore") -> list[dict]:
    """Parse ncrack MQTT brute-force output."""
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        if "Discovered credentials" in line or "password:" in line.lower():
            entities.append({
                "type": "iot_finding",
                "protocol": "mqtt",
                "check": "mqtt_bruteforce",
                "severity": "critical",
                "value": line.strip(),
            })
    return entities


def parse_coap_discover(raw: str, store: "TargetStore") -> list[dict]:
    """Parse CoRE link format: </resource>;ct=0;rt='type'."""
    entities: list[dict] = []
    for segment in raw.split(","):
        segment = segment.strip()
        if not segment:
            continue
        match = re.match(r"<([^>]+)>", segment)
        resource = match.group(1) if match else segment
        entities.append({
            "type": "iot_finding",
            "protocol": "coap",
            "check": "coap_discover",
            "resource": resource,
            "severity": "info",
            "value": segment,
        })
    return entities


def parse_coap_get(raw: str, store: "TargetStore") -> list[dict]:
    """Parse CoAP GET response."""
    if not raw.strip():
        return []
    return [{
        "type": "iot_finding",
        "protocol": "coap",
        "check": "coap_get",
        "severity": "info",
        "value": raw.strip()[:500],
    }]


def _parse_nmap_iot(raw: str, store: "TargetStore", protocol: str, action: str) -> list[dict]:
    """Shared nmap XML parser for IoT protocols (Modbus, BACnet, UPnP)."""
    entities: list[dict] = []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return entities

    for host in root.findall(".//host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr", "") if addr_el is not None else ""

        for port in host.findall(".//port"):
            port_id = port.get("portid", "")
            state_el = port.find("state")
            state = state_el.get("state", "") if state_el is not None else ""

            script_output = ""
            for script in port.findall("script"):
                script_output += script.get("output", "")

            entities.append({
                "type": "iot_finding",
                "protocol": protocol,
                "check": action,
                "target": addr,
                "port": port_id,
                "state": state,
                "severity": "info" if state != "open" else "medium",
                "value": script_output[:300] if script_output else f"{port_id} {state}",
            })
    return entities


def parse_modbus_scan(raw: str, store: "TargetStore") -> list[dict]:
    return _parse_nmap_iot(raw, store, "modbus", "modbus_scan")


def parse_modbus_read(raw: str, store: "TargetStore") -> list[dict]:
    """Parse modbus-cli read output — register values."""
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        entities.append({
            "type": "iot_finding",
            "protocol": "modbus",
            "check": "modbus_read",
            "severity": "info",
            "value": line,
        })
    return entities


def parse_bacnet_scan(raw: str, store: "TargetStore") -> list[dict]:
    return _parse_nmap_iot(raw, store, "bacnet", "bacnet_scan")


def parse_upnp_discover(raw: str, store: "TargetStore") -> list[dict]:
    return _parse_nmap_iot(raw, store, "upnp", "upnp_discover")


def parse_zigbee_sniff(raw: str, store: "TargetStore") -> list[dict]:
    """Parse zbdump output — just capture file info."""
    if not raw.strip():
        return []
    return [{
        "type": "iot_finding",
        "protocol": "zigbee",
        "check": "zigbee_sniff",
        "severity": "info",
        "value": raw.strip()[:200],
    }]


PARSER_MAP[("iot_protocol", "mqtt_discover")] = parse_mqtt_discover
PARSER_MAP[("iot_protocol", "mqtt_pub_test")] = parse_mqtt_pub
PARSER_MAP[("iot_protocol", "mqtt_bruteforce")] = parse_mqtt_bruteforce
PARSER_MAP[("iot_protocol", "coap_discover")] = parse_coap_discover
PARSER_MAP[("iot_protocol", "coap_get")] = parse_coap_get
PARSER_MAP[("iot_protocol", "modbus_scan")] = parse_modbus_scan
PARSER_MAP[("iot_protocol", "modbus_read")] = parse_modbus_read
PARSER_MAP[("iot_protocol", "bacnet_scan")] = parse_bacnet_scan
PARSER_MAP[("iot_protocol", "upnp_discover")] = parse_upnp_discover
PARSER_MAP[("iot_protocol", "zigbee_sniff")] = parse_zigbee_sniff
