"""Parser for IPv6 attack output — THC-IPv6 tools, nmap IPv6."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_alive6(raw: str, store: "TargetStore") -> list[dict]:
    """Parse alive6 output — one IPv6 address per line."""
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("Alive:"):
            continue
        # Lines containing IPv6 addresses (with colons)
        match = re.search(r"([0-9a-fA-F:]{3,})", line)
        if match:
            entities.append({
                "type": "ipv6_finding",
                "target": match.group(1),
                "check": "alive6",
                "severity": "info",
                "value": f"Alive IPv6 host: {match.group(1)}",
            })
    return entities


def parse_detect_sniffer6(raw: str, store: "TargetStore") -> list[dict]:
    """Parse detect-sniffer6 output."""
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if "found" in line.lower() or "sniffer" in line.lower() or "detected" in line.lower():
            entities.append({
                "type": "ipv6_finding",
                "target": "",
                "check": "detect_sniffer6",
                "severity": "high",
                "value": line,
            })
    return entities


def parse_thc_text(raw: str, store: "TargetStore") -> list[dict]:
    """Generic parser for THC-IPv6 tools that produce text output."""
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        entities.append({
            "type": "ipv6_finding",
            "target": "",
            "check": "thc_ipv6",
            "severity": "info",
            "value": line,
        })
    return entities


def parse_nmap_ipv6(raw: str, store: "TargetStore") -> list[dict]:
    """Parse nmap -6 XML output."""
    entities: list[dict] = []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return entities

    for host in root.findall(".//host"):
        addr_el = host.find("address[@addrtype='ipv6']")
        if addr_el is None:
            addr_el = host.find("address")
        addr = addr_el.get("addr", "") if addr_el is not None else ""

        for port in host.findall(".//port"):
            port_id = port.get("portid", "")
            protocol = port.get("protocol", "")
            state_el = port.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            service_el = port.find("service")
            service = service_el.get("name", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""

            entities.append({
                "type": "ipv6_finding",
                "target": addr,
                "check": "nmap_ipv6",
                "severity": "info",
                "value": f"{port_id}/{protocol} {state} {service} {version}".strip(),
                "port": port_id,
                "protocol": protocol,
                "state": state,
                "service": service,
            })
    return entities


PARSER_MAP[("ipv6_attack", "alive6")] = parse_alive6
PARSER_MAP[("ipv6_attack", "detect_sniffer6")] = parse_detect_sniffer6
PARSER_MAP[("ipv6_attack", "dos_new_ip6")] = parse_thc_text
PARSER_MAP[("ipv6_attack", "fake_router6")] = parse_thc_text
PARSER_MAP[("ipv6_attack", "flood_router6")] = parse_thc_text
PARSER_MAP[("ipv6_attack", "parasite6")] = parse_thc_text
PARSER_MAP[("ipv6_attack", "redir6")] = parse_thc_text
PARSER_MAP[("ipv6_attack", "nmap_ipv6")] = parse_nmap_ipv6
PARSER_MAP[("ipv6_attack", "thcping6")] = parse_thc_text
