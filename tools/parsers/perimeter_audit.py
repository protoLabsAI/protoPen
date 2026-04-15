"""Parser for perimeter_audit tool output."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_PORT_RE = re.compile(r'(\d+)/(tcp|udp)')


def parse_router_fingerprint(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    for ip in _IP_RE.findall(raw):
        store.upsert_host(ip=ip, tags=["router", "gateway"])
        entities.append({"type": "host", "ip": ip, "role": "router"})
    title_m = re.search(r'(?:HTTP|HTTPS) title:\s*(.+)', raw)
    if title_m:
        entities.append({"type": "finding", "severity": "info", "title": f"Router web UI: {title_m.group(1).strip()}"})
    return entities


def parse_upnp_discover(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    for ip in _IP_RE.findall(raw):
        store.upsert_host(ip=ip, tags=["upnp"])
        entities.append({"type": "host", "ip": ip, "service": "upnp"})
    if "uuid" in raw.lower() or "upnp" in raw.lower():
        entities.append({"type": "finding", "severity": "info", "title": "UPnP devices found on network"})
    return entities


def parse_upnp_portmap(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    # Extract port mappings
    for line in raw.splitlines():
        port_m = re.search(r'(\d+)\s+->\s+([\d.]+):(\d+)', line)
        if port_m:
            wan_port, lan_ip, lan_port = port_m.groups()
            entities.append({
                "type": "port_forward",
                "wan_port": int(wan_port),
                "lan_ip": lan_ip,
                "lan_port": int(lan_port),
            })
            store.upsert_host(ip=lan_ip, tags=["port_forwarded"])
    return entities


def parse_upnp_add_portmap(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    if "FINDING" in raw or "success" in raw.lower():
        entities.append({
            "type": "finding",
            "severity": "high",
            "title": "UPnP IGD accepts unauthenticated port mapping — WAN exposure possible",
            "detail": raw[:300],
        })
    return entities


def parse_default_creds(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    if "VALID:" in raw:
        for line in raw.splitlines():
            if "VALID:" in line:
                entities.append({
                    "type": "finding",
                    "severity": "critical",
                    "title": "Router default credentials accepted",
                    "detail": line.strip(),
                })
    return entities


def parse_routersploit_scan(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    for line in raw.splitlines():
        if "[+]" in line or "vulnerable" in line.lower():
            entities.append({
                "type": "finding",
                "severity": "critical",
                "title": f"RouterSploit: {line.strip()[:150]}",
            })
    return entities


def parse_wan_portscan(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    for ip in _IP_RE.findall(raw):
        store.upsert_host(ip=ip, tags=["wan", "external"])
    for port, proto in _PORT_RE.findall(raw):
        entities.append({"type": "service", "port": int(port), "protocol": proto, "exposure": "wan"})
    return entities


def parse_dns_rebind_check(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    if "VULNERABLE" in raw:
        entities.append({
            "type": "finding",
            "severity": "high",
            "title": "DNS rebinding protection inactive",
            "detail": raw[:300],
        })
    return entities


def parse_firewall_egress(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    concerning_ports = {"4444": "Metasploit", "6667": "IRC", "9001": "Tor", "23": "Telnet", "25": "SMTP"}
    for port, name in concerning_ports.items():
        if f"OPEN  {port}" in raw:
            entities.append({
                "type": "finding",
                "severity": "medium",
                "title": f"Concerning egress port open: {port} ({name})",
            })
    return entities


def parse_full_perimeter(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    for fn in [
        parse_router_fingerprint, parse_upnp_discover, parse_upnp_portmap,
        parse_default_creds, parse_dns_rebind_check, parse_firewall_egress,
    ]:
        entities.extend(fn(raw, store))
    return entities


PARSER_MAP[("perimeter_audit", "router_fingerprint")] = parse_router_fingerprint
PARSER_MAP[("perimeter_audit", "upnp_discover")] = parse_upnp_discover
PARSER_MAP[("perimeter_audit", "upnp_portmap")] = parse_upnp_portmap
PARSER_MAP[("perimeter_audit", "upnp_add_portmap")] = parse_upnp_add_portmap
PARSER_MAP[("perimeter_audit", "default_creds")] = parse_default_creds
PARSER_MAP[("perimeter_audit", "routersploit_scan")] = parse_routersploit_scan
PARSER_MAP[("perimeter_audit", "wan_portscan")] = parse_wan_portscan
PARSER_MAP[("perimeter_audit", "dns_rebind_check")] = parse_dns_rebind_check
PARSER_MAP[("perimeter_audit", "firewall_egress")] = parse_firewall_egress
PARSER_MAP[("perimeter_audit", "full_perimeter")] = parse_full_perimeter
