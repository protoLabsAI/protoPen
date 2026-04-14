"""Parser for network monitoring output — traffic baselines, host discovery, anomalies."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_traffic_baseline(raw: str, store: "TargetStore") -> list[dict]:
    """Parse traffic baseline capture into normalized findings."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    entities.append(
        {
            "type": "net_baseline",
            "interface": data.get("interface", ""),
            "duration_sec": data.get("duration_sec", 0),
            "packet_count": data.get("packet_count", 0),
            "total_bytes": data.get("total_bytes", 0),
            "top_hosts": data.get("top_hosts", {}),
            "top_ports": data.get("top_ports", {}),
        }
    )
    return entities


def parse_host_discovery(raw: str, store: "TargetStore") -> list[dict]:
    """Parse host discovery results, upsert new hosts and flag anomalies."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for host in data.get("hosts", []):
        ip = host.get("ip", "")
        hostname = host.get("hostname", "")
        if ip:
            store.upsert_host(ip=ip, hostname=hostname)

    for new_host in data.get("new_hosts", []):
        entities.append(
            {
                "type": "net_anomaly",
                "anomaly_type": "new_host",
                "severity": "high",
                "ip": new_host.get("ip", ""),
                "hostname": new_host.get("hostname", ""),
                "network": data.get("network", ""),
            }
        )
    return entities


def parse_service_diff(raw: str, store: "TargetStore") -> list[dict]:
    """Parse service diff results — new/removed services."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    target = data.get("target", "")
    for svc in data.get("new_services", []):
        entities.append(
            {
                "type": "net_anomaly",
                "anomaly_type": "new_service",
                "severity": "high",
                "target": target,
                "port": svc.get("port", 0),
                "service": svc.get("service", ""),
                "version": svc.get("version", ""),
            }
        )
    for svc in data.get("removed_services", []):
        entities.append(
            {
                "type": "net_anomaly",
                "anomaly_type": "removed_service",
                "severity": "medium",
                "target": target,
                "port": svc.get("port", 0),
                "service": svc.get("service", ""),
            }
        )
    return entities


def parse_dns_monitor(raw: str, store: "TargetStore") -> list[dict]:
    """Parse DNS monitoring for suspicious activity."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for item in data.get("suspicious", []):
        entities.append(
            {
                "type": "net_anomaly",
                "anomaly_type": f"dns_{item.get('type', 'unknown')}",
                "severity": "high",
                "domain": item.get("domain", ""),
                "note": item.get("note", ""),
            }
        )
    return entities


def parse_protocol_anomaly(raw: str, store: "TargetStore") -> list[dict]:
    """Parse protocol anomaly detection results."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for proto in data.get("unexpected_protocols", []):
        entities.append(
            {
                "type": "net_anomaly",
                "anomaly_type": "unexpected_protocol",
                "severity": "high",
                "protocol": proto.get("protocol", ""),
                "count": proto.get("count", 0),
            }
        )
    return entities


def parse_arp_watch(raw: str, store: "TargetStore") -> list[dict]:
    """Parse arp_watch output — flag ARP spoofing events as critical network attacks."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for item in data.get("suspicious", []):
        event_type = item.get("event_type", "arp_anomaly")
        entities.append(
            {
                "type": "network_attack",
                "anomaly_type": event_type,
                "severity": "critical",
                "interface": data.get("interface", ""),
                "ip": item.get("ip", ""),
                "mac": item.get("mac", ""),
                "count": item.get("count", 0),
                "note": (
                    "ARP spoofing detected: multiple MACs for same IP"
                    if event_type == "duplicate_ip_mac"
                    else "Gratuitous ARP flood detected: possible poisoning in progress"
                ),
            }
        )
    return entities


def parse_responder_detect(raw: str, store: "TargetStore") -> list[dict]:
    """Parse responder_detect output — flag LLMNR/NBT-NS responders as high-severity network attacks."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for resp in data.get("llmnr_responses", []):
        entities.append(
            {
                "type": "network_attack",
                "anomaly_type": "llmnr_responder",
                "severity": "high",
                "interface": data.get("interface", ""),
                "src_ip": resp.get("src_ip", ""),
                "domain": resp.get("domain", ""),
                "count": resp.get("count", 0),
                "note": "Host is sending LLMNR responses — likely Responder/poisoning tool active",
            }
        )

    for resp in data.get("nbns_responses", []):
        entities.append(
            {
                "type": "network_attack",
                "anomaly_type": "nbns_responder",
                "severity": "high",
                "interface": data.get("interface", ""),
                "src_ip": resp.get("src_ip", ""),
                "domain": resp.get("domain", ""),
                "count": resp.get("count", 0),
                "note": "Host is sending NBT-NS responses — likely Responder/poisoning tool active",
            }
        )

    return entities


def parse_rogue_dhcp_detect(raw: str, store: "TargetStore") -> list[dict]:
    """Parse rogue_dhcp_detect output — flag unauthorized DHCP servers as critical network attacks."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for srv in data.get("rogue_servers", []):
        entities.append(
            {
                "type": "network_attack",
                "anomaly_type": "rogue_dhcp_server",
                "severity": "critical",
                "interface": data.get("interface", ""),
                "ip": srv.get("ip", ""),
                "mac": srv.get("mac", ""),
                "note": "Rogue DHCP server detected: IP not in trusted server list",
            }
        )

    return entities


PARSER_MAP[("net_monitor", "traffic_baseline")] = parse_traffic_baseline
PARSER_MAP[("net_monitor", "host_discovery")] = parse_host_discovery
PARSER_MAP[("net_monitor", "service_diff")] = parse_service_diff
PARSER_MAP[("net_monitor", "dns_monitor")] = parse_dns_monitor
PARSER_MAP[("net_monitor", "protocol_anomaly")] = parse_protocol_anomaly
PARSER_MAP[("net_monitor", "arp_watch")] = parse_arp_watch
PARSER_MAP[("net_monitor", "responder_detect")] = parse_responder_detect
PARSER_MAP[("net_monitor", "rogue_dhcp_detect")] = parse_rogue_dhcp_detect
