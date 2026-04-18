"""Parser for traffic_analysis tool output.

Ingests credential findings and flow data into target_store.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

logger = logging.getLogger(__name__)


def parse_cleartext_harvest(raw: str, store: "TargetStore") -> list[dict]:
    """Ingest cleartext credentials into target_store via add_credential."""
    entities: list[dict] = []
    if not raw:
        return entities
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return entities

    for finding in data.get("findings", []):
        protocol = finding.get("protocol", "")
        src = finding.get("src_ip", "")
        dst = finding.get("dst_ip", "")
        username = finding.get("username", "") or finding.get("credentials", "").split(":")[0]
        password = finding.get("password", "") or (
            ":".join(finding.get("credentials", "").split(":")[1:])
            if ":" in finding.get("credentials", "")
            else finding.get("credentials", "")
        )
        notes = json.dumps({k: v for k, v in finding.items() if k not in ("src_ip", "dst_ip")})
        try:
            store.add_credential(
                username=username,
                password=password,
                source=f"traffic_analysis/cleartext_harvest:{protocol}",
                notes=notes,
            )
        except Exception:
            pass
        entities.append({"type": "credential", "protocol": protocol, "src": src, "dst": dst})
    return entities


def parse_pcap_parse(raw: str, store: "TargetStore") -> list[dict]:
    """Ingest hosts discovered in flows into target_store."""
    entities: list[dict] = []
    if not raw:
        return entities
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return entities

    flows = data.get("flows", {})
    seen_hosts: set[str] = set()
    for proto_flows in (flows.get("tcp", []), flows.get("udp", [])):
        for flow in proto_flows:
            for key in ("src", "dst"):
                ip = flow.get(key, "")
                if ip and ip not in seen_hosts:
                    seen_hosts.add(ip)
                    try:
                        store.upsert_host(
                            ip=ip,
                            tags=["traffic_analysis"],
                            notes="discovered via pcap flow analysis",
                        )
                    except Exception:
                        pass
                    entities.append({"type": "host", "ip": ip})
    return entities


def parse_pcap_capture(raw: str, store: "TargetStore") -> list[dict]:
    """No structured entities to ingest from a live capture."""
    return []


def parse_session_reconstruct(raw: str, store: "TargetStore") -> list[dict]:
    """Ingest HTTP sessions with authorization headers as credentials."""
    entities: list[dict] = []
    if not raw:
        return entities
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return entities

    for session in data.get("http_sessions", []):
        auth = session.get("authorization", "")
        if not auth:
            continue
        host = session.get("host", "unknown")
        uri = session.get("uri", "")
        try:
            store.add_credential(
                username="",
                password="",
                source="traffic_analysis/session_reconstruct",
                notes=json.dumps({"host": host, "uri": uri, "authorization": auth}),
            )
        except Exception:
            pass
        entities.append({"type": "http_credential", "host": host, "uri": uri})
    return entities


def parse_tls_intercept(raw: str, store: "TargetStore") -> list[dict]:
    """Record intercepted TLS flow hosts."""
    entities: list[dict] = []
    if not raw:
        return entities
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return entities

    target = data.get("target_ip", "")
    if target:
        try:
            store.upsert_host(
                ip=target,
                tags=["tls_intercepted"],
                notes="device intercepted via traffic_analysis/tls_intercept",
            )
        except Exception:
            pass

    for flow in data.get("flows", []):
        url = flow.get("url", "")
        if url:
            entities.append({"type": "intercepted_url", "target": target, "url": url})
    return entities


PARSER_MAP[("traffic_analysis", "pcap_capture")] = parse_pcap_capture
PARSER_MAP[("traffic_analysis", "pcap_parse")] = parse_pcap_parse
PARSER_MAP[("traffic_analysis", "session_reconstruct")] = parse_session_reconstruct
PARSER_MAP[("traffic_analysis", "cleartext_harvest")] = parse_cleartext_harvest
PARSER_MAP[("traffic_analysis", "tls_intercept")] = parse_tls_intercept
