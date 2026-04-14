"""Parser for gRPC audit output — grpcurl, grpc-fuzz, protoscan."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_grpc_reflection(raw: str, store: "TargetStore") -> list[dict]:
    """Parse grpcurl list output — one service per line."""
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        entities.append({
            "type": "grpc_finding",
            "check": "grpc_reflection",
            "target": "",
            "severity": "medium",
            "service": line,
            "value": f"Reflected service: {line}",
        })
    return entities


def parse_grpc_describe(raw: str, store: "TargetStore") -> list[dict]:
    """Parse grpcurl describe output."""
    if not raw.strip():
        return []
    return [{
        "type": "grpc_finding",
        "check": "grpc_describe",
        "target": "",
        "severity": "info",
        "value": raw.strip()[:500],
    }]


def parse_grpc_call(raw: str, store: "TargetStore") -> list[dict]:
    """Parse grpcurl call JSON response."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
        entities.append({
            "type": "grpc_finding",
            "check": "grpc_call",
            "target": "",
            "severity": "info",
            "value": json.dumps(data)[:500],
        })
    except json.JSONDecodeError:
        if raw.strip():
            entities.append({
                "type": "grpc_finding",
                "check": "grpc_call",
                "target": "",
                "severity": "info",
                "value": raw.strip()[:500],
            })
    return entities


def parse_grpc_fuzz(raw: str, store: "TargetStore") -> list[dict]:
    """Parse grpc-fuzz JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    results = data if isinstance(data, list) else data.get("results", [data])
    for r in results:
        entities.append({
            "type": "grpc_finding",
            "check": "grpc_fuzz",
            "target": "",
            "severity": r.get("severity", "medium"),
            "service": r.get("service", ""),
            "method": r.get("method", ""),
            "value": r.get("message", str(r)[:200]),
        })
    return entities


def parse_grpc_auth_test(raw: str, store: "TargetStore") -> list[dict]:
    """Parse grpcurl auth test — check if unauthenticated access succeeded."""
    entities: list[dict] = []
    raw_s = raw.strip()
    if not raw_s:
        return entities
    # If we got a valid response without auth, that's a finding
    auth_bypass = "Unauthenticated" not in raw_s and "PermissionDenied" not in raw_s
    entities.append({
        "type": "grpc_finding",
        "check": "grpc_auth_test",
        "target": "",
        "severity": "critical" if auth_bypass else "info",
        "value": "Auth bypass — method accessible without credentials" if auth_bypass else raw_s[:300],
    })
    return entities


def parse_grpc_tls_check(raw: str, store: "TargetStore") -> list[dict]:
    """Parse grpcurl TLS check — if plaintext=false call succeeds, TLS works."""
    entities: list[dict] = []
    raw_s = raw.strip()
    if not raw_s:
        return entities
    tls_ok = "Failed to dial" not in raw_s and "connection refused" not in raw_s.lower()
    entities.append({
        "type": "grpc_finding",
        "check": "grpc_tls_check",
        "target": "",
        "severity": "info" if tls_ok else "high",
        "value": "TLS enforced" if tls_ok else f"TLS issue: {raw_s[:200]}",
    })
    return entities


def parse_protoscan(raw: str, store: "TargetStore") -> list[dict]:
    """Parse protoscan JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    results = data if isinstance(data, list) else data.get("endpoints", [data])
    for r in results:
        entities.append({
            "type": "grpc_finding",
            "check": "protoscan",
            "target": r.get("host", r.get("target", "")),
            "severity": "medium",
            "service": r.get("service", ""),
            "value": r.get("message", str(r)[:200]),
        })
    return entities


PARSER_MAP[("grpc_audit", "grpc_reflection")] = parse_grpc_reflection
PARSER_MAP[("grpc_audit", "grpc_describe")] = parse_grpc_describe
PARSER_MAP[("grpc_audit", "grpc_call")] = parse_grpc_call
PARSER_MAP[("grpc_audit", "grpc_fuzz")] = parse_grpc_fuzz
PARSER_MAP[("grpc_audit", "grpc_auth_test")] = parse_grpc_auth_test
PARSER_MAP[("grpc_audit", "grpc_tls_check")] = parse_grpc_tls_check
PARSER_MAP[("grpc_audit", "grpc_web_test")] = parse_grpc_call
PARSER_MAP[("grpc_audit", "protoscan")] = parse_protoscan
