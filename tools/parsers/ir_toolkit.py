"""Parser for incident response toolkit output — log search, IOC, auth, timeline."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_log_search(raw: str, store: "TargetStore") -> list[dict]:
    """Parse log search results."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    if data.get("match_count", 0) > 0:
        entities.append({
            "type": "ir_finding",
            "finding_type": "log_match",
            "severity": "info",
            "pattern": data.get("pattern", ""),
            "log_path": data.get("log_path", ""),
            "match_count": data.get("match_count", 0),
            "sample_matches": data.get("matches", [])[:5],
        })
    return entities


def parse_ioc_scan(raw: str, store: "TargetStore") -> list[dict]:
    """Parse IOC scan results — each hit is a finding."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for finding in data.get("findings", []):
        entities.append({
            "type": "ir_finding",
            "finding_type": "ioc_hit",
            "severity": "critical",
            "ioc_type": finding.get("ioc_type", "unknown"),
            "ioc_value": finding.get("ioc_value", ""),
            "file": finding.get("file", ""),
            "line": finding.get("line", 0),
            "context": finding.get("context", ""),
        })
    return entities


def parse_auth_log(raw: str, store: "TargetStore") -> list[dict]:
    """Parse auth log analysis for brute force and compromise indicators."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for bf in data.get("brute_force_detected", []):
        entities.append({
            "type": "ir_finding",
            "finding_type": "brute_force",
            "severity": bf.get("severity", "high"),
            "ip": bf.get("ip", ""),
            "attempts": bf.get("attempts", 0),
        })

    if data.get("compromised_likely"):
        for ip in data.get("success_after_brute_force", []):
            entities.append({
                "type": "ir_finding",
                "finding_type": "compromised_account",
                "severity": "critical",
                "ip": ip,
                "note": "Successful auth after brute-force attempts",
            })
    return entities


def parse_timeline(raw: str, store: "TargetStore") -> list[dict]:
    """Parse timeline build results."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    event_count = data.get("event_count", 0)
    if event_count > 0:
        entities.append({
            "type": "ir_finding",
            "finding_type": "timeline",
            "severity": "info",
            "keyword": data.get("keyword", ""),
            "log_path": data.get("log_path", ""),
            "event_count": event_count,
            "first_event": data.get("timeline", [{}])[0].get("timestamp", "") if data.get("timeline") else "",
            "last_event": data.get("timeline", [{}])[-1].get("timestamp", "") if data.get("timeline") else "",
        })
    return entities


def parse_containment(raw: str, store: "TargetStore") -> list[dict]:
    """Parse containment recommendations into actionable findings."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    recs = data.get("recommendations", {})
    for action in recs.get("immediate", []):
        entities.append({
            "type": "ir_finding",
            "finding_type": "containment_action",
            "severity": "critical",
            "phase": "immediate",
            "action": action,
            "attack_type": data.get("attack_type", "generic"),
        })
    return entities


PARSER_MAP[("ir_toolkit", "log_search")] = parse_log_search
PARSER_MAP[("ir_toolkit", "ioc_scan")] = parse_ioc_scan
PARSER_MAP[("ir_toolkit", "auth_log_analyze")] = parse_auth_log
PARSER_MAP[("ir_toolkit", "timeline_build")] = parse_timeline
PARSER_MAP[("ir_toolkit", "containment_recommend")] = parse_containment
