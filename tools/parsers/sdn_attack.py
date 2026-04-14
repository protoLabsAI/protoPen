"""Parser for SDN/Network Automation attack output — controllers, NETCONF, RESTCONF, YANG, OpenFlow."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_sdn_controller_enum(raw: str, store: "TargetStore") -> list[dict]:
    """Parse SDN controller enumeration JSON output — controllers array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for c in data.get("controllers", []):
        entities.append(
            {
                "type": "sdn_finding",
                "protocol": "sdn",
                "check": "sdn_controller_enum",
                "target": c.get("host", c.get("ip", "")),
                "severity": c.get("severity", "medium"),
                "value": c.get("type", c.get("description", str(c)[:200])),
            }
        )
    return entities


def parse_netconf_exploit(raw: str, store: "TargetStore") -> list[dict]:
    """Parse NETCONF audit JSON output — vulnerabilities array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for v in data.get("vulnerabilities", []):
        entities.append(
            {
                "type": "sdn_finding",
                "protocol": "netconf",
                "check": "netconf_exploit",
                "target": v.get("target", v.get("host", "")),
                "severity": v.get("severity", "high"),
                "value": v.get("description", v.get("message", str(v)[:200])),
            }
        )
    return entities


def parse_network_policy(raw: str, store: "TargetStore") -> list[dict]:
    """Parse network policy audit JSON output — policy_issues array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for issue in data.get("policy_issues", []):
        entities.append(
            {
                "type": "sdn_finding",
                "protocol": "sdn",
                "check": "network_policy_audit",
                "target": issue.get("controller", issue.get("target", "")),
                "severity": issue.get("severity", "high"),
                "value": issue.get("description", issue.get("message", str(issue)[:200])),
            }
        )
    return entities


def parse_yang_model(raw: str, store: "TargetStore") -> list[dict]:
    """Parse YANG model enumeration JSON output — models array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for m in data.get("models", []):
        entities.append(
            {
                "type": "sdn_finding",
                "protocol": "yang",
                "check": "yang_model_enum",
                "target": m.get("target", m.get("host", "")),
                "severity": m.get("severity", "info"),
                "value": m.get("module", m.get("name", str(m)[:200])),
            }
        )
    return entities


def parse_restconf(raw: str, store: "TargetStore") -> list[dict]:
    """Parse RESTCONF audit JSON output — endpoints array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for ep in data.get("endpoints", []):
        entities.append(
            {
                "type": "sdn_finding",
                "protocol": "restconf",
                "check": "restconf_test",
                "target": ep.get("url", ep.get("target", "")),
                "severity": ep.get("severity", "medium"),
                "value": ep.get("description", ep.get("path", str(ep)[:200])),
            }
        )
    return entities


def parse_openflow(raw: str, store: "TargetStore") -> list[dict]:
    """Parse OpenFlow audit JSON output — issues array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for issue in data.get("issues", []):
        entities.append(
            {
                "type": "sdn_finding",
                "protocol": "openflow",
                "check": "openflow_audit",
                "target": issue.get("target", issue.get("switch", "")),
                "severity": issue.get("severity", "high"),
                "value": issue.get("description", issue.get("message", str(issue)[:200])),
            }
        )
    return entities


PARSER_MAP[("sdn_attack", "sdn_controller_enum")] = parse_sdn_controller_enum
PARSER_MAP[("sdn_attack", "netconf_exploit")] = parse_netconf_exploit
PARSER_MAP[("sdn_attack", "network_policy_audit")] = parse_network_policy
PARSER_MAP[("sdn_attack", "yang_model_enum")] = parse_yang_model
PARSER_MAP[("sdn_attack", "restconf_test")] = parse_restconf
PARSER_MAP[("sdn_attack", "openflow_audit")] = parse_openflow
