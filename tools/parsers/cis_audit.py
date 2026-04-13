"""Parser for CIS audit output — SSH, TLS, firewall, patch, port baseline."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_cis_checks(raw: str, store: "TargetStore") -> list[dict]:
    """Parse CIS benchmark check results into normalized findings."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    target = data.get("target", "")
    for issue in data.get("issues", []):
        entities.append({
            "type": "cis_finding",
            "target": target,
            "check": issue.get("check", ""),
            "severity": issue.get("severity", "info"),
            "value": issue.get("value", ""),
            "recommendation": issue.get("recommendation", ""),
        })
    return entities


def parse_tls_audit(raw: str, store: "TargetStore") -> list[dict]:
    """Parse TLS/SSL audit results."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    target = data.get("target", "")
    port = data.get("port", 443)

    if data.get("error"):
        entities.append({
            "type": "cis_finding",
            "target": target,
            "check": "TLS Connection",
            "severity": "info",
            "value": data["error"],
            "recommendation": "Verify TLS is configured on the target port",
        })

    for issue in data.get("issues", []):
        entities.append({
            "type": "cis_finding",
            "target": f"{target}:{port}",
            "check": issue.get("check", ""),
            "severity": issue.get("severity", "info"),
            "value": issue.get("value", ""),
            "recommendation": issue.get("recommendation", ""),
        })
    return entities


def parse_patch_check(raw: str, store: "TargetStore") -> list[dict]:
    """Parse patch assessment results."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    pending = data.get("pending_updates", 0)
    if pending > 0:
        entities.append({
            "type": "cis_finding",
            "target": data.get("os", "unknown"),
            "check": "Pending Security Patches",
            "severity": data.get("severity", "medium"),
            "value": f"{pending} updates pending",
            "recommendation": "Apply pending security updates",
            "packages": data.get("packages", [])[:30],
        })
    return entities


def parse_port_baseline(raw: str, store: "TargetStore") -> list[dict]:
    """Parse port baseline comparison results."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    target = data.get("target", "")
    for unexpected in data.get("unexpected", []):
        entities.append({
            "type": "cis_finding",
            "target": target,
            "check": "Unexpected Open Port",
            "severity": "high",
            "value": f"Port {unexpected.get('port', '?')}/{unexpected.get('service', 'unknown')}",
            "recommendation": f"Close port {unexpected.get('port', '?')} or add to expected baseline",
        })
    for missing_port in data.get("missing_expected", []):
        entities.append({
            "type": "cis_finding",
            "target": target,
            "check": "Missing Expected Port",
            "severity": "medium",
            "value": f"Port {missing_port}",
            "recommendation": f"Verify service on port {missing_port} is running",
        })
    return entities


PARSER_MAP[("cis_audit", "ssh_audit")] = parse_cis_checks
PARSER_MAP[("cis_audit", "tls_audit")] = parse_tls_audit
PARSER_MAP[("cis_audit", "firewall_audit")] = parse_cis_checks
PARSER_MAP[("cis_audit", "patch_check")] = parse_patch_check
PARSER_MAP[("cis_audit", "port_baseline")] = parse_port_baseline
