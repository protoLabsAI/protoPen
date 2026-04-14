"""Parser for hardening check output — per-service pass/fail findings."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_hardening(raw: str, store: "TargetStore") -> list[dict]:
    """Parse hardening check results into normalized findings.

    All hardening actions share the same output schema:
    {service, total_checks, passed, failed, checks: [{check, passed, severity, remediation}]}
    """
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    service = data.get("service", "unknown")
    target = data.get("target", "")

    for check in data.get("checks", []):
        if check.get("passed"):
            continue
        entities.append(
            {
                "type": "hardening_finding",
                "service": service,
                "target": target,
                "check": check.get("check", ""),
                "severity": check.get("severity", "info"),
                "expected": check.get("expected", ""),
                "actual": check.get("actual", ""),
                "remediation": check.get("remediation", ""),
            }
        )
    return entities


PARSER_MAP[("hardening_check", "ssh_harden")] = parse_hardening
PARSER_MAP[("hardening_check", "nginx_harden")] = parse_hardening
PARSER_MAP[("hardening_check", "apache_harden")] = parse_hardening
PARSER_MAP[("hardening_check", "docker_harden")] = parse_hardening
PARSER_MAP[("hardening_check", "k8s_harden")] = parse_hardening
