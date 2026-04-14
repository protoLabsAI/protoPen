"""Parser for supply chain security output — dependency confusion, typosquatting, secrets."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_dependency_confusion(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for p in data.get("confused_packages", []):
        entities.append({
            "type": "supply_chain_finding", "protocol": "npm",
            "check": "dependency_confusion_test",
            "target": p.get("name", ""),
            "severity": p.get("severity", "critical"),
            "value": f"internal={p.get('internal_version', '?')} public={p.get('public_version', '?')}",
        })
    return entities


def parse_typosquat(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for c in data.get("candidates", []):
        entities.append({
            "type": "supply_chain_finding", "protocol": "npm",
            "check": "typosquat_scan",
            "target": c.get("name", ""),
            "severity": "high" if c.get("similarity", 0) > 0.9 else "medium",
            "value": f"similarity={c.get('similarity', 0)} downloads={c.get('downloads', 0)}",
        })
    return entities


def parse_provenance(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for c in data.get("checks", []):
        entities.append({
            "type": "supply_chain_finding", "protocol": "provenance",
            "check": "package_provenance_audit",
            "target": c.get("check_name", ""),
            "severity": "info" if c.get("passed") else "high",
            "value": c.get("details", str(c)[:200]),
        })
    return entities


def parse_postinstall(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for s in data.get("scripts", []):
        entities.append({
            "type": "supply_chain_finding", "protocol": "npm",
            "check": "postinstall_audit",
            "target": s.get("package", ""),
            "severity": s.get("risk", "high"),
            "value": s.get("content", str(s)[:200]),
        })
    return entities


def parse_trufflehog(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        entities.append({
            "type": "supply_chain_finding", "protocol": "git",
            "check": "trufflehog_scan",
            "target": obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "unknown"),
            "severity": "critical",
            "value": obj.get("DetectorName", "unknown"),
        })
    return entities


def parse_gitleaks(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    if not isinstance(data, list):
        return entities
    for f in data:
        entities.append({
            "type": "supply_chain_finding", "protocol": "git",
            "check": "gitleaks_scan",
            "target": f.get("File", ""),
            "severity": "critical",
            "value": f.get("Description", str(f)[:200]),
        })
    return entities


def parse_depscan(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for v in data.get("vulnerabilities", []):
        entities.append({
            "type": "supply_chain_finding", "protocol": "deps",
            "check": "depscan",
            "target": v.get("package", v.get("id", "")),
            "severity": v.get("severity", "medium"),
            "value": v.get("id", "") + " " + v.get("package", ""),
        })
    return entities


PARSER_MAP[("supply_chain", "dependency_confusion_test")] = parse_dependency_confusion
PARSER_MAP[("supply_chain", "typosquat_scan")] = parse_typosquat
PARSER_MAP[("supply_chain", "package_provenance_audit")] = parse_provenance
PARSER_MAP[("supply_chain", "postinstall_audit")] = parse_postinstall
PARSER_MAP[("supply_chain", "trufflehog_scan")] = parse_trufflehog
PARSER_MAP[("supply_chain", "gitleaks_scan")] = parse_gitleaks
PARSER_MAP[("supply_chain", "depscan")] = parse_depscan
