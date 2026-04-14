"""Parser for CI/CD audit output — truffleHog, gitleaks, actionlint, semgrep, checkov."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_trufflehog(raw: str, store: "TargetStore") -> list[dict]:
    """Parse truffleHog JSON-lines output (one JSON object per line)."""
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue
        entities.append(
            {
                "type": "secret_finding",
                "detector_name": finding.get("DetectorName", finding.get("detectorName", "")),
                "file": finding.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", ""),
                "line": finding.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("line", 0),
                "verified": finding.get("Verified", finding.get("verified", False)),
                "raw": finding.get("Raw", finding.get("raw", ""))[:80],
                "severity": "critical" if finding.get("Verified", False) else "high",
            }
        )
    return entities


def parse_gitleaks(raw: str, store: "TargetStore") -> list[dict]:
    """Parse gitleaks JSON array output."""
    entities: list[dict] = []
    try:
        findings = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    if not isinstance(findings, list):
        return entities

    for f in findings:
        secret = f.get("Secret", f.get("secret", ""))
        entities.append(
            {
                "type": "secret_finding",
                "rule": f.get("RuleID", f.get("ruleID", "")),
                "secret": secret[:20] + "..." if len(secret) > 20 else secret,
                "file": f.get("File", f.get("file", "")),
                "line": f.get("StartLine", f.get("startLine", 0)),
                "commit": f.get("Commit", f.get("commit", ""))[:8],
                "severity": "high",
            }
        )
    return entities


def parse_github_actions(raw: str, store: "TargetStore") -> list[dict]:
    """Parse actionlint JSON output."""
    entities: list[dict] = []
    try:
        findings = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    if not isinstance(findings, list):
        findings = [findings] if isinstance(findings, dict) else []

    for f in findings:
        entities.append(
            {
                "type": "cicd_finding",
                "message": f.get("message", ""),
                "filepath": f.get("filepath", f.get("filename", "")),
                "line": f.get("line", 0),
                "column": f.get("column", 0),
                "kind": f.get("kind", ""),
                "severity": "medium",
            }
        )
    return entities


def parse_dependency_check(raw: str, store: "TargetStore") -> list[dict]:
    """Parse OWASP dependency-check JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulnerabilities", []):
            entities.append(
                {
                    "type": "dependency_vuln",
                    "name": dep.get("fileName", ""),
                    "cve": vuln.get("name", ""),
                    "severity": vuln.get("severity", "UNKNOWN").lower(),
                    "description": vuln.get("description", "")[:200],
                    "cvss_score": vuln.get("cvssv3", {}).get("baseScore", 0),
                }
            )
    return entities


def parse_semgrep(raw: str, store: "TargetStore") -> list[dict]:
    """Parse semgrep JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for result in data.get("results", []):
        entities.append(
            {
                "type": "code_finding",
                "check_id": result.get("check_id", ""),
                "path": result.get("path", ""),
                "line": result.get("start", {}).get("line", 0),
                "severity": result.get("extra", {}).get("severity", "WARNING").lower(),
                "message": result.get("extra", {}).get("message", ""),
            }
        )
    return entities


def parse_checkov(raw: str, store: "TargetStore") -> list[dict]:
    """Parse checkov JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    # checkov can return a list of check-type results or a single dict
    results_list = data if isinstance(data, list) else [data]
    for results in results_list:
        for check in results.get("results", {}).get("failed_checks", []):
            entities.append(
                {
                    "type": "iac_finding",
                    "check_id": check.get("check_id", ""),
                    "resource": check.get("resource", ""),
                    "check_name": check.get("name", ""),
                    "guideline": check.get("guideline", ""),
                    "file_path": check.get("file_path", ""),
                    "severity": "high",
                }
            )
    return entities


PARSER_MAP[("cicd_audit", "trufflehog_scan")] = parse_trufflehog
PARSER_MAP[("cicd_audit", "trufflehog_filesystem")] = parse_trufflehog
PARSER_MAP[("cicd_audit", "gitleaks_detect")] = parse_gitleaks
PARSER_MAP[("cicd_audit", "gitleaks_protect")] = parse_gitleaks
PARSER_MAP[("cicd_audit", "github_actions_audit")] = parse_github_actions
PARSER_MAP[("cicd_audit", "dependency_check")] = parse_dependency_check
PARSER_MAP[("cicd_audit", "semgrep_ci")] = parse_semgrep
PARSER_MAP[("cicd_audit", "checkov_iac")] = parse_checkov
