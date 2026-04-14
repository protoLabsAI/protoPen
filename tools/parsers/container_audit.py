"""Parser for container/K8s audit output — kube-hunter, kube-bench, deepce, CDK, Trivy."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_kube_hunter(raw: str, store: "TargetStore") -> list[dict]:
    """Parse kube-hunter JSON report into normalized findings."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for vuln in data.get("vulnerabilities", []):
        severity = vuln.get("severity", "info").lower()
        entities.append(
            {
                "type": "k8s_finding",
                "target": vuln.get("location", ""),
                "check": vuln.get("vulnerability", ""),
                "severity": severity,
                "value": vuln.get("description", ""),
                "category": vuln.get("category", ""),
                "hunter": vuln.get("hunter", ""),
            }
        )
    return entities


def parse_kube_bench(raw: str, store: "TargetStore") -> list[dict]:
    """Parse kube-bench CIS benchmark JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for control in data.get("Controls", []):
        for test in control.get("tests", []):
            for result in test.get("results", []):
                status = result.get("status", "")
                if status in ("FAIL", "WARN"):
                    entities.append(
                        {
                            "type": "k8s_finding",
                            "target": control.get("node_type", ""),
                            "check": f"{result.get('test_number', '')} {result.get('test_desc', '')}",
                            "severity": "high" if status == "FAIL" else "medium",
                            "value": result.get("test_desc", ""),
                            "remediation": result.get("remediation", ""),
                            "scored": result.get("scored", True),
                        }
                    )
    return entities


def parse_deepce(raw: str, store: "TargetStore") -> list[dict]:
    """Parse deepce container escape detection output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for escape in data.get("escapes", []):
        entities.append(
            {
                "type": "container_finding",
                "target": "container",
                "check": escape.get("name", ""),
                "severity": escape.get("severity", "high"),
                "value": escape.get("description", ""),
                "exploitable": escape.get("exploitable", False),
            }
        )

    for info in data.get("info", []):
        entities.append(
            {
                "type": "container_finding",
                "target": "container",
                "check": info.get("name", ""),
                "severity": "info",
                "value": info.get("value", ""),
            }
        )
    return entities


def parse_cdk_evaluate(raw: str, store: "TargetStore") -> list[dict]:
    """Parse CDK evaluate output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for finding in data.get("findings", []):
        entities.append(
            {
                "type": "container_finding",
                "target": "container",
                "check": finding.get("name", ""),
                "severity": finding.get("severity", "medium"),
                "value": finding.get("description", ""),
                "exploit_available": finding.get("exploit_available", False),
            }
        )
    return entities


def parse_trivy_image(raw: str, store: "TargetStore") -> list[dict]:
    """Parse Trivy image/fs scan JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    results = data.get("Results", [])
    for result in results:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            entities.append(
                {
                    "type": "container_vuln",
                    "target": target,
                    "check": vuln.get("VulnerabilityID", ""),
                    "severity": vuln.get("Severity", "UNKNOWN").lower(),
                    "value": vuln.get("Title", vuln.get("Description", "")),
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                }
            )
    return entities


PARSER_MAP[("container_audit", "kube_hunter")] = parse_kube_hunter
PARSER_MAP[("container_audit", "kube_hunter_internal")] = parse_kube_hunter
PARSER_MAP[("container_audit", "kube_bench")] = parse_kube_bench
PARSER_MAP[("container_audit", "kube_bench_target")] = parse_kube_bench
PARSER_MAP[("container_audit", "deepce")] = parse_deepce
PARSER_MAP[("container_audit", "cdk_evaluate")] = parse_cdk_evaluate
PARSER_MAP[("container_audit", "trivy_image")] = parse_trivy_image
PARSER_MAP[("container_audit", "trivy_k8s")] = parse_trivy_image
PARSER_MAP[("container_audit", "trivy_fs")] = parse_trivy_image
