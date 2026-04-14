"""Parser for serverless_audit output — Lambda injection, edge functions, IaC, misconfig."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_lambda_inject(raw: str, store: "TargetStore") -> list[dict]:
    """Parse Lambda injection test JSON output — injections array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for inj in data.get("injections", []):
        entities.append({
            "type": "serverless_finding",
            "protocol": "lambda",
            "check": "lambda_inject_test",
            "target": inj.get("function_url", inj.get("target", "")),
            "severity": inj.get("severity", "high"),
            "value": inj.get("description", inj.get("message", str(inj)[:200])),
        })
    return entities


def parse_edge_function(raw: str, store: "TargetStore") -> list[dict]:
    """Parse edge function audit JSON output — findings array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for f in data.get("findings", []):
        entities.append({
            "type": "serverless_finding",
            "protocol": "edge",
            "check": "edge_function_audit",
            "target": f.get("url", f.get("target", "")),
            "severity": f.get("severity", "medium"),
            "value": f.get("description", f.get("message", str(f)[:200])),
        })
    return entities


def parse_event_trigger(raw: str, store: "TargetStore") -> list[dict]:
    """Parse event trigger abuse JSON output — triggers array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for t in data.get("triggers", []):
        entities.append({
            "type": "serverless_finding",
            "protocol": "event",
            "check": "event_trigger_abuse",
            "target": t.get("function_url", t.get("target", "")),
            "severity": t.get("severity", "high"),
            "value": t.get("description", t.get("message", str(t)[:200])),
        })
    return entities


def parse_tfstate(raw: str, store: "TargetStore") -> list[dict]:
    """Parse Terraform state scan JSON output — secrets_found array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for s in data.get("secrets_found", []):
        entities.append({
            "type": "serverless_finding",
            "protocol": "terraform",
            "check": "tfstate_scan",
            "target": s.get("path", s.get("resource", "")),
            "severity": s.get("severity", "critical"),
            "value": s.get("description", s.get("key", str(s)[:200])),
        })
    return entities


def parse_iac_security(raw: str, store: "TargetStore") -> list[dict]:
    """Parse checkov IaC security scan JSON output — results.failed_checks array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    results = data.get("results", {})
    for chk in results.get("failed_checks", []):
        entities.append({
            "type": "serverless_finding",
            "protocol": "iac",
            "check": "iac_security_scan",
            "target": chk.get("file_path", chk.get("resource", "")),
            "severity": chk.get("severity", "high"),
            "value": chk.get("check_id", "") + ": " + chk.get("name", chk.get("description", str(chk)[:200])),
        })
    return entities


def parse_serverless_misconfig(raw: str, store: "TargetStore") -> list[dict]:
    """Parse serverless misconfiguration JSON output — misconfigs array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for mc in data.get("misconfigs", []):
        entities.append({
            "type": "serverless_finding",
            "protocol": "serverless",
            "check": "serverless_misconfig",
            "target": mc.get("function_name", mc.get("resource", "")),
            "severity": mc.get("severity", "high"),
            "value": mc.get("description", mc.get("message", str(mc)[:200])),
        })
    return entities


def parse_cold_start_race(raw: str, store: "TargetStore") -> list[dict]:
    """Parse cold-start race condition JSON output — results array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for r in data.get("results", []):
        entities.append({
            "type": "serverless_finding",
            "protocol": "lambda",
            "check": "cold_start_race",
            "target": r.get("function_url", r.get("target", "")),
            "severity": r.get("severity", "medium"),
            "value": r.get("description", r.get("message", str(r)[:200])),
        })
    return entities


PARSER_MAP[("serverless_audit", "lambda_inject_test")] = parse_lambda_inject
PARSER_MAP[("serverless_audit", "edge_function_audit")] = parse_edge_function
PARSER_MAP[("serverless_audit", "event_trigger_abuse")] = parse_event_trigger
PARSER_MAP[("serverless_audit", "tfstate_scan")] = parse_tfstate
PARSER_MAP[("serverless_audit", "iac_security_scan")] = parse_iac_security
PARSER_MAP[("serverless_audit", "serverless_misconfig")] = parse_serverless_misconfig
PARSER_MAP[("serverless_audit", "cold_start_race")] = parse_cold_start_race
