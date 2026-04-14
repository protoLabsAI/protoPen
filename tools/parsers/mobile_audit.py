"""Parser for mobile_audit tool output — APK/IPA analysis, Frida, drozer, objection."""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

logger = logging.getLogger(__name__)


def parse_apk_decompile(raw: str, store: "TargetStore") -> list[dict]:
    """Parse apktool decompile prose output."""
    entities: list[dict] = []
    if not raw or not raw.strip():
        return entities
    lower = raw.lower()
    if "decompiled" in lower or "output" in lower:
        entities.append({
            "type": "mobile_finding",
            "protocol": "apk",
            "check": "apk_decompile",
            "target": "",
            "severity": "info",
            "value": raw.strip()[:200],
        })
    return entities


def parse_static_analysis(raw: str, store: "TargetStore") -> list[dict]:
    """Parse MobSF static analysis JSON output — findings array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for f in data.get("findings", []):
        entities.append({
            "type": "mobile_finding",
            "protocol": "mobsf",
            "check": "static_analysis",
            "target": f.get("category", ""),
            "severity": f.get("severity", "medium"),
            "value": f.get("description", str(f)[:200]),
        })
    return entities


def parse_jadx_decompile(raw: str, store: "TargetStore") -> list[dict]:
    """Parse jadx decompile prose output."""
    entities: list[dict] = []
    if not raw or not raw.strip():
        return entities
    lower = raw.lower()
    if "decompiled" in lower or "output" in lower:
        entities.append({
            "type": "mobile_finding",
            "protocol": "jadx",
            "check": "jadx_decompile",
            "target": "",
            "severity": "info",
            "value": raw.strip()[:200],
        })
    return entities


def parse_drozer_scan(raw: str, store: "TargetStore") -> list[dict]:
    """Parse drozer content provider scan JSON output — providers array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for p in data.get("providers", []):
        severity = "high" if p.get("exported") else "info"
        entities.append({
            "type": "mobile_finding",
            "protocol": "drozer",
            "check": "drozer_scan",
            "target": p.get("name", ""),
            "severity": severity,
            "value": p.get("name", str(p)[:200]),
        })
    return entities


def parse_frida_hook(raw: str, store: "TargetStore") -> list[dict]:
    """Parse Frida hook JSON output — hooks array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for h in data.get("hooks", []):
        severity = "medium" if h.get("hooked") else "info"
        entities.append({
            "type": "mobile_finding",
            "protocol": "frida",
            "check": "frida_hook",
            "target": h.get("class_name", ""),
            "severity": severity,
            "value": h.get("method", str(h)[:200]),
        })
    return entities


def parse_ssl_pinning(raw: str, store: "TargetStore") -> list[dict]:
    """Parse objection SSL pinning bypass prose output."""
    entities: list[dict] = []
    if not raw or not raw.strip():
        return entities
    lower = raw.lower()
    if "disabled" in lower or "bypassed" in lower:
        severity = "high"
    else:
        severity = "info"
    entities.append({
        "type": "mobile_finding",
        "protocol": "objection",
        "check": "ssl_pinning_bypass",
        "target": "",
        "severity": severity,
        "value": raw.strip()[:200],
    })
    return entities


def parse_ipc_audit(raw: str, store: "TargetStore") -> list[dict]:
    """Parse drozer IPC audit JSON output — components array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for comp in data.get("components", []):
        severity = "high" if comp.get("exported") else "info"
        entities.append({
            "type": "mobile_finding",
            "protocol": "drozer",
            "check": "ipc_audit",
            "target": comp.get("name", ""),
            "severity": severity,
            "value": comp.get("type", str(comp)[:200]),
        })
    return entities


def parse_keychain_dump(raw: str, store: "TargetStore") -> list[dict]:
    """Parse objection keychain/keystore dump JSON output — entries array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for entry in data.get("entries", []):
        severity = "high" if entry.get("accessible") else "info"
        entities.append({
            "type": "mobile_finding",
            "protocol": "objection",
            "check": "keychain_dump",
            "target": entry.get("alias", ""),
            "severity": severity,
            "value": entry.get("type", str(entry)[:200]),
        })
    return entities


PARSER_MAP[("mobile_audit", "apk_decompile")] = parse_apk_decompile
PARSER_MAP[("mobile_audit", "static_analysis")] = parse_static_analysis
PARSER_MAP[("mobile_audit", "jadx_decompile")] = parse_jadx_decompile
PARSER_MAP[("mobile_audit", "drozer_scan")] = parse_drozer_scan
PARSER_MAP[("mobile_audit", "frida_hook")] = parse_frida_hook
PARSER_MAP[("mobile_audit", "ssl_pinning_bypass")] = parse_ssl_pinning
PARSER_MAP[("mobile_audit", "ipc_audit")] = parse_ipc_audit
PARSER_MAP[("mobile_audit", "keychain_dump")] = parse_keychain_dump
