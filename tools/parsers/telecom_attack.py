"""Parser for 5G/telecom attack output — GTP, SIP, SS7, Diameter, IMSI."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_gtp_json(raw: str, store: "TargetStore") -> list[dict]:
    """Parse GTP scan/fuzzer JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    results = data if isinstance(data, list) else data.get("results", [data])
    for r in results:
        entities.append(
            {
                "type": "telecom_finding",
                "protocol": "gtp",
                "check": "gtp_scan",
                "target": r.get("target", r.get("ip", "")),
                "severity": r.get("severity", "medium"),
                "value": r.get("message", r.get("description", str(r)[:200])),
            }
        )
    return entities


def parse_sip_json(raw: str, store: "TargetStore") -> list[dict]:
    """Parse SIPVicious JSON output (svmap, svcrack, svwar)."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    results = data if isinstance(data, list) else data.get("results", [data])
    for r in results:
        entities.append(
            {
                "type": "telecom_finding",
                "protocol": "sip",
                "check": "sip_enum",
                "target": r.get("host", r.get("ip", "")),
                "severity": r.get("severity", "medium"),
                "value": r.get("user_agent", r.get("extension", str(r)[:200])),
            }
        )
    return entities


def parse_ss7_json(raw: str, store: "TargetStore") -> list[dict]:
    """Parse SS7 scan JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    results = data if isinstance(data, list) else data.get("results", [data])
    for r in results:
        entities.append(
            {
                "type": "telecom_finding",
                "protocol": "ss7",
                "check": "ss7_scan",
                "target": r.get("target", ""),
                "severity": r.get("severity", "high"),
                "value": r.get("message", str(r)[:200]),
            }
        )
    return entities


def parse_diameter_json(raw: str, store: "TargetStore") -> list[dict]:
    """Parse Diameter audit JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    results = data if isinstance(data, list) else data.get("results", [data])
    for r in results:
        entities.append(
            {
                "type": "telecom_finding",
                "protocol": "diameter",
                "check": "diameter_audit",
                "target": r.get("peer", ""),
                "severity": r.get("severity", "medium"),
                "value": r.get("message", str(r)[:200]),
            }
        )
    return entities


def parse_imsi_detect(raw: str, store: "TargetStore") -> list[dict]:
    """Parse grgsm_scanner text output — look for ARFCN, freq, CID."""
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.search(r"ARFCN:\s*(\d+)", line, re.IGNORECASE)
        if match or "freq" in line.lower() or "cid" in line.lower():
            entities.append(
                {
                    "type": "telecom_finding",
                    "protocol": "gsm",
                    "check": "imsi_detect",
                    "target": "",
                    "severity": "info",
                    "value": line,
                }
            )
    return entities


def parse_stir_shaken(raw: str, store: "TargetStore") -> list[dict]:
    """Parse STIR/SHAKEN verification JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    entities.append(
        {
            "type": "telecom_finding",
            "protocol": "stir_shaken",
            "check": "stir_shaken_verify",
            "target": data.get("call_id", ""),
            "severity": "high" if not data.get("verified", False) else "info",
            "value": data.get("message", "verified" if data.get("verified") else "unverified"),
        }
    )
    return entities


PARSER_MAP[("telecom_attack", "gtp_scan")] = parse_gtp_json
PARSER_MAP[("telecom_attack", "gtp_fuzzer")] = parse_gtp_json
PARSER_MAP[("telecom_attack", "sip_enum")] = parse_sip_json
PARSER_MAP[("telecom_attack", "sip_crack")] = parse_sip_json
PARSER_MAP[("telecom_attack", "ss7_scan")] = parse_ss7_json
PARSER_MAP[("telecom_attack", "diameter_audit")] = parse_diameter_json
PARSER_MAP[("telecom_attack", "imsi_detect")] = parse_imsi_detect
PARSER_MAP[("telecom_attack", "sip_flood_test")] = parse_sip_json
PARSER_MAP[("telecom_attack", "stir_shaken_verify")] = parse_stir_shaken
