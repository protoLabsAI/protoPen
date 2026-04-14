"""Parser for evasion/AV bypass output — msfvenom, Veil, Shellter, Donut, ScareCrow."""
from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_payload_gen(raw: str, store: "TargetStore") -> list[dict]:
    """Generic parser for payload generators (msfvenom, veil, shellter, donut, scarecrow).

    Look for success/failure indicators in text output.
    """
    entities: list[dict] = []
    raw_s = raw.strip()
    if not raw_s:
        return entities

    success = any(kw in raw_s.lower() for kw in [
        "saved", "written", "generated", "success", "payload size", "final size",
    ])
    size_match = re.search(r"(\d+)\s*bytes?", raw_s)
    entities.append({
        "type": "evasion_finding",
        "check": "payload_gen",
        "severity": "info",
        "technique": "encoding",
        "details": raw_s[:300],
        "success": success,
        "size_bytes": int(size_match.group(1)) if size_match else 0,
    })
    return entities


def parse_amsi_test(raw: str, store: "TargetStore") -> list[dict]:
    """Parse AMSI bypass test JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for result in (data if isinstance(data, list) else data.get("results", [data])):
        bypassed = result.get("bypassed", result.get("success", False))
        entities.append({
            "type": "evasion_finding",
            "check": "amsi_test",
            "severity": "info" if bypassed else "high",
            "technique": result.get("technique", "amsi_bypass"),
            "details": result.get("message", "AMSI bypassed" if bypassed else "AMSI blocked"),
        })
    return entities


def parse_defender_check(raw: str, store: "TargetStore") -> list[dict]:
    """Parse defender-check text output."""
    entities: list[dict] = []
    raw_s = raw.strip()
    if not raw_s:
        return entities
    low = raw_s.lower()
    clean_phrases = ["no threats found", "no threat", "not detected", "clean", "no malware"]
    if any(cp in low for cp in clean_phrases):
        detected = False
    else:
        detected = any(kw in low for kw in ["detected", "threat", "malware", "found"])
    entities.append({
        "type": "evasion_finding",
        "check": "defender_check",
        "severity": "info" if not detected else "high",
        "technique": "av_detection",
        "details": raw_s[:300],
        "detected": detected,
    })
    return entities


def parse_entropy(raw: str, store: "TargetStore") -> list[dict]:
    """Parse entropy analysis JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    entropy = data.get("entropy", 0)
    entities.append({
        "type": "evasion_finding",
        "check": "entropy_analysis",
        "severity": "high" if entropy > 7.5 else ("medium" if entropy > 6.5 else "info"),
        "technique": "entropy_analysis",
        "details": f"Entropy: {entropy:.2f} — {'likely packed/encrypted' if entropy > 7.5 else 'normal range'}",
        "entropy": entropy,
    })
    return entities


PARSER_MAP[("evasion", "msfvenom_generate")] = parse_payload_gen
PARSER_MAP[("evasion", "veil_generate")] = parse_payload_gen
PARSER_MAP[("evasion", "shellter_inject")] = parse_payload_gen
PARSER_MAP[("evasion", "donut_generate")] = parse_payload_gen
PARSER_MAP[("evasion", "scarecrow_generate")] = parse_payload_gen
PARSER_MAP[("evasion", "amsi_test")] = parse_amsi_test
PARSER_MAP[("evasion", "defender_check")] = parse_defender_check
PARSER_MAP[("evasion", "entropy_analysis")] = parse_entropy
