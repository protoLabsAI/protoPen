"""Parser for vulnerability scan output — nikto, nuclei, nmap NSE."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_NIKTO_VULN_RE = re.compile(r"\+\s+OSVDB-(\d+):\s+(.*)")


def parse_nikto(raw: str, store: "TargetStore") -> list[dict]:
    """Parse nikto output for discovered vulnerabilities."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
        for vuln in data.get("vulnerabilities", []):
            entities.append(
                {
                    "type": "vulnerability",
                    "id": vuln.get("id", ""),
                    "msg": vuln.get("msg", ""),
                    "method": vuln.get("method", ""),
                    "url": vuln.get("url", ""),
                }
            )
    except json.JSONDecodeError:
        for m in _NIKTO_VULN_RE.finditer(raw):
            entities.append(
                {
                    "type": "vulnerability",
                    "osvdb": m.group(1),
                    "msg": m.group(2).strip(),
                }
            )
    return entities


def parse_nuclei(raw: str, store: "TargetStore") -> list[dict]:
    """Parse nuclei JSONL output."""
    entities: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            entities.append(
                {
                    "type": "vulnerability",
                    "template_id": entry.get("template-id", ""),
                    "name": entry.get("info", {}).get("name", ""),
                    "severity": entry.get("info", {}).get("severity", ""),
                    "matched_at": entry.get("matched-at", ""),
                }
            )
        except json.JSONDecodeError:
            continue
    return entities


PARSER_MAP[("vuln_scan", "nikto_scan")] = parse_nikto
PARSER_MAP[("vuln_scan", "nuclei_scan")] = parse_nuclei
PARSER_MAP[("vuln_scan", "nuclei_tagged")] = parse_nuclei
