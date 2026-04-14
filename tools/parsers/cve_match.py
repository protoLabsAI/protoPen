"""Parser for CVE matching output — searchsploit, nuclei CVE, nmap vulners."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_searchsploit(raw: str, store: "TargetStore") -> list[dict]:
    """Parse searchsploit JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
        for exploit in data.get("RESULTS_EXPLOIT", []):
            entities.append(
                {
                    "type": "exploit",
                    "title": exploit.get("Title", ""),
                    "edb_id": exploit.get("EDB-ID", ""),
                    "platform": exploit.get("Platform", ""),
                    "path": exploit.get("Path", ""),
                }
            )
    except json.JSONDecodeError:
        pass
    return entities


def parse_cve_nuclei(raw: str, store: "TargetStore") -> list[dict]:
    """Parse nuclei CVE-specific JSONL output."""
    entities: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            info = entry.get("info", {})
            entities.append(
                {
                    "type": "cve",
                    "template_id": entry.get("template-id", ""),
                    "name": info.get("name", ""),
                    "severity": info.get("severity", ""),
                    "cve_id": info.get("classification", {}).get("cve-id", []),
                    "matched_at": entry.get("matched-at", ""),
                }
            )
        except json.JSONDecodeError:
            continue
    return entities


PARSER_MAP[("cve_match", "cve_search")] = parse_searchsploit
PARSER_MAP[("cve_match", "cve_nuclei")] = parse_cve_nuclei
