"""Parser for PhoneInfoga phone-number scan output.

Captures one phone-profile finding (country / carrier / line type) keyed to the
number, so it lands in the target store alongside the rest of the engagement's
intel. The OSINT footprint (search-engine dork URLs) is left out — it's
navigation, not a finding.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

# Header: "phoneinfoga: scan of +14155552671"
_NUMBER_RE = re.compile(r"scan of\s+(?P<number>\+?[\d\s().-]{6,})", re.IGNORECASE)
# Local-scanner metadata lines: "Country: US (+1)", "Carrier: ...", "Line type: mobile"
_FIELD_RE = re.compile(r"^(?P<key>Country|Carrier|Line type)\s*:\s*(?P<val>.+?)\s*$", re.IGNORECASE)


def parse_scan(raw: str, store: "TargetStore") -> list[dict]:
    """Extract the number's country / carrier / line type as one phone finding."""
    if not raw or raw.startswith("[timeout]"):
        return []
    m = _NUMBER_RE.search(raw)
    number = m.group("number").strip() if m else ""
    if not number:
        return []

    fields: dict[str, str] = {}
    for line in raw.splitlines():
        fm = _FIELD_RE.match(line.strip())
        if fm:
            fields[fm.group("key").lower().replace(" ", "_")] = fm.group("val").strip()

    country = fields.get("country", "")
    carrier = fields.get("carrier", "")
    line_type = fields.get("line_type", "")
    summary = " · ".join(p for p in [country, carrier, line_type] if p) or "no metadata"
    return [
        {
            "type": "phone",
            "category": "osint-phone",
            "severity": "info",
            "target": number,
            "title": f"phone {number}",
            "value": summary,
            "country": country,
            "carrier": carrier,
            "line_type": line_type,
        }
    ]


PARSER_MAP[("phoneinfoga", "scan")] = parse_scan
