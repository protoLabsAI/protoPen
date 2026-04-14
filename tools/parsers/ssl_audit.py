"""Parser for SSL/TLS audit output — testssl.sh JSON."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_testssl(raw: str, store: "TargetStore") -> list[dict]:
    """Parse testssl.sh JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            for entry in data:
                entities.append(
                    {
                        "type": "ssl_finding",
                        "id": entry.get("id", ""),
                        "severity": entry.get("severity", ""),
                        "finding": entry.get("finding", ""),
                    }
                )
    except json.JSONDecodeError:
        pass
    return entities


PARSER_MAP[("ssl_audit", "ssl_full_audit")] = parse_testssl
PARSER_MAP[("ssl_audit", "ssl_protocols")] = parse_testssl
PARSER_MAP[("ssl_audit", "ssl_ciphers")] = parse_testssl
PARSER_MAP[("ssl_audit", "ssl_vulnerabilities")] = parse_testssl
PARSER_MAP[("ssl_audit", "ssl_certificates")] = parse_testssl
