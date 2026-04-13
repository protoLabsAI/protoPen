"""Parser for SSRF detection output."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_ssrf(raw: str, store: "TargetStore") -> list[dict]:
    """Parse SSRF detection output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            for entry in data:
                if entry.get("status") == 200:
                    entities.append({
                        "type": "ssrf_finding",
                        "payload": entry.get("payload", ""),
                        "status": entry.get("status", 0),
                    })
        elif isinstance(data, dict):
            if data.get("vulnerable"):
                entities.append({
                    "type": "ssrf_finding",
                    "callback_url": data.get("callback_url", ""),
                    "hits": len(data.get("hits", [])),
                })
    except json.JSONDecodeError:
        pass
    return entities


PARSER_MAP[("ssrf_detect", "ssrf_basic")] = parse_ssrf
PARSER_MAP[("ssrf_detect", "ssrf_cloud_meta")] = parse_ssrf
PARSER_MAP[("ssrf_detect", "ssrf_callback")] = parse_ssrf
