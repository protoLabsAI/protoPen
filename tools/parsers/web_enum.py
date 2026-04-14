"""Parser for web enumeration output — gobuster and ffuf."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_GOBUSTER_LINE_RE = re.compile(r"^(/\S+)\s+\(Status:\s*(\d+)\)")


def parse_gobuster(raw: str, store: "TargetStore") -> list[dict]:
    """Parse gobuster output for discovered web paths."""
    entities: list[dict] = []
    for line in raw.splitlines():
        m = _GOBUSTER_LINE_RE.match(line.strip())
        if m:
            entities.append(
                {
                    "type": "web_path",
                    "path": m.group(1),
                    "status": int(m.group(2)),
                }
            )
    return entities


def parse_ffuf(raw: str, store: "TargetStore") -> list[dict]:
    """Parse ffuf JSON output for discovered endpoints."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
        for result in data.get("results", []):
            entities.append(
                {
                    "type": "web_path",
                    "url": result.get("url", ""),
                    "status": result.get("status", 0),
                    "length": result.get("length", 0),
                }
            )
    except json.JSONDecodeError:
        pass
    return entities


PARSER_MAP[("web_enum", "gobuster_dir")] = parse_gobuster
PARSER_MAP[("web_enum", "gobuster_vhost")] = parse_gobuster
PARSER_MAP[("web_enum", "ffuf_fuzz")] = parse_ffuf
PARSER_MAP[("web_enum", "ffuf_param")] = parse_ffuf
