"""Parser for JWT tool output."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_jwt_decode(raw: str, store: "TargetStore") -> list[dict]:
    """Parse JWT decode output for findings."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
        header = data.get("header", {})
        payload = data.get("payload", {})
        entities.append({
            "type": "jwt_info",
            "algorithm": header.get("alg", ""),
            "claims": list(payload.keys()),
            "analysis": data.get("analysis", []),
        })
    except json.JSONDecodeError:
        if "FOUND:" in raw:
            for line in raw.splitlines():
                if line.startswith("FOUND:"):
                    entities.append({
                        "type": "jwt_secret",
                        "secret": line.split("FOUND:", 1)[1].strip(),
                    })
    return entities


PARSER_MAP[("jwt_tool", "jwt_decode")] = parse_jwt_decode
PARSER_MAP[("jwt_tool", "jwt_alg_none")] = parse_jwt_decode
PARSER_MAP[("jwt_tool", "jwt_crack")] = parse_jwt_decode
PARSER_MAP[("jwt_tool", "jwt_tamper")] = parse_jwt_decode
