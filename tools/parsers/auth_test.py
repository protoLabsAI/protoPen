"""Parser for auth testing output."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_auth_test(raw: str, store: "TargetStore") -> list[dict]:
    """Parse auth testing output for vulnerabilities."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
        if data.get("vulnerable") or data.get("potential_vuln"):
            entities.append({
                "type": "auth_vulnerability",
                "url": data.get("url", ""),
                "vuln_type": "IDOR/BOLA" if "results" in data else "privilege_escalation",
            })
        if data.get("fixed_cookies"):
            entities.append({
                "type": "auth_vulnerability",
                "vuln_type": "session_fixation",
                "fixed_cookies": data.get("fixed_cookies", []),
            })
    except json.JSONDecodeError:
        pass
    return entities


PARSER_MAP[("auth_test", "idor_check")] = parse_auth_test
PARSER_MAP[("auth_test", "privesc_horizontal")] = parse_auth_test
PARSER_MAP[("auth_test", "privesc_vertical")] = parse_auth_test
PARSER_MAP[("auth_test", "session_fixation")] = parse_auth_test
PARSER_MAP[("auth_test", "token_replay")] = parse_auth_test
