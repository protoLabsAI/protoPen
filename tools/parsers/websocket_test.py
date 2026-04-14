"""Parser for WebSocket security test output — auth_bypass, cswsh, injection."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_ws_auth_bypass(raw: str, store: "TargetStore") -> list[dict]:
    """Parse WebSocket auth bypass test output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for test in data.get("tests", []):
        if test.get("vulnerable"):
            entities.append(
                {
                    "type": "ws_finding",
                    "target": data.get("url", ""),
                    "check": f"ws_auth_bypass:{test.get('test', '')}",
                    "severity": test.get("severity", "medium"),
                    "value": test.get("detail", ""),
                }
            )
    return entities


def parse_ws_cswsh(raw: str, store: "TargetStore") -> list[dict]:
    """Parse CSWSH test output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for test in data.get("tests", []):
        if test.get("vulnerable"):
            entities.append(
                {
                    "type": "ws_finding",
                    "target": data.get("url", ""),
                    "check": f"cswsh:{test.get('origin', '')}",
                    "severity": test.get("severity", "high"),
                    "value": test.get("detail", ""),
                }
            )
    return entities


def parse_ws_injection(raw: str, store: "TargetStore") -> list[dict]:
    """Parse WebSocket injection test output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for test in data.get("tests", []):
        if test.get("reflected") or test.get("error_leak"):
            entities.append(
                {
                    "type": "ws_finding",
                    "target": data.get("url", ""),
                    "check": f"ws_injection:{test.get('category', '')}",
                    "severity": test.get("severity", "medium"),
                    "value": test.get("payload", ""),
                    "reflected": test.get("reflected", False),
                    "error_leak": test.get("error_leak", False),
                    "response_preview": test.get("response_preview", ""),
                }
            )
    return entities


PARSER_MAP[("websocket_test", "auth_bypass")] = parse_ws_auth_bypass
PARSER_MAP[("websocket_test", "cswsh")] = parse_ws_cswsh
PARSER_MAP[("websocket_test", "injection")] = parse_ws_injection
