"""Parser for SPA security test output — route_bypass, state_inspect, postmessage, token_leakage, dom_xss, sourcemap_check."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_route_bypass(raw: str, store: "TargetStore") -> list[dict]:
    """Parse SPA route bypass test output — bypassed_routes array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for route in data.get("bypassed_routes", []):
        entities.append(
            {
                "type": "spa_finding",
                "target": data.get("url", ""),
                "check": f"route_bypass:{route.get('path', '')}",
                "severity": route.get("severity", "high"),
                "value": route.get("detail", ""),
                "path": route.get("path", ""),
                "guard": route.get("guard", ""),
            }
        )
    return entities


def parse_state_inspect(raw: str, store: "TargetStore") -> list[dict]:
    """Parse SPA state inspection output — exposed_state array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for item in data.get("exposed_state", []):
        entities.append(
            {
                "type": "spa_finding",
                "target": data.get("url", ""),
                "check": f"state_inspect:{item.get('store', '')}",
                "severity": item.get("severity", "medium"),
                "value": item.get("detail", ""),
                "store": item.get("store", ""),
                "key_path": item.get("key_path", ""),
            }
        )
    return entities


def parse_postmessage(raw: str, store: "TargetStore") -> list[dict]:
    """Parse postMessage handler scan output — handlers array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for handler in data.get("handlers", []):
        if not handler.get("origin_check", True):
            entities.append(
                {
                    "type": "spa_finding",
                    "target": data.get("url", ""),
                    "check": f"postmessage:{handler.get('location', '')}",
                    "severity": handler.get("severity", "high"),
                    "value": handler.get("detail", ""),
                    "origin_check": handler.get("origin_check", False),
                    "location": handler.get("location", ""),
                }
            )
    return entities


def parse_token_leakage(raw: str, store: "TargetStore") -> list[dict]:
    """Parse token leakage audit output — leaks array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for leak in data.get("leaks", []):
        entities.append(
            {
                "type": "spa_finding",
                "target": data.get("url", ""),
                "check": f"token_leakage:{leak.get('storage', '')}",
                "severity": leak.get("severity", "high"),
                "value": leak.get("detail", ""),
                "storage": leak.get("storage", ""),
                "token_type": leak.get("token_type", ""),
            }
        )
    return entities


def parse_dom_xss(raw: str, store: "TargetStore") -> list[dict]:
    """Parse DOM XSS scan output — sinks array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for sink in data.get("sinks", []):
        entities.append(
            {
                "type": "spa_finding",
                "target": data.get("url", ""),
                "check": f"dom_xss:{sink.get('sink_type', '')}",
                "severity": sink.get("severity", "high"),
                "value": sink.get("detail", ""),
                "sink_type": sink.get("sink_type", ""),
                "source": sink.get("source", ""),
                "location": sink.get("location", ""),
            }
        )
    return entities


def parse_sourcemap_check(raw: str, store: "TargetStore") -> list[dict]:
    """Parse source map exposure check output — exposed_maps array."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for smap in data.get("exposed_maps", []):
        entities.append(
            {
                "type": "spa_finding",
                "target": data.get("url", ""),
                "check": f"sourcemap:{smap.get('file', '')}",
                "severity": smap.get("severity", "medium"),
                "value": smap.get("detail", ""),
                "file": smap.get("file", ""),
                "map_url": smap.get("map_url", ""),
            }
        )
    return entities


PARSER_MAP[("spa_test", "route_bypass")] = parse_route_bypass
PARSER_MAP[("spa_test", "state_inspect")] = parse_state_inspect
PARSER_MAP[("spa_test", "postmessage_scan")] = parse_postmessage
PARSER_MAP[("spa_test", "token_leakage_audit")] = parse_token_leakage
PARSER_MAP[("spa_test", "dom_xss_scan")] = parse_dom_xss
PARSER_MAP[("spa_test", "js_source_map_check")] = parse_sourcemap_check
