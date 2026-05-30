"""Parser for recon_pipeline output — subdomains, httpx probes, nuclei findings,
screenshots, asset correlation, attack graph, and tech detection.

Mixed inputs: the protopen_scripts actions emit a single JSON object with named
arrays; the raw nuclei/httpx actions emit JSON Lines (one object per line).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def _iter_jsonl(raw: str):
    """Yield parsed objects from JSON Lines output (skips blank/garbage lines)."""
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def parse_full_pipeline(raw: str, store: "TargetStore") -> list[dict]:
    """Parse the full pipeline JSON — {"subdomains": [...], "technologies": {...}}."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for sub in data.get("subdomains", []):
        techs = ", ".join(sub.get("technologies", []) or [])
        ips = ", ".join(sub.get("ips", []) or [])
        entities.append(
            {
                "type": "recon_asset",
                "check": "subdomain",
                "target": sub.get("subdomain", ""),
                "severity": "info",
                "value": f"status={sub.get('status', '?')} ips=[{ips}] tech=[{techs}]",
            }
        )
    return entities


def parse_subdomain_httpx(raw: str, store: "TargetStore") -> list[dict]:
    """Parse httpx -json output (JSONL) — one probed host per line."""
    entities: list[dict] = []
    for obj in _iter_jsonl(raw):
        entities.append(
            {
                "type": "recon_asset",
                "check": "subdomain_httpx",
                "target": obj.get("url", obj.get("input", obj.get("host", ""))),
                "severity": "info",
                "value": f"status={obj.get('status_code', '?')} title={obj.get('title', '')}",
            }
        )
    return entities


def parse_nuclei(raw: str, store: "TargetStore") -> list[dict]:
    """Parse nuclei -json output (JSONL) — one finding per line."""
    entities: list[dict] = []
    for obj in _iter_jsonl(raw):
        info = obj.get("info", {}) if isinstance(obj.get("info"), dict) else {}
        entities.append(
            {
                "type": "recon_finding",
                "category": "nuclei",
                "check": obj.get("template-id", obj.get("template", "nuclei")),
                "target": obj.get("matched-at", obj.get("host", "")),
                "severity": info.get("severity", "info"),
                "title": info.get("name", ""),
                "value": info.get("name", obj.get("template-id", "")),
            }
        )
    return entities


def parse_screenshot(raw: str, store: "TargetStore") -> list[dict]:
    """Parse screenshot capture JSON — {"screenshots": [{url, status, path}]}."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for shot in data.get("screenshots", []):
        entities.append(
            {
                "type": "recon_asset",
                "check": "screenshot",
                "target": shot.get("url", ""),
                "severity": "info",
                "value": f"status={shot.get('status', '?')} path={shot.get('path', '')}",
            }
        )
    return entities


def parse_asset_correlate(raw: str, store: "TargetStore") -> list[dict]:
    """Parse asset correlation JSON — {"assets": [...], "correlations": [...]}."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for asset in data.get("assets", []):
        techs = ", ".join(asset.get("technologies", []) or [])
        entities.append(
            {
                "type": "recon_asset",
                "check": f"asset:{asset.get('type', 'host')}",
                "target": asset.get("host", asset.get("url", "")),
                "severity": "info",
                "value": f"source={asset.get('source', '')} tech=[{techs}]",
            }
        )
    return entities


def parse_attack_graph(raw: str, store: "TargetStore") -> list[dict]:
    """Parse attack-graph JSON — {"nodes": [...], "edges": [...]}."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for node in data.get("nodes", []):
        if not isinstance(node, dict):
            continue
        entities.append(
            {
                "type": "recon_finding",
                "category": "attack_graph",
                "check": "attack_graph_node",
                "target": node.get("id", node.get("host", node.get("label", ""))),
                "severity": node.get("severity", "info"),
                "value": node.get("category", node.get("type", node.get("label", ""))),
            }
        )
    return entities


def parse_tech_detect(raw: str, store: "TargetStore") -> list[dict]:
    """Parse httpx -tech-detect -json output (JSONL)."""
    entities: list[dict] = []
    for obj in _iter_jsonl(raw):
        tech = obj.get("tech", obj.get("technologies", []))
        if isinstance(tech, list):
            tech = ", ".join(str(t) for t in tech)
        entities.append(
            {
                "type": "recon_asset",
                "check": "tech_detect",
                "target": obj.get("url", obj.get("input", "")),
                "severity": "info",
                "value": str(tech),
            }
        )
    return entities


PARSER_MAP[("recon_pipeline", "full_pipeline")] = parse_full_pipeline
PARSER_MAP[("recon_pipeline", "subdomain_httpx")] = parse_subdomain_httpx
PARSER_MAP[("recon_pipeline", "nuclei_scan")] = parse_nuclei
PARSER_MAP[("recon_pipeline", "screenshot_capture")] = parse_screenshot
PARSER_MAP[("recon_pipeline", "asset_correlate")] = parse_asset_correlate
PARSER_MAP[("recon_pipeline", "attack_graph_build")] = parse_attack_graph
PARSER_MAP[("recon_pipeline", "tech_detect")] = parse_tech_detect
