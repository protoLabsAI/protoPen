#!/usr/bin/env python3
"""Attack graph builder.

Reads correlated asset data from JSON files in an input directory
and constructs an attack graph showing logical attack paths
(e.g., internet → CDN → WAF → API gateway → backend → database).
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import logging
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Node type classification based on technologies/labels
TECH_ROLES = {
    "cloudflare": "cdn_waf",
    "fastly": "cdn",
    "akamai": "cdn",
    "vercel": "edge_hosting",
    "netlify": "edge_hosting",
    "nginx": "web_server",
    "apache": "web_server",
    "iis": "web_server",
    "traefik": "reverse_proxy",
    "istio": "service_mesh",
    "kubernetes": "orchestration",
    "aws_alb": "load_balancer",
    "next_js": "frontend",
    "react": "frontend",
    "wordpress": "cms",
    "django": "backend",
    "rails": "backend",
    "express": "backend",
    "php": "backend",
    "laravel": "backend",
    "mysql": "database",
    "postgres": "database",
    "redis": "cache_db",
    "mongo": "database",
    "elastic": "search_db",
}

SUBDOMAIN_ROLES = {
    "api": "api_gateway",
    "auth": "auth_service",
    "sso": "auth_service",
    "login": "auth_service",
    "admin": "admin_panel",
    "portal": "admin_panel",
    "dashboard": "admin_panel",
    "db": "database",
    "database": "database",
    "mysql": "database",
    "postgres": "database",
    "redis": "cache_db",
    "mongo": "database",
    "cdn": "cdn",
    "static": "static_assets",
    "assets": "static_assets",
    "s3": "object_storage",
    "backup": "backup_storage",
    "mail": "mail_server",
    "smtp": "mail_server",
    "vpn": "vpn_gateway",
    "git": "scm",
    "gitlab": "scm",
    "jenkins": "ci_cd",
    "ci": "ci_cd",
    "grafana": "monitoring",
    "kibana": "monitoring",
    "metrics": "monitoring",
}


def _classify_node(host: str, technologies: list[str]) -> str:
    """Determine the role/type of a node."""
    subdomain = host.split(".")[0].lower()
    if subdomain in SUBDOMAIN_ROLES:
        return SUBDOMAIN_ROLES[subdomain]
    for tech in technologies:
        if tech in TECH_ROLES:
            return TECH_ROLES[tech]
    return "web_service"


def _load_assets(input_dir: str) -> list[dict[str, Any]]:
    """Load correlated asset data from JSON files."""
    assets: list[dict[str, Any]] = []
    for filepath in glob.glob(os.path.join(input_dir, "**/*.json"), recursive=True):
        try:
            with open(filepath) as fh:
                data = json.load(fh)
            # Handle asset_correlate output
            if isinstance(data, dict) and "assets" in data:
                assets.extend(data["assets"])
            # Handle recon_pipeline output
            elif isinstance(data, dict) and "subdomains" in data:
                for sub in data.get("subdomains", []):
                    if isinstance(sub, dict):
                        assets.append(
                            {
                                "host": sub.get("subdomain", ""),
                                "technologies": sub.get("technologies", []),
                                "ips": sub.get("ips", []),
                            }
                        )
        except Exception as exc:
            logger.debug("Skipping %s: %s", filepath, exc)
    return assets


def _build_attack_graph(domain: str, assets: list[dict[str, Any]]) -> tuple[list[dict], list[dict]]:
    """Build nodes and edges for the attack graph."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    node_map: dict[str, str] = {}  # host -> node_id
    next_id = [0]

    def _get_or_create_node(host: str, role: str, label: str | None = None) -> str:
        if host not in node_map:
            nid = f"n{next_id[0]}"
            next_id[0] += 1
            node_map[host] = nid
            nodes.append(
                {
                    "id": nid,
                    "label": label or host,
                    "host": host,
                    "role": role,
                }
            )
        return node_map[host]

    # Internet entry point
    internet_id = _get_or_create_node("internet", "internet", "Internet")

    # Domain root
    domain_id = _get_or_create_node(domain, "domain_root", domain)
    edges.append(
        {
            "from": internet_id,
            "to": domain_id,
            "label": "HTTP/HTTPS",
            "attack_path": "initial_access",
        }
    )

    # CDN/WAF layer (cloudflare, fastly, etc.)
    cdn_nodes: list[str] = []
    api_nodes: list[str] = []
    auth_nodes: list[str] = []
    backend_nodes: list[str] = []
    db_nodes: list[str] = []
    admin_nodes: list[str] = []

    for asset in assets:
        host = asset.get("host", "")
        if not host:
            continue
        techs = asset.get("technologies", []) or []
        role = _classify_node(host, techs)
        node_id = _get_or_create_node(host, role)

        if role in ("cdn", "cdn_waf"):
            cdn_nodes.append(node_id)
        elif role in ("api_gateway",):
            api_nodes.append(node_id)
        elif role in ("auth_service",):
            auth_nodes.append(node_id)
        elif role in ("backend", "web_service", "web_server", "cms"):
            backend_nodes.append(node_id)
        elif role in ("database", "cache_db", "search_db", "object_storage", "backup_storage"):
            db_nodes.append(node_id)
        elif role in ("admin_panel",):
            admin_nodes.append(node_id)

    # Build edges: internet → CDN → backend/API → database
    prev_layer = [domain_id]

    if cdn_nodes:
        for cdn_id in cdn_nodes:
            edges.append({"from": internet_id, "to": cdn_id, "label": "HTTP/HTTPS", "attack_path": "initial_access"})
        prev_layer = cdn_nodes

    for api_id in api_nodes:
        for src_id in prev_layer:
            edges.append({"from": src_id, "to": api_id, "label": "API request", "attack_path": "api_abuse"})
        for auth_id in auth_nodes:
            edges.append({"from": api_id, "to": auth_id, "label": "auth check", "attack_path": "auth_bypass"})
        for db_id in db_nodes:
            edges.append({"from": api_id, "to": db_id, "label": "DB query", "attack_path": "data_exfiltration"})

    for backend_id in backend_nodes:
        for src_id in prev_layer:
            if src_id not in api_nodes:
                edges.append({"from": src_id, "to": backend_id, "label": "HTTP request", "attack_path": "web_attack"})
        for db_id in db_nodes:
            edges.append({"from": backend_id, "to": db_id, "label": "DB query", "attack_path": "data_exfiltration"})

    for admin_id in admin_nodes:
        edges.append(
            {"from": internet_id, "to": admin_id, "label": "direct access", "attack_path": "admin_panel_exposure"}
        )

    for auth_id in auth_nodes:
        for src_id in prev_layer:
            edges.append({"from": src_id, "to": auth_id, "label": "auth request", "attack_path": "credential_attack"})

    return nodes, edges


def main() -> None:
    parser = argparse.ArgumentParser(description="Attack graph builder")
    parser.add_argument("--input-dir", required=True, help="Directory containing recon/correlation JSON files")
    parser.add_argument("--domain", required=True, help="Root domain for the attack graph")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"nodes": [], "edges": []}

    try:
        if not os.path.isdir(args.input_dir):
            result["error"] = f"Input directory not found: {args.input_dir}"
            print(json.dumps(result))
            return

        assets = _load_assets(args.input_dir)
        nodes, edges = _build_attack_graph(args.domain, assets)
        result["nodes"] = nodes
        result["edges"] = edges
        result["summary"] = {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "attack_paths": list({e.get("attack_path") for e in edges if e.get("attack_path")}),
        }

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("attack_graph error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
