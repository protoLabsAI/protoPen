#!/usr/bin/env python3
"""Asset correlator.

Reads JSON files from an input directory (produced by recon tools),
correlates IPs, domains, and technologies across all sources,
and returns a unified asset summary with cross-source correlations.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)


def _load_json_files(input_dir: str) -> list[tuple[str, Any]]:
    """Load all JSON files from the directory."""
    files: list[tuple[str, Any]] = []
    for filepath in glob.glob(os.path.join(input_dir, "**/*.json"), recursive=True):
        try:
            with open(filepath) as fh:
                data = json.load(fh)
            files.append((filepath, data))
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("Skipping %s: %s", filepath, exc)
    return files


def _extract_assets(filename: str, data: Any) -> list[dict[str, Any]]:
    """Extract asset records from a JSON blob."""
    assets: list[dict[str, Any]] = []
    source = os.path.basename(filename)

    if not isinstance(data, dict):
        return assets

    # Subdomains from recon_pipeline format
    for sub in data.get("subdomains", []):
        if isinstance(sub, dict):
            asset: dict[str, Any] = {
                "type": "subdomain",
                "host": sub.get("subdomain", ""),
                "ips": sub.get("ips", []),
                "technologies": sub.get("technologies", []),
                "source": source,
                "http_status": sub.get("status"),
                "url": sub.get("url", ""),
            }
            assets.append(asset)

    # Screenshots/live URLs
    for shot in data.get("screenshots", []):
        if isinstance(shot, dict) and shot.get("status") == "live":
            from urllib.parse import urlparse
            parsed = urlparse(shot.get("url", ""))
            assets.append({
                "type": "url",
                "host": parsed.netloc or shot.get("url", ""),
                "ips": [],
                "technologies": [],
                "source": source,
                "http_status": shot.get("http_status"),
                "url": shot.get("url", ""),
            })

    # Direct domain/IP entries
    if "domain" in data and "dns" in data:
        assets.append({
            "type": "domain",
            "host": data["domain"],
            "ips": data.get("dns", {}).get("ips", []),
            "technologies": list(data.get("technologies", {}).keys()),
            "source": source,
            "http_status": None,
            "url": "",
        })

    # Findings with URLs
    for finding in data.get("findings", []):
        if isinstance(finding, dict) and "url" in finding:
            from urllib.parse import urlparse
            parsed = urlparse(finding["url"])
            if parsed.netloc:
                assets.append({
                    "type": "finding_url",
                    "host": parsed.netloc,
                    "ips": [],
                    "technologies": [],
                    "source": source,
                    "severity": finding.get("severity", "info"),
                    "url": finding["url"],
                })

    return assets


def _build_correlations(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find IPs/hosts that appear across multiple sources."""
    ip_to_hosts: dict[str, set[str]] = defaultdict(set)
    host_to_sources: dict[str, set[str]] = defaultdict(set)
    tech_to_hosts: dict[str, set[str]] = defaultdict(set)

    for asset in assets:
        host = asset.get("host", "")
        if host:
            host_to_sources[host].add(asset.get("source", ""))
        for ip in asset.get("ips", []):
            ip_to_hosts[ip].add(host)
        for tech in asset.get("technologies", []):
            tech_to_hosts[tech].add(host)

    correlations: list[dict[str, Any]] = []

    # Hosts seen across multiple files
    for host, sources in host_to_sources.items():
        if len(sources) > 1:
            correlations.append({
                "type": "cross_source_host",
                "host": host,
                "sources": list(sources),
                "detail": f"Host '{host}' appears in {len(sources)} sources: {', '.join(sorted(sources))}",
            })

    # IPs shared by multiple hosts (potential shared infrastructure)
    for ip, hosts in ip_to_hosts.items():
        if len(hosts) > 1:
            correlations.append({
                "type": "shared_ip",
                "ip": ip,
                "hosts": list(hosts),
                "detail": f"IP {ip} shared by {len(hosts)} hosts — possible shared infrastructure",
            })

    # Technologies seen across multiple hosts
    for tech, hosts in tech_to_hosts.items():
        if len(hosts) > 2:
            correlations.append({
                "type": "common_technology",
                "technology": tech,
                "hosts": list(hosts),
                "detail": f"Technology '{tech}' detected on {len(hosts)} hosts",
            })

    return correlations


def main() -> None:
    parser = argparse.ArgumentParser(description="Asset correlator across recon results")
    parser.add_argument("--input-dir", required=True, help="Directory containing recon JSON files")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"assets": [], "correlations": []}

    try:
        if not os.path.isdir(args.input_dir):
            result["error"] = f"Input directory not found: {args.input_dir}"
            print(json.dumps(result))
            return

        files = _load_json_files(args.input_dir)

        if not files:
            result["error"] = f"No JSON files found in {args.input_dir}"
            print(json.dumps(result))
            return

        all_assets: list[dict[str, Any]] = []
        for filepath, data in files:
            assets = _extract_assets(filepath, data)
            all_assets.extend(assets)

        # Deduplicate assets by (type, host, url)
        seen: set[tuple] = set()
        deduped: list[dict[str, Any]] = []
        for asset in all_assets:
            key = (asset.get("type"), asset.get("host"), asset.get("url", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(asset)

        result["assets"] = deduped
        result["correlations"] = _build_correlations(deduped)
        result["summary"] = {
            "total_assets": len(deduped),
            "total_correlations": len(result["correlations"]),
            "files_processed": len(files),
        }

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("asset_correlate error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
