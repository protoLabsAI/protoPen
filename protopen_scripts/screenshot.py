#!/usr/bin/env python3
"""URL liveness checker and screenshot placeholder.

For each URL in the targets file, makes a HEAD/GET request to verify
liveness. Since no headless browser is available, records live/dead status
and saves a placeholder file. This is a pure-HTTP implementation.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests
from protopen_scripts._common import make_headers, make_session

logger = logging.getLogger(__name__)


def _load_targets(path: str) -> list[str]:
    """Load URLs from a newline-delimited file."""
    try:
        with open(path) as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.startswith('#')]
    except OSError as exc:
        logger.error("Could not read targets file %s: %s", path, exc)
        return []


def _probe_url(url: str, timeout: int = 10) -> dict[str, Any]:
    """Probe a single URL for liveness."""
    entry: dict[str, Any] = {"url": url, "status": "unknown", "path": "", "http_status": None}
    try:
        resp = requests.head(url, timeout=timeout, allow_redirects=True, headers=make_headers())
        entry["http_status"] = resp.status_code
        entry["status"] = "live" if resp.status_code < 500 else "error"
        entry["final_url"] = resp.url
        entry["server"] = resp.headers.get("Server", "")
        entry["content_type"] = resp.headers.get("Content-Type", "")
    except requests.ConnectionError:
        entry["status"] = "unreachable"
    except requests.Timeout:
        entry["status"] = "timeout"
    except requests.RequestException as exc:
        entry["status"] = "error"
        entry["error"] = str(exc)

    return entry


def _save_placeholder(output_dir: str, url: str, entry: dict[str, Any]) -> str:
    """Save a JSON placeholder for the screenshot."""
    safe_name = re.sub(r'[^\w\-.]', '_', url.replace('://', '_'))[:100]
    filename = f"{safe_name}.json"
    filepath = os.path.join(output_dir, filename)
    try:
        with open(filepath, 'w') as fh:
            json.dump(entry, fh, indent=2)
    except OSError as exc:
        logger.warning("Could not save placeholder for %s: %s", url, exc)
        return ""
    return filepath


def main() -> None:
    parser = argparse.ArgumentParser(description="URL liveness checker and screenshot placeholder")
    parser.add_argument("--targets-file", required=True, help="File containing URLs to check (one per line)")
    parser.add_argument("--output-dir", default="/tmp/screenshots", help="Output directory for placeholders")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"screenshots": []}

    try:
        os.makedirs(args.output_dir, exist_ok=True)
        targets = _load_targets(args.targets_file)

        if not targets:
            result["error"] = f"No targets found in {args.targets_file}"
            print(json.dumps(result))
            return

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(_probe_url, url): url for url in targets}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    entry = future.result()
                    # Save placeholder
                    placeholder_path = _save_placeholder(args.output_dir, url, entry)
                    if placeholder_path:
                        entry["path"] = placeholder_path
                    result["screenshots"].append(entry)
                except Exception as exc:
                    result["screenshots"].append({
                        "url": url,
                        "status": "error",
                        "path": "",
                        "error": str(exc),
                    })

        # Sort by URL for deterministic output
        result["screenshots"].sort(key=lambda x: x.get("url", ""))

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("screenshot error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
