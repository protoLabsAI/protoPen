#!/usr/bin/env python3
"""Typosquatting scanner.

Generates common typosquat variants of a package name and checks
each against the given registry, returning matches that exist.
"""
from __future__ import annotations

import argparse
import json
import sys
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urljoin

import requests
from protopen_scripts._common import make_session

logger = logging.getLogger(__name__)


def _generate_typosquats(name: str) -> set[str]:
    """Generate typosquat candidates for a package name."""
    candidates: set[str] = set()

    # Handle scoped packages
    scope = ""
    base_name = name
    if name.startswith('@') and '/' in name:
        scope, base_name = name.split('/', 1)

    # 1. Character transpositions
    for i in range(len(base_name) - 1):
        swapped = list(base_name)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        candidates.add(''.join(swapped))

    # 2. Character substitutions (common keyboard neighbors)
    neighbors = {
        'a': 'sq', 'b': 'vn', 'c': 'xv', 'd': 'sf', 'e': 'wr', 'f': 'dg',
        'g': 'fh', 'h': 'gj', 'i': 'uo', 'j': 'hk', 'k': 'jl', 'l': 'k',
        'm': 'n', 'n': 'mb', 'o': 'ip', 'p': 'o', 'q': 'w', 'r': 'et',
        's': 'ad', 't': 'ry', 'u': 'yi', 'v': 'bc', 'w': 'qe', 'x': 'zc',
        'y': 'tu', 'z': 'x',
    }
    for i, ch in enumerate(base_name):
        if ch in neighbors:
            for sub in neighbors[ch]:
                variant = base_name[:i] + sub + base_name[i + 1:]
                candidates.add(variant)

    # 3. Character omissions
    for i in range(len(base_name)):
        candidates.add(base_name[:i] + base_name[i + 1:])

    # 4. Character duplications
    for i, ch in enumerate(base_name):
        candidates.add(base_name[:i] + ch + base_name[i:])

    # 5. Hyphen/underscore substitution
    if '-' in base_name:
        candidates.add(base_name.replace('-', '_'))
        candidates.add(base_name.replace('-', ''))
    if '_' in base_name:
        candidates.add(base_name.replace('_', '-'))
        candidates.add(base_name.replace('_', ''))

    # 6. Common prefix/suffix additions
    for affix in ('js', 'ts', 'node', 'npm', 'pkg', '-js', '-ts', '-node', '-lib', 'lib'):
        if not base_name.endswith(affix):
            candidates.add(base_name + '-' + affix)
        if not base_name.startswith(affix):
            candidates.add(affix + '-' + base_name)

    # 7. Common misspellings of 'lib', 'util', 'helper'
    for orig, repl in [('lib', 'libs'), ('util', 'utils'), ('helper', 'helpers'), ('react', 'reakt')]:
        if orig in base_name:
            candidates.add(base_name.replace(orig, repl))

    # Remove the original name and empty strings
    candidates.discard(base_name)
    candidates.discard('')
    candidates.discard(name)

    # Re-apply scope if present
    if scope:
        return {f"{scope}/{c}" for c in candidates}
    return candidates


def _similarity(a: str, b: str) -> float:
    """Simple character-level similarity ratio."""
    if not a or not b:
        return 0.0
    # Levenshtein distance approximation
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return 0.0
    # Count common chars
    common = sum(1 for ca, cb in zip(a, b) if ca == cb)
    return common / max(la, lb)


def _check_npm_package(session: requests.Session, registry: str, package_name: str) -> dict[str, Any] | None:
    """Check if package exists on npm registry."""
    encoded = package_name.replace('/', '%2F') if package_name.startswith('@') else package_name
    url = urljoin(registry.rstrip('/') + '/', encoded)
    try:
        resp = session.get(url, timeout=12)
        if resp.status_code == 200:
            try:
                data = resp.json()
                latest = data.get('dist-tags', {}).get('latest', 'unknown')
                dl_data = data.get('downloads', {})
                downloads = dl_data.get('monthly', 0) if isinstance(dl_data, dict) else 0
                return {"exists": True, "latest": latest, "downloads": downloads}
            except Exception:
                return {"exists": True, "latest": "unknown", "downloads": 0}
    except requests.RequestException as exc:
        logger.debug("Registry check failed for %s: %s", package_name, exc)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Typosquatting scanner")
    parser.add_argument("--package", required=True, help="Package name to check for typosquats")
    parser.add_argument("--registry", default="https://registry.npmjs.org", help="Package registry URL")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"candidates": []}

    try:
        typosquats = _generate_typosquats(args.package)
        session = make_session()

        def _check(variant: str) -> dict[str, Any] | None:
            meta = _check_npm_package(session, args.registry, variant)
            if meta and meta.get("exists"):
                sim = _similarity(args.package, variant)
                return {
                    "name": variant,
                    "similarity": round(sim, 3),
                    "downloads": meta.get("downloads", 0),
                    "latest_version": meta.get("latest", "unknown"),
                    "severity": "high" if sim > 0.8 else "medium",
                }
            return None

        # Cap at 200 candidates to avoid excessive requests
        candidates_list = list(typosquats)[:200]
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(_check, v): v for v in candidates_list}
            for future in as_completed(futures):
                finding = future.result()
                if finding:
                    result["candidates"].append(finding)

        # Sort by similarity descending
        result["candidates"].sort(key=lambda x: x["similarity"], reverse=True)
        result["package_checked"] = args.package
        result["total_variants_checked"] = len(candidates_list)

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("typosquat error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
