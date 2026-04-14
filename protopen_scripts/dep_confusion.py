#!/usr/bin/env python3
"""Dependency confusion tester.

Reads package names from a file and checks whether each exists as a public
package on the given registry. Internal packages (no dots, short names) with
a public counterpart are flagged as potential dependency confusion targets.
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
from urllib.parse import urljoin

import requests
from protopen_scripts._common import make_session

logger = logging.getLogger(__name__)


def _looks_internal(name: str) -> bool:
    """Heuristic: package name looks like an internal/private package."""
    # Scoped packages with @company/ prefix are common internal indicators
    if name.startswith("@") and "/" in name:
        scope = name.split("/")[0]
        # Known public scopes are not internal
        public_scopes = {
            "@angular",
            "@babel",
            "@types",
            "@vue",
            "@nuxt",
            "@nestjs",
            "@aws-sdk",
            "@google-cloud",
            "@microsoft",
            "@emotion",
            "@mui",
            "@chakra-ui",
            "@testing-library",
            "@storybook",
            "@jest",
            "@rollup",
            "@eslint",
            "@prettier",
            "@jest-community",
        }
        if scope.lower() not in public_scopes:
            return True

    # Short names without dots/hyphens, or names matching common internal patterns
    if re.match(r"^[a-z][a-z0-9]{1,12}$", name) and "." not in name:
        # Exclude very common public packages
        common_public = {
            "lodash",
            "express",
            "react",
            "webpack",
            "babel",
            "axios",
            "moment",
            "jquery",
            "chalk",
            "debug",
            "yargs",
            "commander",
            "glob",
            "async",
            "jest",
            "mocha",
            "eslint",
            "prettier",
            "typescript",
            "nodemon",
            "dotenv",
            "cors",
            "helmet",
            "morgan",
            "uuid",
            "bcrypt",
            "jsonwebtoken",
            "sequelize",
            "mongoose",
            "redis",
            "mysql",
            "postgres",
            "pg",
        }
        if name not in common_public:
            return True

    return False


def _check_npm_registry(session: requests.Session, registry: str, package_name: str) -> dict[str, Any] | None:
    """Check if package exists on npm registry. Return metadata or None."""
    # Handle scoped packages
    encoded = package_name.replace("/", "%2F") if package_name.startswith("@") else package_name
    url = urljoin(registry.rstrip("/") + "/", encoded)
    try:
        resp = session.get(url, timeout=15)
        if resp.status_code == 200:
            try:
                data = resp.json()
                latest = data.get("dist-tags", {}).get("latest", "")
                versions = list(data.get("versions", {}).keys())
                return {
                    "exists": True,
                    "latest": latest,
                    "versions": versions[-3:] if versions else [],
                    "description": data.get("description", ""),
                    "author": str(data.get("author", "")),
                }
            except Exception:
                return {"exists": True, "latest": "unknown", "versions": [], "description": "", "author": ""}
        return None
    except requests.RequestException as exc:
        logger.debug("Registry check failed for %s: %s", package_name, exc)
        return None


def _check_pypi(session: requests.Session, package_name: str) -> dict[str, Any] | None:
    """Check PyPI for a package."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        resp = session.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            info = data.get("info", {})
            return {
                "exists": True,
                "latest": info.get("version", "unknown"),
                "versions": [],
                "description": info.get("summary", ""),
                "author": info.get("author", ""),
            }
        return None
    except requests.RequestException:
        return None


def check_package(session: requests.Session, registry: str, package_name: str) -> dict[str, Any] | None:
    """Check if package exists on public registry."""
    is_pypi = "pypi.org" in registry
    if is_pypi:
        return _check_pypi(session, package_name)
    return _check_npm_registry(session, registry, package_name)


def main() -> None:
    parser = argparse.ArgumentParser(description="Dependency confusion tester")
    parser.add_argument("--registry", default="https://registry.npmjs.org", help="Package registry URL")
    parser.add_argument("--packages-file", required=True, help="File containing package names (one per line)")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"confused_packages": []}

    try:
        if not os.path.isfile(args.packages_file):
            result["error"] = f"Packages file not found: {args.packages_file}"
            print(json.dumps(result))
            return

        with open(args.packages_file) as fh:
            packages = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

        session = make_session()

        def _check(pkg: str) -> dict[str, Any] | None:
            if not _looks_internal(pkg):
                return None
            meta = check_package(session, args.registry, pkg)
            if meta and meta.get("exists"):
                return {
                    "name": pkg,
                    "severity": "critical",
                    "internal_version": "1.0.0",  # unknown without lock file
                    "public_version": meta.get("latest", "unknown"),
                    "description": meta.get("description", ""),
                    "detail": f"Internal-looking package '{pkg}' has a public counterpart (v{meta.get('latest', '?')}) — dependency confusion attack surface",
                }
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(_check, pkg): pkg for pkg in packages}
            for future in as_completed(futures):
                finding = future.result()
                if finding:
                    result["confused_packages"].append(finding)

        result["confused_packages"].sort(key=lambda x: x["name"])

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("dep_confusion error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
