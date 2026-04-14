#!/usr/bin/env python3
"""Package provenance auditor.

Fetches package metadata from a registry and checks for supply chain
integrity indicators: repository URL, license, author, age, and download metrics.
"""

from __future__ import annotations

import argparse
import json
import sys
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import requests
from protopen_scripts._common import make_session

logger = logging.getLogger(__name__)


def _parse_date(date_str: str | None) -> datetime | None:
    """Parse ISO date string."""
    if not date_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str.split("+")[0].rstrip("Z"), fmt.rstrip("Z"))
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def fetch_npm_metadata(session: requests.Session, registry: str, package_name: str) -> dict[str, Any] | None:
    """Fetch npm package metadata."""
    encoded = package_name.replace("/", "%2F") if package_name.startswith("@") else package_name
    url = urljoin(registry.rstrip("/") + "/", encoded)
    try:
        resp = session.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException as exc:
        logger.debug("npm metadata fetch failed: %s", exc)
    return None


def fetch_pypi_metadata(session: requests.Session, package_name: str) -> dict[str, Any] | None:
    """Fetch PyPI package metadata."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        resp = session.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException as exc:
        logger.debug("PyPI metadata fetch failed: %s", exc)
    return None


def run_npm_checks(data: dict[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    name = data.get("name", "unknown")

    # Repository
    repo = data.get("repository")
    has_repo = bool(repo)
    checks.append(
        {
            "check_name": "repository_present",
            "passed": has_repo,
            "details": str(repo.get("url", repo) if isinstance(repo, dict) else repo)
            if has_repo
            else "No repository URL in package metadata",
        }
    )

    # License
    license_val = data.get("license", "")
    has_license = bool(license_val)
    checks.append(
        {
            "check_name": "license_present",
            "passed": has_license,
            "details": license_val if has_license else "No license declared",
        }
    )

    # Author
    author = data.get("author")
    has_author = bool(author)
    checks.append(
        {
            "check_name": "author_present",
            "passed": has_author,
            "details": str(author.get("name", author) if isinstance(author, dict) else author)
            if has_author
            else "No author in package metadata",
        }
    )

    # Creation date / freshness
    time_data = data.get("time", {})
    created_str = time_data.get("created") if isinstance(time_data, dict) else None
    created = _parse_date(created_str)
    if created:
        now = datetime.now(timezone.utc)
        age_days = (now - created).days
        is_fresh = age_days < 30
        checks.append(
            {
                "check_name": "package_age",
                "passed": not is_fresh,
                "details": f"Package created {age_days} days ago ({created.strftime('%Y-%m-%d')})"
                + (" — SUSPICIOUSLY RECENT" if is_fresh else ""),
            }
        )
    else:
        checks.append(
            {
                "check_name": "package_age",
                "passed": None,
                "details": "Could not determine package creation date",
            }
        )

    # Maintainers
    maintainers = data.get("maintainers", [])
    checks.append(
        {
            "check_name": "maintainers_present",
            "passed": bool(maintainers),
            "details": f"{len(maintainers)} maintainer(s): {', '.join(m.get('name', str(m)) for m in maintainers[:3]) if maintainers else 'none'}",
        }
    )

    # Downloads (npm downloads API)
    latest_version = data.get("dist-tags", {}).get("latest", "")
    version_data = data.get("versions", {}).get(latest_version, {}) if latest_version else {}
    has_dist = bool(version_data.get("dist", {}).get("tarball"))
    checks.append(
        {
            "check_name": "dist_tarball_present",
            "passed": has_dist,
            "details": "Distribution tarball URL present" if has_dist else "No distribution tarball found",
        }
    )

    # Check for install scripts
    scripts = version_data.get("scripts", {}) if version_data else {}
    dangerous_scripts = {
        k: v
        for k, v in scripts.items()
        if k in ("postinstall", "install", "preinstall")
        and any(cmd in str(v) for cmd in ("curl", "wget", "eval", "exec", "bash", "sh "))
    }
    if dangerous_scripts:
        checks.append(
            {
                "check_name": "no_dangerous_install_scripts",
                "passed": False,
                "details": f"Dangerous install script(s) detected: {dangerous_scripts}",
            }
        )
    else:
        checks.append(
            {
                "check_name": "no_dangerous_install_scripts",
                "passed": True,
                "details": "No dangerous install scripts detected in package metadata",
            }
        )

    return checks


def run_pypi_checks(data: dict[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    info = data.get("info", {})

    checks.append(
        {
            "check_name": "repository_present",
            "passed": bool(info.get("project_url") or info.get("home_page") or info.get("project_urls")),
            "details": info.get("home_page", "") or str(info.get("project_urls", "")),
        }
    )

    checks.append(
        {
            "check_name": "license_present",
            "passed": bool(info.get("license")),
            "details": info.get("license", "No license declared"),
        }
    )

    checks.append(
        {
            "check_name": "author_present",
            "passed": bool(info.get("author") or info.get("maintainer")),
            "details": info.get("author", "") or info.get("maintainer", "No author declared"),
        }
    )

    # Upload date of latest version
    releases = data.get("releases", {})
    latest = info.get("version", "")
    if latest and latest in releases:
        release_files = releases[latest]
        if release_files:
            upload_date_str = release_files[0].get("upload_time")
            created = _parse_date(upload_date_str)
            if created:
                now = datetime.now(timezone.utc)
                age_days = (now - created).days
                is_fresh = age_days < 30
                checks.append(
                    {
                        "check_name": "package_age",
                        "passed": not is_fresh,
                        "details": f"Latest version uploaded {age_days} days ago"
                        + (" — SUSPICIOUSLY RECENT" if is_fresh else ""),
                    }
                )

    return checks


def main() -> None:
    parser = argparse.ArgumentParser(description="Package provenance auditor")
    parser.add_argument("--package", required=True, help="Package name to audit")
    parser.add_argument("--registry", default="https://registry.npmjs.org", help="Package registry URL")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"checks": []}

    try:
        session = make_session()

        is_pypi = "pypi.org" in args.registry
        if is_pypi:
            data = fetch_pypi_metadata(session, args.package)
        else:
            data = fetch_npm_metadata(session, args.registry, args.package)

        if data is None:
            result["error"] = f"Package '{args.package}' not found on registry {args.registry}"
            result["checks"].append(
                {
                    "check_name": "package_exists",
                    "passed": False,
                    "details": f"Package not found on {args.registry}",
                }
            )
        else:
            result["checks"].append(
                {
                    "check_name": "package_exists",
                    "passed": True,
                    "details": f"Package found on {args.registry}",
                }
            )
            if is_pypi:
                result["checks"].extend(run_pypi_checks(data))
            else:
                result["checks"].extend(run_npm_checks(data))

        result["package"] = args.package
        result["registry"] = args.registry
        result["passed"] = sum(1 for c in result["checks"] if c.get("passed") is True)
        result["failed"] = sum(1 for c in result["checks"] if c.get("passed") is False)

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("provenance error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
