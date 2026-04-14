#!/usr/bin/env python3
"""SPA client-side route guard bypass tester.

Tests whether protected SPA routes are accessible without authentication
by probing them directly without session cookies.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import logging
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from protopen_scripts._common import make_session

logger = logging.getLogger(__name__)

PROTECTED_PATTERNS = re.compile(
    r"(?:dashboard|admin|settings|profile|account|portal|manage|console|"
    r"user|member|secure|private|internal|staff|panel|config|billing|orders|"
    r"reports|analytics|workspace|org|team)",
    re.IGNORECASE,
)

LOGIN_PATTERNS = re.compile(r"(?:login|signin|sign-in|logout|sign-out)", re.IGNORECASE)

# JS route patterns: look for route definitions like path: '/admin'
ROUTE_PATTERN = re.compile(
    r"""(?:path|route|href|to)\s*[=:]\s*['"`](/[a-z0-9_\-/]+)['"`]""",
    re.IGNORECASE,
)

# Anchor href patterns
HREF_PATTERN = re.compile(r'href=["\']([^"\'#?]+)["\']', re.IGNORECASE)


def extract_routes_from_html(html: str, base_url: str) -> list[str]:
    """Extract href links and JS route strings from HTML."""
    routes: set[str] = set()

    parsed_base = urlparse(base_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    for href in HREF_PATTERN.findall(html):
        href = href.strip()
        if href.startswith("/") and not href.startswith("//"):
            routes.add(href)
        elif href.startswith(base_origin):
            path = urlparse(href).path
            if path:
                routes.add(path)

    for m in ROUTE_PATTERN.finditer(html):
        path = m.group(1)
        if path and path != "/":
            routes.add(path)

    return list(routes)


def load_routes_from_file(path: str) -> list[str]:
    """Load routes from a newline-delimited file."""
    try:
        with open(path) as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    except OSError as exc:
        logger.warning("Could not read routes file %s: %s", path, exc)
        return []


def is_protected_route(path: str) -> bool:
    return bool(PROTECTED_PATTERNS.search(path)) and not bool(LOGIN_PATTERNS.search(path))


def classify_response(resp: requests.Response, base_url: str) -> str | None:
    """Return 'bypassed' if response indicates unauthenticated access was allowed."""
    if resp.status_code == 200:
        return "bypassed"
    # 302/301 redirect to login is expected — not bypassed
    if resp.status_code in (301, 302, 303, 307, 308):
        loc = resp.headers.get("Location", "")
        if LOGIN_PATTERNS.search(loc):
            return None
        # redirect away from expected auth flow
        return None
    return None


def probe_route(base_url: str, path: str, session: requests.Session) -> dict[str, Any] | None:
    """Probe a route without auth cookies. Return finding dict or None."""
    url = urljoin(base_url, path)
    try:
        resp = session.get(url, allow_redirects=False, timeout=10)
    except requests.RequestException as exc:
        logger.debug("Request failed for %s: %s", url, exc)
        return None

    result = classify_response(resp, base_url)
    if result == "bypassed":
        return {
            "path": path,
            "severity": "high",
            "detail": f"Route returned {resp.status_code} without authentication",
            "guard": "none",
        }
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="SPA route guard bypass tester")
    parser.add_argument("--url", required=True, help="Target SPA URL")
    parser.add_argument("--routes-file", default="", help="Optional file of routes to test")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"url": args.url, "bypassed_routes": []}

    try:
        # Use a clean session with no cookies
        session = make_session()

        # Fetch the landing page to get routes
        resp = session.get(args.url, timeout=15)
        html = resp.text

        # Gather JS content from linked scripts for more route extraction
        js_urls: list[str] = []
        script_src_re = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
        parsed_base = urlparse(args.url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        for src in script_src_re.findall(html):
            if src.startswith("http"):
                js_urls.append(src)
            elif src.startswith("//"):
                js_urls.append(f"{parsed_base.scheme}:{src}")
            elif src.startswith("/"):
                js_urls.append(f"{base_origin}{src}")

        combined = html
        for js_url in js_urls[:10]:  # limit to first 10 scripts
            try:
                js_resp = session.get(js_url, timeout=10)
                combined += js_resp.text
            except requests.RequestException:
                pass

        routes = extract_routes_from_html(combined, args.url)

        if args.routes_file:
            routes.extend(load_routes_from_file(args.routes_file))

        # Deduplicate and filter to protected-looking routes
        candidate_routes = list({r for r in routes if is_protected_route(r)})

        bypassed: list[dict[str, Any]] = []
        for path in candidate_routes[:50]:  # cap at 50 to avoid hammering
            finding = probe_route(args.url, path, session)
            if finding:
                bypassed.append(finding)

        result["bypassed_routes"] = bypassed

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("spa_route_bypass error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
