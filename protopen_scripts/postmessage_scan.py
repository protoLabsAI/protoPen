#!/usr/bin/env python3
"""postMessage security scanner.

Downloads linked JS files and checks for postMessage handlers
that lack origin validation.
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

logger = logging.getLogger(__name__)

# Patterns to detect postMessage event listeners
LISTENER_PATTERNS = [
    re.compile(r'''addEventListener\s*\(\s*['"`]message['"`]'''),
    re.compile(r'''window\.addEventListener\s*\(\s*['"`]message['"`]'''),
    re.compile(r'''self\.addEventListener\s*\(\s*['"`]message['"`]'''),
    re.compile(r'''onmessage\s*='''),
]

# Patterns that indicate postMessage usage (as sender)
POSTMESSAGE_SEND = re.compile(r'''\.postMessage\s*\(''')

# Origin validation patterns
ORIGIN_CHECK_PATTERNS = [
    re.compile(r'event\.origin'),
    re.compile(r'e\.origin'),
    re.compile(r'msg\.origin'),
    re.compile(r'message\.origin'),
    re.compile(r'trustedOrigins'),
    re.compile(r'allowedOrigins'),
    re.compile(r'validOrigins'),
    re.compile(r'checkOrigin'),
    re.compile(r'verifyOrigin'),
    re.compile(r'origin\s*==='),
    re.compile(r'origin\s*!=='),
    re.compile(r'origin\.includes'),
    re.compile(r'origin\.startsWith'),
    re.compile(r'origin\.endsWith'),
]

# event.data usage
EVENT_DATA_PATTERN = re.compile(r'event\.data|e\.data|msg\.data|message\.data')


def _extract_js_urls(html: str, base_url: str) -> list[str]:
    parsed_base = urlparse(base_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    urls: list[str] = []

    src_re = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
    for src in src_re.findall(html):
        if src.startswith('http'):
            urls.append(src)
        elif src.startswith('//'):
            urls.append(f"{parsed_base.scheme}:{src}")
        elif src.startswith('/'):
            urls.append(f"{base_origin}{src}")
        else:
            urls.append(urljoin(base_url, src))
    return urls


def _find_listener_region(js: str, pattern: re.Pattern) -> list[tuple[int, str]]:
    """Return (line_no, surrounding_context) for each match."""
    lines = js.splitlines()
    results: list[tuple[int, str]] = []
    for i, line in enumerate(lines, 1):
        if pattern.search(line):
            results.append((i, line.strip()))
    return results


def _check_origin_validation_nearby(js: str, line_no: int, window: int = 30) -> bool:
    """Check if any origin validation pattern appears within `window` lines of line_no."""
    lines = js.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    chunk = '\n'.join(lines[start:end])
    return any(p.search(chunk) for p in ORIGIN_CHECK_PATTERNS)


def analyze_js(js_content: str, filename: str) -> list[dict[str, Any]]:
    """Analyze JS content for unsafe postMessage handlers."""
    findings: list[dict[str, Any]] = []

    for pattern in LISTENER_PATTERNS:
        occurrences = _find_listener_region(js_content, pattern)
        for line_no, line_text in occurrences:
            has_origin_check = _check_origin_validation_nearby(js_content, line_no)
            findings.append({
                "origin_check": has_origin_check,
                "severity": "info" if has_origin_check else "high",
                "detail": (
                    f"postMessage handler at line {line_no} "
                    + ("with origin validation" if has_origin_check else "with NO origin check")
                ),
                "location": f"{filename}:{line_no}",
            })

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="postMessage security scanner")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"url": args.url, "handlers": []}

    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "protopen-postmessage-scan/1.0"})

        resp = session.get(args.url, timeout=15)
        html = resp.text

        # Also check inline scripts
        inline_re = re.compile(r'<script(?![^>]+src=)[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
        for i, match in enumerate(inline_re.finditer(html)):
            inline_js = match.group(1)
            findings = analyze_js(inline_js, f"inline_script_{i + 1}")
            result["handlers"].extend(findings)

        # Check linked JS files
        js_urls = _extract_js_urls(html, args.url)
        for js_url in js_urls[:15]:
            try:
                js_resp = session.get(js_url, timeout=10)
                filename = urlparse(js_url).path.split('/')[-1] or js_url
                findings = analyze_js(js_resp.text, filename)
                result["handlers"].extend(findings)
            except requests.RequestException as exc:
                logger.debug("Failed to fetch JS %s: %s", js_url, exc)

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("postmessage_scan error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
