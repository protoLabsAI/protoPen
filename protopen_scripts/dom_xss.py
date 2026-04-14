#!/usr/bin/env python3
"""DOM XSS sink detector.

Downloads linked JS files and searches for dangerous DOM sink patterns
that may allow cross-site scripting via unfiltered user input.
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

# Dangerous sinks and their context patterns
SINK_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("innerHTML", re.compile(r'''(\w+)\.innerHTML\s*[+=]{1,2}\s*([^;{}\n]+)'''), "innerHTML assigned from expression"),
    ("innerHTML", re.compile(r'''\.innerHTML\s*=\s*(?!['"`])([^;{}\n'"]+)'''), "innerHTML assigned from variable"),
    ("outerHTML", re.compile(r'''(\w+)\.outerHTML\s*=\s*(?!['"`])([^;{}\n'"]+)'''), "outerHTML assigned from variable"),
    ("document.write", re.compile(r'''document\.write\s*\(([^)]+)\)'''), "document.write with dynamic content"),
    ("document.writeln", re.compile(r'''document\.writeln\s*\(([^)]+)\)'''), "document.writeln with dynamic content"),
    ("eval", re.compile(r'''\beval\s*\((?!['"`])([^)]+)\)'''), "eval with non-literal argument"),
    ("setTimeout", re.compile(r'''setTimeout\s*\((?!function|=>|\()([^,)]+)[,)]'''), "setTimeout with string argument (code execution)"),
    ("setInterval", re.compile(r'''setInterval\s*\((?!function|=>|\()([^,)]+)[,)]'''), "setInterval with string argument (code execution)"),
    ("dangerouslySetInnerHTML", re.compile(r'''dangerouslySetInnerHTML\s*=\s*\{'''), "React dangerouslySetInnerHTML usage"),
    ("insertAdjacentHTML", re.compile(r'''\.insertAdjacentHTML\s*\(\s*['"][^'"]+['"]\s*,\s*(?!['"`])([^)]+)\)'''), "insertAdjacentHTML with variable content"),
    ("location.href", re.compile(r'''location\.href\s*=\s*(?!['"`])([^;{}\n'"]+)'''), "location.href assigned from variable (open redirect / XSS)"),
    ("location.replace", re.compile(r'''location\.replace\s*\((?!['"`])([^)]+)\)'''), "location.replace with variable argument"),
    ("src assignment", re.compile(r'''\.src\s*=\s*(?!['"`])([^;{}\n'"]+)'''), "Script/image src assigned from variable"),
    ("Function constructor", re.compile(r'''\bnew\s+Function\s*\('''), "Function constructor (dynamic code execution)"),
    ("__html", re.compile(r'''__html\s*:\s*(?!['"`])([^,}]+)'''), "React __html prop with variable content"),
]

# Likely user-input sources that increase confidence
SOURCE_PATTERNS = re.compile(
    r'(?:params|query|search|hash|location|input|value|data|req\.|request\.|'
    r'document\.URL|document\.referrer|window\.name|URLSearchParams)',
    re.IGNORECASE,
)


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


def _filter_false_positive(match_text: str) -> bool:
    """Return True if this looks like a false positive (static string assignment etc.)."""
    stripped = match_text.strip()
    # Purely static string assignments
    if re.match(r'''^['"`][^'"`]*['"`]$''', stripped):
        return True
    # Template literals with no variables
    if re.match(r'''^`[^$]*`$''', stripped):
        return True
    return False


def analyze_js_for_sinks(js_content: str, filename: str) -> list[dict[str, Any]]:
    sinks: list[dict[str, Any]] = []
    lines = js_content.splitlines()

    for sink_type, pattern, description in SINK_PATTERNS:
        for match in pattern.finditer(js_content):
            # Find line number
            line_no = js_content[:match.start()].count('\n') + 1
            matched_text = match.group(0)

            # Get context for source detection
            start = max(0, match.start() - 200)
            end = min(len(js_content), match.end() + 200)
            context = js_content[start:end]

            # Filter obvious false positives
            if match.lastindex and match.lastindex >= 1:
                rhs = match.group(match.lastindex).strip()
                if _filter_false_positive(rhs):
                    continue

            # Check if a tainted source appears nearby
            has_source = bool(SOURCE_PATTERNS.search(context))
            source_hint = "userInput" if has_source else "unknown"

            sinks.append({
                "sink_type": sink_type,
                "severity": "high" if has_source else "medium",
                "detail": description,
                "source": source_hint,
                "location": f"{filename}:{line_no}",
            })

    return sinks


def main() -> None:
    parser = argparse.ArgumentParser(description="DOM XSS sink detector")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"url": args.url, "sinks": []}

    try:
        session = make_session()

        resp = session.get(args.url, timeout=15)
        html = resp.text

        # Analyze inline scripts
        inline_re = re.compile(r'<script(?![^>]+src=)[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
        for i, match in enumerate(inline_re.finditer(html)):
            sinks = analyze_js_for_sinks(match.group(1), f"inline_script_{i + 1}")
            result["sinks"].extend(sinks)

        # Analyze linked JS files
        js_urls = _extract_js_urls(html, args.url)
        for js_url in js_urls[:20]:
            try:
                js_resp = session.get(js_url, timeout=10)
                filename = urlparse(js_url).path.split('/')[-1] or js_url
                sinks = analyze_js_for_sinks(js_resp.text, filename)
                result["sinks"].extend(sinks)
            except requests.RequestException as exc:
                logger.debug("Failed to fetch JS %s: %s", js_url, exc)

        # Deduplicate: same sink + file + line
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for sink in result["sinks"]:
            key = f"{sink['sink_type']}:{sink['location']}"
            if key not in seen:
                seen.add(key)
                deduped.append(sink)
        result["sinks"] = deduped

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("dom_xss error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
