#!/usr/bin/env python3
"""Token leakage auditor.

Scans HTML and JS for evidence of authentication tokens stored in
localStorage/sessionStorage and tokens exposed in URL hash/query strings.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import logging
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from protopen_scripts._common import make_session

logger = logging.getLogger(__name__)

# localStorage/sessionStorage patterns
LOCALSTORAGE_PATTERNS = [
    (re.compile(r'''localStorage\.setItem\s*\(\s*['"`]([^'"`]*(?:token|auth|jwt|access|refresh|bearer|session)[^'"`]*?)['"`]''', re.IGNORECASE), "localStorage", "write"),
    (re.compile(r'''localStorage\.getItem\s*\(\s*['"`]([^'"`]*(?:token|auth|jwt|access|refresh|bearer|session)[^'"`]*?)['"`]''', re.IGNORECASE), "localStorage", "read"),
    (re.compile(r'''sessionStorage\.setItem\s*\(\s*['"`]([^'"`]*(?:token|auth|jwt|session|bearer)[^'"`]*?)['"`]''', re.IGNORECASE), "sessionStorage", "write"),
    (re.compile(r'''sessionStorage\.getItem\s*\(\s*['"`]([^'"`]*(?:token|auth|jwt|session|bearer)[^'"`]*?)['"`]''', re.IGNORECASE), "sessionStorage", "read"),
    # Also catch generic localStorage.token = ... patterns
    (re.compile(r'''localStorage\[['"`]([^'"`]*(?:token|auth|jwt|access|refresh)[^'"`]*?)['"`]\]\s*=''', re.IGNORECASE), "localStorage", "write"),
]

# URL hash fragment token patterns
HASH_TOKEN_PATTERNS = [
    (re.compile(r'#access_token=', re.IGNORECASE), "URL hash", "access_token"),
    (re.compile(r'#id_token=', re.IGNORECASE), "URL hash", "id_token"),
    (re.compile(r'#token=', re.IGNORECASE), "URL hash", "token"),
    (re.compile(r'#auth=', re.IGNORECASE), "URL hash", "auth"),
    (re.compile(r'#refresh_token=', re.IGNORECASE), "URL hash", "refresh_token"),
]

# URL query param token patterns in HTML links
QUERY_TOKEN_PATTERNS = [
    (re.compile(r'[?&]token=', re.IGNORECASE), "URL query", "token"),
    (re.compile(r'[?&]auth=', re.IGNORECASE), "URL query", "auth"),
    (re.compile(r'[?&]access_token=', re.IGNORECASE), "URL query", "access_token"),
    (re.compile(r'[?&]api_key=', re.IGNORECASE), "URL query", "api_key"),
    (re.compile(r'[?&]apikey=', re.IGNORECASE), "URL query", "apikey"),
    (re.compile(r'[?&]jwt=', re.IGNORECASE), "URL query", "jwt"),
]

# Patterns indicating token in JS code sent to hash
HASH_WRITE_PATTERNS = [
    re.compile(r'location\.hash\s*=.*(?:token|auth|jwt)', re.IGNORECASE),
    re.compile(r'window\.location\.hash\s*=.*(?:token|auth|jwt)', re.IGNORECASE),
    re.compile(r'history\.(?:push|replace)State.*#.*(?:token|auth|jwt)', re.IGNORECASE),
]


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


def check_localstorage(content: str) -> list[dict[str, Any]]:
    leaks: list[dict[str, Any]] = []
    for pattern, storage, operation in LOCALSTORAGE_PATTERNS:
        for m in pattern.finditer(content):
            key_name = m.group(1) if m.lastindex and m.lastindex >= 1 else "unknown"
            # Classify token type
            token_type = "access_token"
            kl = key_name.lower()
            if "refresh" in kl:
                token_type = "refresh_token"
            elif "id_token" in kl or "idtoken" in kl:
                token_type = "id_token"
            elif "session" in kl:
                token_type = "session_id"
            elif "jwt" in kl:
                token_type = "jwt"

            leaks.append({
                "storage": storage,
                "severity": "high",
                "detail": f"Auth token stored in {storage} (key: '{key_name}', operation: {operation})",
                "token_type": token_type,
            })
    return leaks


def check_url_fragments(html: str, check_fragments: bool, check_query: bool) -> list[dict[str, Any]]:
    leaks: list[dict[str, Any]] = []

    if check_fragments:
        for pattern, source, token_type in HASH_TOKEN_PATTERNS:
            if pattern.search(html):
                leaks.append({
                    "storage": source,
                    "severity": "high",
                    "detail": f"'{token_type}' parameter found in URL hash fragment — visible in browser history",
                    "token_type": token_type,
                })
        # Check for JS that writes tokens to hash
        for pattern in HASH_WRITE_PATTERNS:
            if pattern.search(html):
                leaks.append({
                    "storage": "URL hash (JS write)",
                    "severity": "high",
                    "detail": "JavaScript writes auth token to URL hash fragment",
                    "token_type": "unknown",
                })

    if check_query:
        for pattern, source, token_type in QUERY_TOKEN_PATTERNS:
            if pattern.search(html):
                leaks.append({
                    "storage": source,
                    "severity": "medium",
                    "detail": f"'{token_type}' found in URL query parameter — token logged by servers/proxies",
                    "token_type": token_type,
                })

    return leaks


def main() -> None:
    parser = argparse.ArgumentParser(description="Token leakage auditor")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--check-localstorage", action="store_true", help="Check for localStorage token storage")
    parser.add_argument("--check-url-fragments", action="store_true", help="Check for tokens in URL fragments")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"url": args.url, "leaks": []}

    try:
        session = make_session()

        resp = session.get(args.url, timeout=15)
        html = resp.text

        # Combine inline JS and linked JS files
        combined_js = html

        js_urls = _extract_js_urls(html, args.url)
        for js_url in js_urls[:15]:
            try:
                js_resp = session.get(js_url, timeout=10)
                combined_js += js_resp.text
            except requests.RequestException:
                pass

        # Always check localStorage patterns (flag is advisory, we run it)
        ls_leaks = check_localstorage(combined_js)
        result["leaks"].extend(ls_leaks)

        # Check URL fragment/query params
        frag_leaks = check_url_fragments(combined_js, args.check_url_fragments, args.check_url_fragments)
        result["leaks"].extend(frag_leaks)

        # Deduplicate by detail string
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for leak in result["leaks"]:
            key = f"{leak['storage']}:{leak['token_type']}"
            if key not in seen:
                seen.add(key)
                deduped.append(leak)
        result["leaks"] = deduped

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("token_leakage error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
