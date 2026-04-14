#!/usr/bin/env python3
"""JavaScript source map exposure checker.

For each JS file linked in the HTML, checks if the corresponding .map
file is publicly accessible. Also looks for //# sourceMappingURL= comments.
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

SOURCE_MAP_COMMENT = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")
X_SOURCE_MAP_HEADER = re.compile(r"X-SourceMap|SourceMap", re.IGNORECASE)


def _extract_js_urls(html: str, base_url: str) -> list[str]:
    parsed_base = urlparse(base_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    urls: list[str] = []
    src_re = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
    for src in src_re.findall(html):
        if src.startswith("http"):
            urls.append(src)
        elif src.startswith("//"):
            urls.append(f"{parsed_base.scheme}:{src}")
        elif src.startswith("/"):
            urls.append(f"{base_origin}{src}")
        else:
            urls.append(urljoin(base_url, src))
    return urls


def _check_map_url(session: requests.Session, map_url: str, js_filename: str) -> dict[str, Any] | None:
    """Return finding dict if source map is accessible."""
    try:
        resp = session.get(map_url, timeout=10)
        if resp.status_code == 200:
            content_type = resp.headers.get("Content-Type", "")
            # Source maps are typically JSON
            is_json = "json" in content_type or "javascript" in content_type
            try:
                data = resp.json()
                has_sources = "sources" in data or "sourceRoot" in data
            except Exception:
                has_sources = False

            severity = "medium"
            detail = "Source map publicly accessible"
            if has_sources:
                severity = "high"
                detail = "Source map accessible and contains source file paths/content"

            return {
                "file": js_filename,
                "severity": severity,
                "detail": detail,
                "map_url": map_url,
            }
    except requests.RequestException as exc:
        logger.debug("Map check failed for %s: %s", map_url, exc)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="JS source map exposure checker")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"url": args.url, "exposed_maps": []}

    try:
        session = make_session()

        resp = session.get(args.url, timeout=15)
        html = resp.text

        js_urls = _extract_js_urls(html, args.url)
        parsed_base = urlparse(args.url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        checked_maps: set[str] = set()

        for js_url in js_urls[:20]:
            js_filename = urlparse(js_url).path.split("/")[-1] or "unknown.js"

            # Strategy 1: Try <js_url>.map
            map_url = js_url + ".map"
            if map_url not in checked_maps:
                checked_maps.add(map_url)
                finding = _check_map_url(session, map_url, js_filename)
                if finding:
                    result["exposed_maps"].append(finding)
                    continue  # found via direct .map, skip downloading JS

            # Strategy 2: Download JS and check for sourceMappingURL comment
            try:
                js_resp = session.get(js_url, timeout=10)
                js_content = js_resp.text

                # Check X-SourceMap response header
                for header_name in ("X-SourceMap", "SourceMap"):
                    header_val = js_resp.headers.get(header_name)
                    if header_val:
                        if header_val.startswith("http"):
                            sm_url = header_val
                        elif header_val.startswith("/"):
                            sm_url = f"{base_origin}{header_val}"
                        else:
                            sm_url = urljoin(js_url, header_val)
                        if sm_url not in checked_maps:
                            checked_maps.add(sm_url)
                            finding = _check_map_url(session, sm_url, js_filename)
                            if finding:
                                result["exposed_maps"].append(finding)

                # Check sourceMappingURL comment
                m = SOURCE_MAP_COMMENT.search(js_content)
                if m:
                    comment_url = m.group(1).strip()
                    # Skip data URIs
                    if comment_url.startswith("data:"):
                        continue
                    if comment_url.startswith("http"):
                        sm_url = comment_url
                    elif comment_url.startswith("/"):
                        sm_url = f"{base_origin}{comment_url}"
                    else:
                        sm_url = urljoin(js_url, comment_url)

                    if sm_url not in checked_maps:
                        checked_maps.add(sm_url)
                        finding = _check_map_url(session, sm_url, js_filename)
                        if finding:
                            result["exposed_maps"].append(finding)

            except requests.RequestException as exc:
                logger.debug("Failed to fetch JS %s: %s", js_url, exc)

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("sourcemap_check error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
