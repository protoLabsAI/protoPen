#!/usr/bin/env python3
"""SPA SSR dehydrated state inspector.

Checks for sensitive data (auth tokens, user IDs, session data, PII)
exposed in server-side rendered HTML state blobs.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import logging
from typing import Any

import requests
from protopen_scripts._common import make_session

logger = logging.getLogger(__name__)

# Patterns that indicate sensitive data
SENSITIVE_KEY_PATTERNS = re.compile(
    r'(?:token|accessToken|idToken|refreshToken|jwt|bearer|'
    r'sessionId|session_id|csrfToken|csrf|'
    r'userId|user_id|uid|sub|email|phone|ssn|'
    r'password|secret|apiKey|api_key|privateKey)',
    re.IGNORECASE,
)

# SSR state container patterns
SSR_PATTERNS = [
    (re.compile(r'<script[^>]*>\s*window\.__NEXT_DATA__\s*=\s*({.*?})\s*;?\s*</script>', re.DOTALL), "__NEXT_DATA__"),
    (re.compile(r'<script[^>]*>\s*window\.__REDUX_STATE__\s*=\s*({.*?})\s*;?\s*</script>', re.DOTALL), "__REDUX_STATE__"),
    (re.compile(r'<script[^>]*>\s*window\.__INITIAL_STATE__\s*=\s*({.*?})\s*;?\s*</script>', re.DOTALL), "__INITIAL_STATE__"),
    (re.compile(r'<script[^>]*>\s*window\.__APP_STATE__\s*=\s*({.*?})\s*;?\s*</script>', re.DOTALL), "__APP_STATE__"),
    (re.compile(r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', re.DOTALL), "__NEXT_DATA__"),
    (re.compile(r'"dehydratedState"\s*:\s*({.*?})\s*[,}]', re.DOTALL), "dehydratedState"),
    (re.compile(r'window\.INITIAL_DATA\s*=\s*({.*?});', re.DOTALL), "INITIAL_DATA"),
    (re.compile(r'<script[^>]*type=["\']application/json["\'][^>]*>\s*({.*?})\s*</script>', re.DOTALL), "json_script_tag"),
]


def _safe_json(text: str) -> Any:
    """Try to parse JSON, return None on failure."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _find_sensitive_paths(obj: Any, path: str = "") -> list[tuple[str, Any]]:
    """Recursively walk obj and return (path, value) for sensitive-looking keys."""
    found: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_path = f"{path}.{k}" if path else k
            if SENSITIVE_KEY_PATTERNS.search(str(k)):
                if v and str(v) not in ("null", "undefined", ""):
                    found.append((full_path, v))
            found.extend(_find_sensitive_paths(v, full_path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:10]):  # limit list depth
            found.extend(_find_sensitive_paths(item, f"{path}[{i}]"))
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description="SPA SSR state inspector")
    parser.add_argument("--url", required=True, help="Target SPA URL")
    parser.add_argument("--store-type", default="redux", help="State store type hint (redux, vuex, pinia, etc.)")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"url": args.url, "exposed_state": []}

    try:
        session = make_session()
        resp = session.get(args.url, timeout=15)
        html = resp.text

        for pattern, store_name in SSR_PATTERNS:
            for match in pattern.finditer(html):
                raw = match.group(1)
                parsed = _safe_json(raw)
                if parsed is None:
                    # partial match — just flag existence
                    result["exposed_state"].append({
                        "store": store_name,
                        "severity": "low",
                        "detail": f"State blob found in SSR HTML ({store_name}) but could not parse as JSON",
                        "key_path": store_name,
                    })
                    continue

                sensitive = _find_sensitive_paths(parsed)
                if sensitive:
                    for key_path, value in sensitive:
                        # mask the value if it looks like a real secret
                        display_val = str(value)
                        if len(display_val) > 20:
                            display_val = display_val[:8] + "..." + display_val[-4:]
                        result["exposed_state"].append({
                            "store": store_name,
                            "severity": "high" if any(
                                t in key_path.lower()
                                for t in ("token", "jwt", "session", "password", "secret", "apikey", "api_key")
                            ) else "medium",
                            "detail": f"Sensitive field '{key_path}' exposed in SSR dehydrated state",
                            "key_path": f"{store_name}.{key_path}",
                        })
                else:
                    # State found but no obvious sensitive keys — still flag as info
                    result["exposed_state"].append({
                        "store": store_name,
                        "severity": "info",
                        "detail": f"State blob ({store_name}) present in SSR HTML — review for sensitive data",
                        "key_path": store_name,
                    })

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("spa_state error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
