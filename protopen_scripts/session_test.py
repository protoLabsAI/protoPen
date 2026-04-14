#!/usr/bin/env python3
"""Session security tester.

Makes a GET to the URL, records cookies, then makes a POST to discoverable
login endpoints. Checks for session fixation, missing HttpOnly/Secure/SameSite
cookie flags, and whether session IDs regenerate after login.
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

LOGIN_PATHS = [
    "/login",
    "/signin",
    "/auth/login",
    "/auth/signin",
    "/api/login",
    "/api/signin",
    "/api/auth/login",
    "/api/auth/signin",
    "/user/login",
    "/account/login",
    "/session/new",
]

SESSION_COOKIE_NAMES = re.compile(
    r'(?:session|sess|sid|auth|token|jwt|connect\.sid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|CSRF)',
    re.IGNORECASE,
)


def _analyze_cookie_flags(cookie: requests.cookies.RequestsCookieJar | Any, cookie_name: str, cookie_value: str, resp: requests.Response) -> list[dict[str, Any]]:
    """Analyze Set-Cookie header flags for a given cookie name."""
    findings: list[dict[str, Any]] = []

    # Parse Set-Cookie header(s) from response
    set_cookie_headers = resp.raw.headers.getlist('Set-Cookie') if hasattr(resp.raw.headers, 'getlist') else []
    if not set_cookie_headers:
        # Fallback: parse from response.headers
        raw_header = resp.headers.get('Set-Cookie', '')
        if raw_header:
            set_cookie_headers = [raw_header]

    for sc_header in set_cookie_headers:
        if not sc_header.startswith(cookie_name + '='):
            continue

        flags = sc_header.lower()
        if 'httponly' not in flags:
            findings.append({
                "severity": "medium",
                "vulnerability_type": "cookie_flags_missing",
                "message": f"Session cookie '{cookie_name}' missing HttpOnly flag — accessible via JavaScript",
            })

        if 'secure' not in flags:
            findings.append({
                "severity": "medium",
                "vulnerability_type": "cookie_flags_missing",
                "message": f"Session cookie '{cookie_name}' missing Secure flag — transmitted over HTTP",
            })

        if 'samesite' not in flags:
            findings.append({
                "severity": "medium",
                "vulnerability_type": "cookie_flags_missing",
                "message": f"Session cookie '{cookie_name}' missing SameSite attribute — CSRF risk",
            })
        elif 'samesite=none' in flags and 'secure' not in flags:
            findings.append({
                "severity": "high",
                "vulnerability_type": "cookie_samesite_none_no_secure",
                "message": f"Session cookie '{cookie_name}' has SameSite=None without Secure — cross-site requests allowed over HTTP",
            })

    return findings


def get_session_cookies(resp: requests.Response) -> dict[str, str]:
    """Extract session-like cookies from a response."""
    cookies: dict[str, str] = {}
    for cookie in resp.cookies:
        if SESSION_COOKIE_NAMES.search(cookie.name):
            cookies[cookie.name] = cookie.value
    # Also check Set-Cookie header for cookies not in requests cookie jar
    for sc in resp.headers.get('Set-Cookie', '').split('\n'):
        if '=' in sc:
            name = sc.split('=')[0].strip()
            if SESSION_COOKIE_NAMES.search(name) and name not in cookies:
                cookies[name] = sc.split('=', 1)[1].split(';')[0].strip()
    return cookies


def main() -> None:
    parser = argparse.ArgumentParser(description="Session security tester")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"findings": []}

    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "protopen-session-test/1.0"})

        # Step 1: GET the URL to collect any pre-login session cookies
        resp_initial = session.get(args.url, timeout=15, allow_redirects=True)
        pre_login_cookies = get_session_cookies(resp_initial)

        # Analyze flags on pre-login cookies
        for cookie_name, cookie_value in pre_login_cookies.items():
            flag_findings = _analyze_cookie_flags(None, cookie_name, cookie_value, resp_initial)
            result["findings"].extend(flag_findings)

        if not pre_login_cookies:
            result["findings"].append({
                "severity": "info",
                "vulnerability_type": "no_session_cookie",
                "message": "No session-like cookies found on initial GET — may use token-based auth",
            })

        # Step 2: Find login endpoint
        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        login_url: str | None = None

        for path in LOGIN_PATHS:
            candidate = urljoin(origin, path)
            try:
                probe = session.get(candidate, timeout=8, allow_redirects=False)
                if probe.status_code in (200, 302, 405):
                    login_url = candidate
                    break
            except requests.RequestException:
                pass

        if not login_url:
            result["findings"].append({
                "severity": "info",
                "vulnerability_type": "login_endpoint_not_found",
                "message": "Could not discover login endpoint — session fixation test skipped",
            })
        else:
            result["findings"].append({
                "severity": "info",
                "vulnerability_type": "login_endpoint_found",
                "message": f"Login endpoint found: {login_url}",
            })

            # Step 3: POST to login with dummy credentials
            post_data = {
                "username": "test@example.com",
                "password": "invalid_test_password",
                "email": "test@example.com",
            }
            try:
                resp_login = session.post(
                    login_url,
                    data=post_data,
                    timeout=15,
                    allow_redirects=False,
                )
                post_login_cookies = get_session_cookies(resp_login)

                # Check for session fixation: if pre-login session ID persists unchanged after login
                for cookie_name, pre_value in pre_login_cookies.items():
                    post_value = post_login_cookies.get(cookie_name)
                    if post_value is not None:
                        if post_value == pre_value:
                            result["findings"].append({
                                "severity": "high",
                                "vulnerability_type": "session_fixation",
                                "message": f"Session cookie '{cookie_name}' was NOT regenerated after login attempt — session fixation risk",
                            })
                        else:
                            result["findings"].append({
                                "severity": "info",
                                "vulnerability_type": "session_regenerated",
                                "message": f"Session cookie '{cookie_name}' was regenerated after login — good",
                            })

                # Analyze flags on post-login cookies
                for cookie_name, cookie_value in post_login_cookies.items():
                    flag_findings = _analyze_cookie_flags(None, cookie_name, cookie_value, resp_login)
                    result["findings"].extend(flag_findings)

            except requests.RequestException as exc:
                result["findings"].append({
                    "severity": "info",
                    "vulnerability_type": "login_post_error",
                    "message": f"POST to login endpoint failed: {exc}",
                })

        # Check CSRF protection
        resp_check = session.get(args.url, timeout=10)
        csrf_indicators = ['csrf', 'xsrf', '_token', 'authenticity_token']
        html = resp_check.text.lower()
        has_csrf = any(ind in html for ind in csrf_indicators)
        if not has_csrf:
            result["findings"].append({
                "severity": "medium",
                "vulnerability_type": "csrf_token_not_detected",
                "message": "No CSRF token indicators found in page HTML — CSRF protection may be absent",
            })

    except Exception as exc:
        result["error"] = str(exc)
        result["findings"].append({
            "severity": "error",
            "vulnerability_type": "scan_error",
            "message": f"Scan failed: {exc}",
        })
        logger.error("session_test error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
