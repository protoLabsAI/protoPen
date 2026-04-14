#!/usr/bin/env python3
"""OAuth redirect_uri validation tester.

Discovers OAuth endpoints and tests whether redirect_uri is validated
against registered URIs or can be tampered to redirect tokens to attacker domains.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import logging
from typing import Any
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests
from protopen_scripts._common import make_session

logger = logging.getLogger(__name__)

WELL_KNOWN_PATH = "/.well-known/openid-configuration"
COMMON_OAUTH_PATHS = [
    "/oauth/authorize",
    "/auth/oauth2/authorize",
    "/oauth2/authorize",
    "/connect/authorize",
    "/v1/authorize",
    "/api/oauth/authorize",
    "/login/oauth/authorize",
    "/oauth/auth",
]

EVIL_REDIRECT_URIS = [
    "https://evil.com/steal",
    "//evil.com/steal",
    "https://mush.bike.evil.com/steal",
    "https://trusted.com.evil.com/steal",
    "https://evil.com%2F@trusted.com/steal",
    "https://trusted.com/\x00@evil.com/steal",
]

OPEN_REDIRECT_PARAMS = [
    "redirectTo",
    "redirect_to",
    "redirect",
    "next",
    "returnTo",
    "return_to",
    "return",
    "callback",
    "continue",
    "goto",
    "destination",
]

EVIL_REDIRECT_VALUE = "https://evil.com/steal"


def discover_oauth_endpoints(session: requests.Session, base_url: str) -> dict[str, Any]:
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    info: dict[str, Any] = {"authorization_endpoint": None, "well_known": None}

    # Try OIDC well-known
    wk_url = urljoin(origin, WELL_KNOWN_PATH)
    try:
        resp = session.get(wk_url, timeout=10)
        if resp.status_code == 200:
            try:
                data = resp.json()
                info["well_known"] = data
                info["authorization_endpoint"] = data.get("authorization_endpoint")
            except Exception:
                pass
    except requests.RequestException:
        pass

    # Try common paths if no well-known found
    if not info["authorization_endpoint"]:
        for path in COMMON_OAUTH_PATHS:
            url = urljoin(origin, path)
            try:
                resp = session.get(url, timeout=8, allow_redirects=False)
                if resp.status_code in (200, 302, 400, 401, 405):
                    # Endpoint exists (even error responses indicate presence)
                    info["authorization_endpoint"] = url
                    break
            except requests.RequestException:
                pass

    return info


def test_redirect_uri(session: requests.Session, auth_endpoint: str, client_id: str) -> list[dict[str, Any]]:
    """Test evil redirect_uri values against the auth endpoint."""
    findings: list[dict[str, Any]] = []
    parsed = urlparse(auth_endpoint)

    for evil_uri in EVIL_REDIRECT_URIS:
        params = {
            "response_type": "code",
            "client_id": client_id or "test_client",
            "redirect_uri": evil_uri,
            "scope": "openid",
            "state": "test_state_12345",
        }
        url = f"{auth_endpoint}?{urlencode(params)}"
        try:
            resp = session.get(url, timeout=10, allow_redirects=False)
            # If the server redirects to the evil URI or returns a 200 with code,
            # that indicates a vulnerability
            location = resp.headers.get("Location", "")
            if resp.status_code in (200, 302, 303) and ("evil.com" in location or "evil.com" in resp.text):
                findings.append(
                    {
                        "severity": "critical",
                        "vulnerability_type": "redirect_uri_bypass",
                        "message": f"redirect_uri validation bypass: server accepted '{evil_uri}' — redirected to attacker domain",
                    }
                )
                break
            elif resp.status_code == 200 and "code=" in resp.text:
                findings.append(
                    {
                        "severity": "high",
                        "vulnerability_type": "redirect_uri_reflection",
                        "message": f"Authorization code potentially leakable via redirect_uri='{evil_uri}' (200 response with code)",
                    }
                )
                break
            elif resp.status_code in (400, 422) and evil_uri in (resp.text or ""):
                findings.append(
                    {
                        "severity": "medium",
                        "vulnerability_type": "redirect_uri_reflected_in_error",
                        "message": "redirect_uri reflected in error response (check for open redirect chain)",
                    }
                )
                break
        except requests.RequestException as exc:
            logger.debug("redirect_uri test failed for %s: %s", evil_uri, exc)

    return findings


def test_open_redirect(session: requests.Session, base_url: str) -> list[dict[str, Any]]:
    """Test login URL for open redirect via common query parameters."""
    findings: list[dict[str, Any]] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    login_paths = ["/login", "/signin", "/auth/login", "/auth/signin", "/account/login", "/user/login"]
    for path in login_paths:
        login_url = urljoin(origin, path)
        for param in OPEN_REDIRECT_PARAMS:
            test_url = f"{login_url}?{param}={EVIL_REDIRECT_VALUE}"
            try:
                resp = session.get(test_url, timeout=8, allow_redirects=False)
                location = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and "evil.com" in location:
                    findings.append(
                        {
                            "severity": "high",
                            "vulnerability_type": "open_redirect",
                            "message": f"Open redirect via '{param}' parameter at {login_url} — accepts external domain",
                        }
                    )
            except requests.RequestException:
                pass

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="OAuth redirect_uri validation tester")
    parser.add_argument("--url", required=True, help="Target authorization server URL")
    parser.add_argument("--client-id", default="", help="Optional OAuth client ID to use in tests")
    parser.add_argument("--redirect-uri", default="", help="Legitimate redirect URI (baseline)")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"findings": []}

    try:
        session = make_session()
        session.max_redirects = 3

        # Discover OAuth endpoints
        endpoint_info = discover_oauth_endpoints(session, args.url)
        auth_endpoint = endpoint_info.get("authorization_endpoint")

        if not auth_endpoint:
            result["findings"].append(
                {
                    "severity": "info",
                    "vulnerability_type": "no_oauth_endpoint",
                    "message": "No OAuth/OIDC authorization endpoint discovered at target",
                }
            )
        else:
            result["findings"].append(
                {
                    "severity": "info",
                    "vulnerability_type": "oauth_endpoint_found",
                    "message": f"OAuth authorization endpoint found: {auth_endpoint}",
                }
            )

            # Test redirect_uri manipulation
            redirect_findings = test_redirect_uri(session, auth_endpoint, args.client_id)
            result["findings"].extend(redirect_findings)

            if not redirect_findings:
                result["findings"].append(
                    {
                        "severity": "info",
                        "vulnerability_type": "redirect_uri_validated",
                        "message": "redirect_uri appears to be validated (evil URIs rejected)",
                    }
                )

        # Test open redirect in login flow
        open_redirect_findings = test_open_redirect(session, args.url)
        result["findings"].extend(open_redirect_findings)

        if not open_redirect_findings:
            result["findings"].append(
                {
                    "severity": "info",
                    "vulnerability_type": "no_open_redirect",
                    "message": "No open redirect found in login flow parameters",
                }
            )

    except Exception as exc:
        result["error"] = str(exc)
        result["findings"].append(
            {
                "severity": "error",
                "vulnerability_type": "scan_error",
                "message": f"Scan failed: {exc}",
            }
        )
        logger.error("oauth_redirect error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
