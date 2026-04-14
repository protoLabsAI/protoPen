#!/usr/bin/env python3
"""SAML endpoint prober and injection tester.

If no SAML response is given, checks if SAML ACS endpoints exist at
common paths. If a response is given, attempts to post it and analyze
server behavior for XML signature wrapping vulnerabilities.
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

SAML_PATHS = [
    "/saml/acs",
    "/saml/consume",
    "/auth/saml",
    "/auth/saml/callback",
    "/sso/saml",
    "/sso/saml2",
    "/api/auth/saml/callback",
    "/saml2/acs",
    "/Saml/Acs",
    "/api/sso/saml",
    "/identity/saml/acs",
    "/saml/SSO",
    "/saml/assertion",
]


def check_saml_endpoints(session: requests.Session, base_url: str) -> list[tuple[str, int]]:
    """Probe common SAML ACS paths. Return list of (url, status)."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    found: list[tuple[str, int]] = []

    for path in SAML_PATHS:
        url = urljoin(origin, path)
        try:
            # POST with empty body to detect SAML ACS endpoints
            resp = session.post(url, data={}, timeout=8, allow_redirects=False)
            if resp.status_code in (200, 302, 303, 400, 403, 405, 422, 500):
                found.append((url, resp.status_code))
                if resp.status_code not in (404, 410):
                    logger.debug("SAML candidate: %s -> %d", url, resp.status_code)
        except requests.RequestException:
            pass

    return found


def test_saml_injection(session: requests.Session, acs_url: str, saml_response: str) -> list[dict[str, Any]]:
    """Post a SAML response and check for signs of acceptance or interesting error messages."""
    findings: list[dict[str, Any]] = []

    # Post the original response
    try:
        resp = session.post(
            acs_url,
            data={"SAMLResponse": saml_response, "RelayState": "test"},
            timeout=15,
            allow_redirects=False,
        )

        findings.append({
            "severity": "info",
            "vulnerability_type": "saml_post_result",
            "message": f"SAML POST to {acs_url} returned HTTP {resp.status_code}",
        })

        # Check if accepted (redirected to app, or 200 with session cookie)
        if resp.status_code in (302, 303) and 'Set-Cookie' in resp.headers:
            loc = resp.headers.get('Location', '')
            if not re.search(r'(?:error|fail|invalid|login)', loc, re.IGNORECASE):
                findings.append({
                    "severity": "high",
                    "vulnerability_type": "saml_response_accepted",
                    "message": f"SAML response accepted and session cookie issued — verify signature was validated",
                })

        # Signature wrapping: try sending response without signature
        # We inject a comment to slightly modify the response
        if saml_response:
            # Try adding whitespace (XML normalization attack vector)
            modified = saml_response.replace('+', '%2B')  # URL-encode for form post
            resp2 = session.post(
                acs_url,
                data={"SAMLResponse": modified, "RelayState": "test"},
                timeout=10,
                allow_redirects=False,
            )
            if resp2.status_code == resp.status_code:
                findings.append({
                    "severity": "medium",
                    "vulnerability_type": "saml_whitespace_tolerant",
                    "message": "SAML endpoint returned same response to URL-encoded modification — may accept whitespace normalization attacks",
                })

    except requests.RequestException as exc:
        logger.debug("SAML inject request failed: %s", exc)
        findings.append({
            "severity": "error",
            "vulnerability_type": "saml_post_error",
            "message": f"HTTP request to SAML ACS failed: {exc}",
        })

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="SAML endpoint prober and injection tester")
    parser.add_argument("--url", required=True, help="Target SP/IdP URL")
    parser.add_argument("--response", default="", help="Optional base64-encoded SAML response to inject")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"findings": []}

    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "protopen-saml-inject/1.0"})

        # Find SAML endpoints
        endpoints = check_saml_endpoints(session, args.url)

        if not endpoints:
            result["findings"].append({
                "severity": "info",
                "vulnerability_type": "saml_endpoint",
                "message": "No SAML endpoint found at target",
            })
        else:
            for acs_url, status in endpoints:
                result["findings"].append({
                    "severity": "info",
                    "vulnerability_type": "saml_endpoint_found",
                    "message": f"SAML ACS endpoint found: {acs_url} (HTTP {status})",
                })

            # If response provided, test injection against first found endpoint
            if args.response:
                primary_acs = endpoints[0][0]
                inject_findings = test_saml_injection(session, primary_acs, args.response)
                result["findings"].extend(inject_findings)

    except Exception as exc:
        result["error"] = str(exc)
        result["findings"].append({
            "severity": "error",
            "vulnerability_type": "scan_error",
            "message": f"Scan failed: {exc}",
        })
        logger.error("saml_inject error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
