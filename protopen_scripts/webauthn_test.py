#!/usr/bin/env python3
"""WebAuthn/passkey endpoint tester.

Checks for WebAuthn registration/authentication endpoints and
evaluates rpId validation strictness.
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

WEBAUTHN_PATHS = [
    "/api/auth/passkey",
    "/api/auth/passkey/register",
    "/api/auth/passkey/authenticate",
    "/api/auth/webauthn",
    "/auth/webauthn",
    "/auth/webauthn/register",
    "/auth/webauthn/authenticate",
    "/.well-known/webauthn",
    "/api/passkey",
    "/passkey",
    "/webauthn",
    "/api/webauthn/register",
    "/api/webauthn/authenticate",
    "/v1/auth/webauthn",
    "/api/fido2/register",
    "/api/fido2/authenticate",
]


def _get_expected_rp_id(base_url: str) -> str:
    """Extract the expected rpId from the URL (effective domain)."""
    parsed = urlparse(base_url)
    return parsed.netloc.split(':')[0]


def check_well_known_webauthn(session: requests.Session, base_url: str) -> list[dict[str, Any]]:
    """Check /.well-known/webauthn for allowed origin configuration."""
    findings: list[dict[str, Any]] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    wk_url = urljoin(origin, "/.well-known/webauthn")

    try:
        resp = session.get(wk_url, timeout=10)
        if resp.status_code == 200:
            try:
                config = resp.json()
                origins = config.get("origins", [])
                findings.append({
                    "severity": "info",
                    "vulnerability_type": "webauthn_well_known",
                    "message": f"/.well-known/webauthn found — allowed origins: {origins}",
                })
                # Check for overly broad origins
                for origin_entry in origins:
                    if origin_entry in ('*', 'null') or re.match(r'^https?://', origin_entry) is None:
                        findings.append({
                            "severity": "high",
                            "vulnerability_type": "webauthn_wildcard_origin",
                            "message": f"WebAuthn allowed origin '{origin_entry}' is overly permissive",
                        })
            except Exception:
                findings.append({
                    "severity": "info",
                    "vulnerability_type": "webauthn_well_known_invalid",
                    "message": "/.well-known/webauthn exists but returned invalid JSON",
                })
    except requests.RequestException:
        pass

    return findings


def probe_webauthn_endpoints(session: requests.Session, base_url: str) -> list[dict[str, Any]]:
    """Probe common WebAuthn paths."""
    findings: list[dict[str, Any]] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    found_any = False

    for path in WEBAUTHN_PATHS:
        url = urljoin(origin, path)
        try:
            # Try GET first
            resp = session.get(url, timeout=8, allow_redirects=False)
            if resp.status_code not in (404, 410, 501):
                found_any = True
                findings.append({
                    "severity": "info",
                    "vulnerability_type": "webauthn_endpoint_found",
                    "message": f"WebAuthn endpoint found: {url} (HTTP {resp.status_code})",
                })
                # Check for challenge exposure
                try:
                    data = resp.json()
                    if 'challenge' in data:
                        findings.append({
                            "severity": "medium",
                            "vulnerability_type": "webauthn_challenge_unauthenticated",
                            "message": f"WebAuthn challenge returned without authentication: {url}",
                        })
                    if 'rpId' in data:
                        rp_id = data['rpId']
                        expected = _get_expected_rp_id(base_url)
                        if rp_id != expected and not expected.endswith(f".{rp_id}"):
                            findings.append({
                                "severity": "high",
                                "vulnerability_type": "webauthn_rpid_mismatch",
                                "message": f"rpId '{rp_id}' does not match expected domain '{expected}'",
                            })
                except Exception:
                    pass
        except requests.RequestException:
            pass

    if not found_any:
        findings.append({
            "severity": "info",
            "vulnerability_type": "webauthn_not_detected",
            "message": "No WebAuthn endpoints found at target",
        })

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="WebAuthn/passkey endpoint tester")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--rp-id", default="", help="Optional expected relying party ID")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"findings": []}

    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "protopen-webauthn-test/1.0"})

        # Check /.well-known/webauthn
        wk_findings = check_well_known_webauthn(session, args.url)
        result["findings"].extend(wk_findings)

        # Probe WebAuthn endpoints
        endpoint_findings = probe_webauthn_endpoints(session, args.url)
        result["findings"].extend(endpoint_findings)

    except Exception as exc:
        result["error"] = str(exc)
        result["findings"].append({
            "severity": "error",
            "vulnerability_type": "scan_error",
            "message": f"Scan failed: {exc}",
        })
        logger.error("webauthn_test error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
