#!/usr/bin/env python3
"""OAuth device flow security tester.

Checks for device authorization grant endpoints and tests for
predictable user codes, weak polling intervals, and long expiry times.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import logging
import string
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger(__name__)

DEVICE_ENDPOINTS = [
    "/oauth/device/code",
    "/oauth/device_authorization",
    "/auth/device",
    "/device/code",
    "/connect/deviceauthorization",
    "/oauth2/device/code",
    "/v1/device/code",
    "/api/oauth/device/code",
]


def _entropy_estimate(code: str) -> float:
    """Estimate character diversity (0-1) of user code."""
    chars = set(code.replace("-", "").replace(" ", "").upper())
    alphabet = set(string.ascii_uppercase + string.digits)
    return len(chars) / len(alphabet) if alphabet else 0


def _check_device_endpoint(session: requests.Session, url: str, client_id: str) -> dict[str, Any] | None:
    """Probe a device code endpoint. Return endpoint info or None."""
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"client_id": client_id or "test_client", "scope": "openid"}
    try:
        resp = session.post(url, data=data, headers=headers, timeout=10)
        if resp.status_code in (200, 400, 401, 403):
            # 400 may mean client not registered — endpoint still exists
            if resp.status_code == 200:
                try:
                    return resp.json()
                except Exception:
                    return {"_raw": resp.text[:200], "_status": resp.status_code}
            else:
                # Endpoint exists but client rejected
                return {"_error": resp.text[:200], "_status": resp.status_code}
    except requests.RequestException as exc:
        logger.debug("Device endpoint probe failed for %s: %s", url, exc)
    return None


def analyze_device_response(endpoint_url: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze device code response for security issues."""
    findings: list[dict[str, Any]] = []

    # Endpoint exists
    findings.append({
        "severity": "medium",
        "vulnerability_type": "device_flow_found",
        "message": f"OAuth device flow endpoint found at {endpoint_url}",
    })

    if "_error" in data:
        findings.append({
            "severity": "info",
            "vulnerability_type": "device_flow_client_rejected",
            "message": f"Device flow endpoint exists but rejected test client: {data.get('_error', '')[:100]}",
        })
        return findings

    # Check expiry (expires_in)
    expires_in = data.get("expires_in")
    if expires_in is not None:
        if int(expires_in) > 900:  # > 15 minutes
            findings.append({
                "severity": "low",
                "vulnerability_type": "device_flow_long_expiry",
                "message": f"Device code expiry is {expires_in}s ({expires_in // 60} min) — longer than recommended 5-15 min",
            })

    # Check polling interval
    interval = data.get("interval")
    if interval is not None:
        if int(interval) < 5:
            findings.append({
                "severity": "medium",
                "vulnerability_type": "device_flow_short_interval",
                "message": f"Device code polling interval is {interval}s — may allow brute-force of user code",
            })

    # Check user code predictability
    user_code = data.get("user_code", "")
    if user_code:
        entropy = _entropy_estimate(user_code)
        code_clean = user_code.replace("-", "").replace(" ", "")
        code_len = len(code_clean)
        if code_len < 8:
            findings.append({
                "severity": "high",
                "vulnerability_type": "device_flow_weak_user_code",
                "message": f"Device user code is only {code_len} chars ('{user_code}') — susceptible to brute force",
            })
        if entropy < 0.3:
            findings.append({
                "severity": "medium",
                "vulnerability_type": "device_flow_low_entropy_code",
                "message": f"Device user code '{user_code}' has low character diversity — may be predictable",
            })

    # Check if verification_uri is over HTTP
    verification_uri = data.get("verification_uri", data.get("verification_url", ""))
    if verification_uri and verification_uri.startswith("http://"):
        findings.append({
            "severity": "high",
            "vulnerability_type": "device_flow_http_verification_uri",
            "message": f"Device verification URI uses HTTP: {verification_uri}",
        })

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="OAuth device flow security tester")
    parser.add_argument("--url", required=True, help="Target OAuth server URL")
    parser.add_argument("--client-id", default="", help="Optional OAuth client ID")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"findings": []}

    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "protopen-oauth-device/1.0"})

        parsed = urlparse(args.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Try OIDC well-known for device endpoint
        wk_url = urljoin(origin, "/.well-known/openid-configuration")
        device_endpoint_url: str | None = None
        try:
            wk_resp = session.get(wk_url, timeout=10)
            if wk_resp.status_code == 200:
                wk_data = wk_resp.json()
                device_endpoint_url = wk_data.get("device_authorization_endpoint")
        except Exception:
            pass

        # Probe common paths
        found = False
        for path in DEVICE_ENDPOINTS:
            probe_url = urljoin(origin, path)
            data = _check_device_endpoint(session, probe_url, args.client_id)
            if data is not None:
                findings = analyze_device_response(probe_url, data)
                result["findings"].extend(findings)
                found = True
                break

        if not found and device_endpoint_url:
            data = _check_device_endpoint(session, device_endpoint_url, args.client_id)
            if data is not None:
                findings = analyze_device_response(device_endpoint_url, data)
                result["findings"].extend(findings)
                found = True

        if not found:
            result["findings"].append({
                "severity": "info",
                "vulnerability_type": "device_flow_not_found",
                "message": "No OAuth device flow endpoint found at target",
            })

    except Exception as exc:
        result["error"] = str(exc)
        result["findings"].append({
            "severity": "error",
            "vulnerability_type": "scan_error",
            "message": f"Scan failed: {exc}",
        })
        logger.error("oauth_device_flow error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
