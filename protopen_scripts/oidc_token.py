#!/usr/bin/env python3
"""OIDC token security tester.

Checks for algorithm confusion vectors using OIDC discovery.
If a token is provided, decodes it without verification and inspects claims.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from protopen_scripts._common import make_session

logger = logging.getLogger(__name__)

# Algorithms that are weak or exploitable
WEAK_ALGORITHMS = {"none", "HS256_with_RS256_key"}
DANGEROUS_ALGORITHMS = {"none"}
ALG_CONFUSION_RISK = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}


def _b64_decode_padding(s: str) -> bytes:
    """Base64 URL decode with padding correction."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def decode_jwt_unsafe(token: str) -> tuple[dict, dict, str] | None:
    """Decode JWT without verification. Returns (header, payload, signature_b64)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64_decode_padding(parts[0]))
        payload = json.loads(_b64_decode_padding(parts[1]))
        return header, payload, parts[2]
    except Exception as exc:
        logger.debug("JWT decode failed: %s", exc)
        return None


def analyze_token(token: str) -> list[dict[str, Any]]:
    """Analyze a JWT/OIDC token for security issues."""
    findings: list[dict[str, Any]] = []

    decoded = decode_jwt_unsafe(token)
    if decoded is None:
        findings.append(
            {
                "severity": "info",
                "vulnerability_type": "token_parse_error",
                "message": "Could not decode provided token — may not be a valid JWT",
            }
        )
        return findings

    header, payload, sig = decoded

    # Check algorithm
    alg = header.get("alg", "").upper()
    if alg == "NONE" or alg == "":
        findings.append(
            {
                "severity": "critical",
                "vulnerability_type": "alg_none",
                "message": "Token uses 'alg: none' — signature verification bypassed",
            }
        )
    elif alg in ("HS256", "HS384", "HS512"):
        findings.append(
            {
                "severity": "medium",
                "vulnerability_type": "hmac_algorithm",
                "message": f"Token uses HMAC algorithm {alg} — if server is RS256, algorithm confusion attack may be possible",
            }
        )
    elif alg in ALG_CONFUSION_RISK:
        findings.append(
            {
                "severity": "info",
                "vulnerability_type": "asymmetric_algorithm",
                "message": f"Token uses {alg} — check if server also accepts HS256 (algorithm confusion vector)",
            }
        )

    # Check key ID (kid) for injection
    kid = header.get("kid", "")
    if kid:
        if re.search(r"[/\\]", kid) or ".." in kid:
            findings.append(
                {
                    "severity": "high",
                    "vulnerability_type": "kid_path_traversal",
                    "message": f"Token 'kid' header contains path traversal characters: {kid!r}",
                }
            )
        if re.search(r"['\";]|--|\bOR\b|\bAND\b|\bSELECT\b", kid, re.IGNORECASE):
            findings.append(
                {
                    "severity": "high",
                    "vulnerability_type": "kid_injection",
                    "message": f"Token 'kid' header may contain injection payload: {kid!r}",
                }
            )

    # Check 'jku' or 'x5u' for SSRF/hijack
    for claim in ("jku", "x5u", "jwks_uri"):
        val = header.get(claim)
        if val:
            findings.append(
                {
                    "severity": "high",
                    "vulnerability_type": f"{claim}_injection_vector",
                    "message": f"Token header contains '{claim}': {val!r} — attacker-controlled key URL possible if server follows it",
                }
            )

    # Check expiry
    import time

    exp = payload.get("exp")
    if exp is not None:
        if exp < time.time():
            findings.append(
                {
                    "severity": "info",
                    "vulnerability_type": "token_expired",
                    "message": f"Token is expired (exp={exp})",
                }
            )
        elif exp - time.time() > 86400 * 7:
            findings.append(
                {
                    "severity": "low",
                    "vulnerability_type": "long_lived_token",
                    "message": "Token expires far in the future — long-lived tokens increase blast radius on compromise",
                }
            )

    # Check for sensitive claims
    sensitive_keys = {"password", "secret", "api_key", "apikey", "private_key"}
    for key in payload:
        if key.lower() in sensitive_keys:
            findings.append(
                {
                    "severity": "high",
                    "vulnerability_type": "sensitive_claim_in_token",
                    "message": f"Sensitive claim '{key}' found in token payload",
                }
            )

    # Audience check
    aud = payload.get("aud")
    if not aud:
        findings.append(
            {
                "severity": "medium",
                "vulnerability_type": "missing_audience",
                "message": "Token has no 'aud' (audience) claim — may be accepted by unintended services",
            }
        )

    if not findings:
        findings.append(
            {
                "severity": "info",
                "vulnerability_type": "token_ok",
                "message": f"Token decoded successfully. alg={alg}, sub={payload.get('sub', 'N/A')}, aud={payload.get('aud', 'N/A')}",
            }
        )

    return findings


def check_server_algorithm_support(session: requests.Session, base_url: str) -> list[dict[str, Any]]:
    """Check OIDC discovery for weak algorithm support."""
    findings: list[dict[str, Any]] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    wk_url = urljoin(origin, "/.well-known/openid-configuration")

    try:
        resp = session.get(wk_url, timeout=10)
        if resp.status_code == 200:
            config = resp.json()
            # Check if server advertises 'none' algorithm support
            id_token_algs = config.get("id_token_signing_alg_values_supported", [])
            if "none" in id_token_algs:
                findings.append(
                    {
                        "severity": "critical",
                        "vulnerability_type": "server_supports_alg_none",
                        "message": "OIDC server advertises 'none' as a supported signing algorithm",
                    }
                )
            # Check for both HS and RS support (confusion vector)
            has_hs = any(a.startswith("HS") for a in id_token_algs)
            has_rs = any(a.startswith("RS") or a.startswith("ES") for a in id_token_algs)
            if has_hs and has_rs:
                findings.append(
                    {
                        "severity": "medium",
                        "vulnerability_type": "mixed_algorithm_support",
                        "message": f"Server supports both HMAC and asymmetric algorithms: {id_token_algs} — algorithm confusion possible",
                    }
                )
    except Exception as exc:
        logger.debug("Algorithm check failed: %s", exc)

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="OIDC token security tester")
    parser.add_argument("--url", required=True, help="Target OIDC provider URL")
    parser.add_argument("--token", default="", help="Optional JWT/OIDC token to analyze")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"findings": []}

    try:
        session = make_session()

        # Check server-side algorithm support
        server_findings = check_server_algorithm_support(session, args.url)
        result["findings"].extend(server_findings)

        # Analyze provided token if given
        if args.token:
            token_findings = analyze_token(args.token)
            result["findings"].extend(token_findings)
        else:
            result["findings"].append(
                {
                    "severity": "info",
                    "vulnerability_type": "no_token_provided",
                    "message": "No token provided — only server-side algorithm discovery performed",
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
        logger.error("oidc_token error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
