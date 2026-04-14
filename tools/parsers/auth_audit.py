"""Parser for modern auth audit output — OAuth, OIDC, SAML, JWT, WebAuthn."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def _parse_auth_json(raw: str, store: "TargetStore", check: str) -> list[dict]:
    """Shared JSON parser for auth audit tools."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    results = data if isinstance(data, list) else data.get("findings", data.get("results", [data]))
    for r in results:
        entities.append(
            {
                "type": "auth_finding",
                "check": check,
                "severity": r.get("severity", "medium"),
                "vulnerability_type": r.get("vulnerability_type", r.get("type", check)),
                "details": r.get("message", r.get("description", str(r)[:200])),
            }
        )
    return entities


def parse_oauth_redirect(raw: str, store: "TargetStore") -> list[dict]:
    return _parse_auth_json(raw, store, "oauth_redirect_test")


def parse_oauth_device_code(raw: str, store: "TargetStore") -> list[dict]:
    return _parse_auth_json(raw, store, "oauth_device_code")


def parse_oidc_discovery(raw: str, store: "TargetStore") -> list[dict]:
    """Parse OIDC .well-known config — extract key endpoints."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    # If it's a direct OIDC config (has issuer), summarize it
    if "issuer" in data:
        entities.append(
            {
                "type": "auth_finding",
                "check": "oidc_discovery",
                "severity": "info",
                "vulnerability_type": "oidc_config",
                "details": f"Issuer: {data.get('issuer', '')}, "
                f"auth: {data.get('authorization_endpoint', 'N/A')}, "
                f"token: {data.get('token_endpoint', 'N/A')}, "
                f"grants: {data.get('grant_types_supported', [])}",
            }
        )
    else:
        return _parse_auth_json(raw, store, "oidc_discovery")
    return entities


def parse_oidc_token(raw: str, store: "TargetStore") -> list[dict]:
    return _parse_auth_json(raw, store, "oidc_token_test")


def parse_saml(raw: str, store: "TargetStore") -> list[dict]:
    return _parse_auth_json(raw, store, "saml_decode")


def parse_saml_inject(raw: str, store: "TargetStore") -> list[dict]:
    return _parse_auth_json(raw, store, "saml_inject")


def parse_jwt(raw: str, store: "TargetStore") -> list[dict]:
    return _parse_auth_json(raw, store, "jwt_scan")


def parse_jwt_crack(raw: str, store: "TargetStore") -> list[dict]:
    return _parse_auth_json(raw, store, "jwt_crack")


def parse_webauthn(raw: str, store: "TargetStore") -> list[dict]:
    return _parse_auth_json(raw, store, "webauthn_test")


def parse_session_fixation(raw: str, store: "TargetStore") -> list[dict]:
    return _parse_auth_json(raw, store, "session_fixation")


PARSER_MAP[("auth_audit", "oauth_redirect_test")] = parse_oauth_redirect
PARSER_MAP[("auth_audit", "oauth_device_code")] = parse_oauth_device_code
PARSER_MAP[("auth_audit", "oidc_discovery")] = parse_oidc_discovery
PARSER_MAP[("auth_audit", "oidc_token_test")] = parse_oidc_token
PARSER_MAP[("auth_audit", "saml_decode")] = parse_saml
PARSER_MAP[("auth_audit", "saml_inject")] = parse_saml_inject
PARSER_MAP[("auth_audit", "jwt_scan")] = parse_jwt
PARSER_MAP[("auth_audit", "jwt_crack")] = parse_jwt_crack
PARSER_MAP[("auth_audit", "webauthn_test")] = parse_webauthn
PARSER_MAP[("auth_audit", "session_fixation")] = parse_session_fixation
