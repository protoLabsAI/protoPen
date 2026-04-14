"""Tests for auth_audit parsers."""
from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock

from tools.parsers.auth_audit import (
    parse_oauth_redirect,
    parse_oauth_device_code,
    parse_oidc_discovery,
    parse_oidc_token,
    parse_saml,
    parse_saml_inject,
    parse_jwt,
    parse_jwt_crack,
    parse_webauthn,
    parse_session_fixation,
)


@pytest.fixture
def store():
    return MagicMock()


class TestParseOAuthRedirect:
    def test_findings(self, store):
        raw = json.dumps({"findings": [
            {"severity": "high", "vulnerability_type": "open_redirect", "message": "Redirect accepted to attacker domain"},
        ]})
        entities = parse_oauth_redirect(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "auth_finding"
        assert entities[0]["severity"] == "high"

    def test_empty(self, store):
        assert parse_oauth_redirect(json.dumps({"findings": []}), store) == []

    def test_invalid(self, store):
        assert parse_oauth_redirect("not json", store) == []


class TestParseOAuthDeviceCode:
    def test_findings(self, store):
        raw = json.dumps({"findings": [{"severity": "medium", "message": "Device code flow allows phishing"}]})
        entities = parse_oauth_device_code(raw, store)
        assert len(entities) == 1

    def test_invalid(self, store):
        assert parse_oauth_device_code("not json", store) == []


class TestParseOIDCDiscovery:
    def test_oidc_config(self, store):
        raw = json.dumps({
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "grant_types_supported": ["authorization_code", "refresh_token"],
        })
        entities = parse_oidc_discovery(raw, store)
        assert len(entities) == 1
        assert "auth.example.com" in entities[0]["details"]

    def test_findings_format(self, store):
        raw = json.dumps({"findings": [{"severity": "medium", "message": "Implicit flow enabled"}]})
        entities = parse_oidc_discovery(raw, store)
        assert len(entities) == 1

    def test_invalid(self, store):
        assert parse_oidc_discovery("not json", store) == []


class TestParseOIDCToken:
    def test_findings(self, store):
        raw = json.dumps({"findings": [{"severity": "critical", "message": "Token accepted without audience validation"}]})
        entities = parse_oidc_token(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "critical"

    def test_invalid(self, store):
        assert parse_oidc_token("not json", store) == []


class TestParseSAML:
    def test_decode(self, store):
        raw = json.dumps({"findings": [{"severity": "high", "message": "SAML response unsigned"}]})
        entities = parse_saml(raw, store)
        assert len(entities) == 1

    def test_inject(self, store):
        raw = json.dumps({"findings": [{"severity": "critical", "message": "XML signature wrapping succeeded"}]})
        entities = parse_saml_inject(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "critical"

    def test_invalid(self, store):
        assert parse_saml("not json", store) == []


class TestParseJWT:
    def test_scan_findings(self, store):
        raw = json.dumps({"findings": [
            {"severity": "critical", "vulnerability_type": "alg_confusion", "message": "RS256 to HS256 downgrade"},
        ]})
        entities = parse_jwt(raw, store)
        assert len(entities) == 1
        assert entities[0]["vulnerability_type"] == "alg_confusion"

    def test_crack_success(self, store):
        raw = json.dumps({"findings": [{"severity": "critical", "message": "Secret found: password123"}]})
        entities = parse_jwt_crack(raw, store)
        assert len(entities) == 1

    def test_invalid(self, store):
        assert parse_jwt("not json", store) == []


class TestParseWebAuthn:
    def test_findings(self, store):
        raw = json.dumps({"findings": [{"severity": "medium", "message": "Origin not validated in assertion"}]})
        entities = parse_webauthn(raw, store)
        assert len(entities) == 1

    def test_invalid(self, store):
        assert parse_webauthn("not json", store) == []


class TestParseSessionFixation:
    def test_findings(self, store):
        raw = json.dumps({"findings": [
            {"severity": "high", "vulnerability_type": "session_fixation", "message": "Session ID not rotated after login"},
        ]})
        entities = parse_session_fixation(raw, store)
        assert len(entities) == 1
        assert entities[0]["vulnerability_type"] == "session_fixation"

    def test_invalid(self, store):
        assert parse_session_fixation("not json", store) == []
