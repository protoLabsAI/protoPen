"""Tests for websocket_test parsers — auth_bypass, cswsh, injection."""

from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock

from tools.parsers.websocket_test import (
    parse_ws_auth_bypass,
    parse_ws_cswsh,
    parse_ws_injection,
)


@pytest.fixture
def store():
    return MagicMock()


# ── auth_bypass parser ───────────────────────────────────────────────────────


class TestParseWsAuthBypass:
    def test_vulnerable(self, store):
        raw = json.dumps(
            {
                "url": "ws://target:8080",
                "tests": [
                    {
                        "test": "no_auth_connect",
                        "vulnerable": True,
                        "severity": "high",
                        "detail": "Server accepted unauthenticated connection",
                    },
                ],
            }
        )
        entities = parse_ws_auth_bypass(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "ws_finding"
        assert entities[0]["severity"] == "high"
        assert entities[0]["target"] == "ws://target:8080"

    def test_not_vulnerable(self, store):
        raw = json.dumps(
            {
                "url": "ws://target:8080",
                "tests": [
                    {
                        "test": "no_auth_connect",
                        "vulnerable": False,
                        "severity": "info",
                        "detail": "Connection rejected",
                    },
                ],
            }
        )
        entities = parse_ws_auth_bypass(raw, store)
        assert entities == []

    def test_empty_tests(self, store):
        raw = json.dumps({"url": "ws://t", "tests": []})
        assert parse_ws_auth_bypass(raw, store) == []

    def test_invalid_json(self, store):
        assert parse_ws_auth_bypass("not json", store) == []


# ── cswsh parser ─────────────────────────────────────────────────────────────


class TestParseWsCswsh:
    def test_vulnerable_origins(self, store):
        raw = json.dumps(
            {
                "url": "ws://target:8080",
                "tests": [
                    {
                        "test": "cswsh",
                        "origin": "https://evil.com",
                        "vulnerable": True,
                        "severity": "high",
                        "detail": "Evil origin accepted",
                    },
                    {
                        "test": "cswsh",
                        "origin": "null",
                        "vulnerable": True,
                        "severity": "high",
                        "detail": "Null origin accepted",
                    },
                    {
                        "test": "cswsh",
                        "origin": "https://attacker.example.com",
                        "vulnerable": False,
                        "severity": "info",
                        "detail": "Rejected",
                    },
                ],
            }
        )
        entities = parse_ws_cswsh(raw, store)
        assert len(entities) == 2
        assert entities[0]["check"] == "cswsh:https://evil.com"
        assert entities[1]["check"] == "cswsh:null"

    def test_all_rejected(self, store):
        raw = json.dumps(
            {
                "url": "ws://target:8080",
                "tests": [
                    {"test": "cswsh", "origin": "https://evil.com", "vulnerable": False, "severity": "info"},
                ],
            }
        )
        assert parse_ws_cswsh(raw, store) == []

    def test_invalid_json(self, store):
        assert parse_ws_cswsh("not json", store) == []


# ── injection parser ─────────────────────────────────────────────────────────


class TestParseWsInjection:
    def test_reflected_payload(self, store):
        raw = json.dumps(
            {
                "url": "ws://target:8080",
                "tests": [
                    {
                        "test": "injection",
                        "category": "sqli",
                        "payload": "' OR '1'='1",
                        "reflected": True,
                        "error_leak": False,
                        "severity": "high",
                        "response_preview": "' OR '1'='1",
                    },
                ],
            }
        )
        entities = parse_ws_injection(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "ws_finding"
        assert entities[0]["reflected"] is True
        assert entities[0]["check"] == "ws_injection:sqli"

    def test_error_leak(self, store):
        raw = json.dumps(
            {
                "url": "ws://target:8080",
                "tests": [
                    {
                        "test": "injection",
                        "category": "sqli",
                        "payload": "1; DROP TABLE",
                        "reflected": False,
                        "error_leak": True,
                        "severity": "medium",
                        "response_preview": "SQL syntax error",
                    },
                ],
            }
        )
        entities = parse_ws_injection(raw, store)
        assert len(entities) == 1
        assert entities[0]["error_leak"] is True

    def test_no_findings(self, store):
        raw = json.dumps(
            {
                "url": "ws://t",
                "tests": [
                    {
                        "test": "injection",
                        "category": "xss",
                        "payload": "<script>",
                        "reflected": False,
                        "error_leak": False,
                        "severity": "info",
                    },
                ],
            }
        )
        assert parse_ws_injection(raw, store) == []

    def test_empty_tests(self, store):
        raw = json.dumps({"url": "ws://t", "tests": []})
        assert parse_ws_injection(raw, store) == []

    def test_invalid_json(self, store):
        assert parse_ws_injection("not json", store) == []
