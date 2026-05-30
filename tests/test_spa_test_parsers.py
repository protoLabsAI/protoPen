"""Tests for spa_test parsers."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from tools.parsers.spa_test import (
    parse_dom_xss,
    parse_postmessage,
    parse_route_bypass,
    parse_sourcemap_check,
    parse_state_inspect,
    parse_token_leakage,
)


@pytest.fixture
def store():
    return MagicMock()


class TestRouteBypass:
    def test_bypassed_routes(self, store):
        raw = json.dumps(
            {
                "url": "https://app.example",
                "bypassed_routes": [{"path": "/admin", "severity": "high", "detail": "no guard", "guard": "authGuard"}],
            }
        )
        entities = parse_route_bypass(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "spa_finding"
        assert entities[0]["target"] == "https://app.example"
        assert entities[0]["check"] == "route_bypass:/admin"
        assert entities[0]["path"] == "/admin"

    def test_empty(self, store):
        assert parse_route_bypass(json.dumps({"bypassed_routes": []}), store) == []

    def test_invalid(self, store):
        assert parse_route_bypass("nope", store) == []


class TestStateInspect:
    def test_exposed_state(self, store):
        raw = json.dumps(
            {
                "url": "https://app",
                "exposed_state": [{"store": "redux", "severity": "medium", "key_path": "auth.token"}],
            }
        )
        entities = parse_state_inspect(raw, store)
        assert entities[0]["check"] == "state_inspect:redux"
        assert entities[0]["key_path"] == "auth.token"


class TestPostMessage:
    def test_includes_only_missing_origin_check(self, store):
        raw = json.dumps(
            {
                "url": "https://app",
                "handlers": [
                    {"location": "main.js:10", "origin_check": False, "severity": "high"},
                    {"location": "safe.js:5", "origin_check": True},
                ],
            }
        )
        entities = parse_postmessage(raw, store)
        # Only the handler without an origin check is flagged.
        assert len(entities) == 1
        assert entities[0]["location"] == "main.js:10"
        assert entities[0]["origin_check"] is False


class TestTokenLeakage:
    def test_leaks(self, store):
        raw = json.dumps(
            {"url": "https://app", "leaks": [{"storage": "localStorage", "token_type": "jwt", "severity": "high"}]}
        )
        entities = parse_token_leakage(raw, store)
        assert entities[0]["check"] == "token_leakage:localStorage"
        assert entities[0]["token_type"] == "jwt"


class TestDomXss:
    def test_sinks(self, store):
        raw = json.dumps(
            {"url": "https://app", "sinks": [{"sink_type": "innerHTML", "source": "location.hash", "severity": "high"}]}
        )
        entities = parse_dom_xss(raw, store)
        assert entities[0]["check"] == "dom_xss:innerHTML"
        assert entities[0]["source"] == "location.hash"


class TestSourcemapCheck:
    def test_exposed_maps(self, store):
        raw = json.dumps(
            {"url": "https://app", "exposed_maps": [{"file": "app.js", "map_url": "app.js.map", "severity": "medium"}]}
        )
        entities = parse_sourcemap_check(raw, store)
        assert entities[0]["check"] == "sourcemap:app.js"
        assert entities[0]["map_url"] == "app.js.map"

    def test_invalid(self, store):
        assert parse_sourcemap_check("{bad", store) == []
