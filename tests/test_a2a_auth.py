"""Tests for the A2A request-time auth/origin middleware (a2a_auth.py).

Locks two behaviors that regressed in review of the a2a-sdk migration:
  - the caller's ``bearer_token`` is authoritative — passing ``""`` (an
    API-key-only agent) must NOT let ``A2A_AUTH_TOKEN`` silently re-enable
    bearer auth behind the advertised card;
  - origin enforcement is browser-only — a request with no ``Origin`` header
    (server-to-server: the hub, the scheduler loopback) must pass even when an
    allowlist is configured; only a present, disallowed ``Origin`` is rejected.
"""

from __future__ import annotations

import a2a_auth
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _app() -> FastAPI:
    app = FastAPI()

    @app.post("/a2a")
    async def _rpc():
        return {"ok": True}

    @app.post("/public")
    async def _public():
        return {"ok": True}

    app.add_middleware(a2a_auth.A2AAuthMiddleware)
    return app


@pytest.fixture(autouse=True)
def _reset_guard():
    yield
    a2a_auth.configure(bearer_token="", api_key="", allowed_origins_raw="")


def test_empty_bearer_token_does_not_fall_back_to_env(monkeypatch):
    """A caller passing "" means open bearer — env must not re-enable it."""
    monkeypatch.setenv("A2A_AUTH_TOKEN", "sneaky-env-token")
    a2a_auth.configure(bearer_token="", api_key="", allowed_origins_raw="")
    assert a2a_auth._BEARER[0] is None
    # And the endpoint is reachable without any Authorization header.
    c = TestClient(_app())
    assert c.post("/a2a").status_code == 200


def test_none_bearer_token_still_uses_env_fallback(monkeypatch):
    """``None`` is the explicit 'use the env fallback' signal."""
    monkeypatch.setenv("A2A_AUTH_TOKEN", "env-token")
    a2a_auth.configure(bearer_token=None, api_key="", allowed_origins_raw="")
    assert a2a_auth._BEARER[0] == "env-token"


def test_origin_check_skipped_when_no_origin_header():
    """Server-to-server callers send no Origin and must not be rejected."""
    a2a_auth.configure(bearer_token="", api_key="", allowed_origins_raw="https://console.example.com")
    c = TestClient(_app())
    assert c.post("/a2a").status_code == 200  # no Origin header → allowed


def test_disallowed_origin_rejected():
    a2a_auth.configure(bearer_token="", api_key="", allowed_origins_raw="https://console.example.com")
    c = TestClient(_app())
    r = c.post("/a2a", headers={"Origin": "https://evil.example.com"})
    assert r.status_code == 403


def test_allowed_origin_passes():
    a2a_auth.configure(bearer_token="", api_key="", allowed_origins_raw="https://console.example.com")
    c = TestClient(_app())
    r = c.post("/a2a", headers={"Origin": "https://console.example.com"})
    assert r.status_code == 200


def test_x_api_key_constant_time_accept_and_reject():
    """X-API-Key is enforced when set: the exact key passes, a wrong/absent key is
    rejected. The compare is constant-time (hmac.compare_digest, #1398) — this locks
    the accept/reject behavior across that change."""
    a2a_auth.configure(bearer_token="", api_key="s3cret-key", allowed_origins_raw="")
    c = TestClient(_app())
    assert c.post("/a2a", headers={"x-api-key": "s3cret-key"}).status_code == 200
    assert c.post("/a2a", headers={"x-api-key": "wrong"}).status_code == 401
    assert c.post("/a2a").status_code == 401  # missing header → rejected
    # A non-ASCII key must reject cleanly (401), not crash compare_digest into a 500.
    assert c.post("/a2a", headers={"x-api-key": "wrøng-ké¥"}).status_code == 401


def test_guard_only_applies_to_a2a_prefix():
    """Non-/a2a paths bypass the guard entirely (origin allowlist set)."""
    a2a_auth.configure(bearer_token="", api_key="", allowed_origins_raw="https://console.example.com")
    c = TestClient(_app())
    assert c.post("/public", headers={"Origin": "https://evil.example.com"}).status_code == 200
