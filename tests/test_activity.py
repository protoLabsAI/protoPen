"""Tests for the Activity thread wiring (ADR 0003 slice 2)."""

from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

import a2a_handler
from a2a_handler import register_a2a_routes


def test_notify_terminal_invokes_hook_and_is_exception_safe():
    record = SimpleNamespace(id="t1", context_id="system:activity", accumulated_text="hi")
    seen = []
    prior = a2a_handler._ON_TERMINAL[0]
    try:
        a2a_handler._ON_TERMINAL[0] = seen.append
        a2a_handler._notify_terminal(record)
        assert seen == [record]

        # A throwing hook must not propagate into the background runner.
        def boom(_):
            raise RuntimeError("nope")

        a2a_handler._ON_TERMINAL[0] = boom
        a2a_handler._notify_terminal(record)  # no raise

        # No hook registered → no-op.
        a2a_handler._ON_TERMINAL[0] = None
        a2a_handler._notify_terminal(record)
    finally:
        a2a_handler._ON_TERMINAL[0] = prior


def _register(app, **extra):
    """Register the A2A routes on *app* with harmless stubs (+ optional kwargs)."""

    async def _stub_stream(_message, _session_id):  # pragma: no cover - not invoked
        if False:
            yield ("text", "")

    register_a2a_routes(
        app=app,
        chat_stream_fn_factory=_stub_stream,
        chat_fn=lambda *a, **k: [],
        api_key="",
        agent_card={},
        **extra,
    )


def test_activity_route_returns_history():
    async def activity_list():
        return {
            "context_id": "system:activity",
            "messages": [
                {"role": "user", "content": "morning standup"},
                {"role": "assistant", "content": "3 PRs merged overnight."},
            ],
        }

    app = FastAPI()
    _register(app, activity_list=activity_list)
    resp = TestClient(app).get("/api/activity")
    assert resp.status_code == 200
    body = resp.json()
    assert body["context_id"] == "system:activity"
    assert [m["role"] for m in body["messages"]] == ["user", "assistant"]


def test_activity_route_absent_without_callback():
    """No activity_list wired → the route isn't registered (404)."""
    app = FastAPI()
    _register(app)
    assert TestClient(app).get("/api/activity").status_code == 404
