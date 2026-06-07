"""Integrated terminal — PTY-over-WebSocket bridge (server/terminal.py)."""

import json
import os
import pty

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from server.terminal import _detect_shell, _set_winsize, register_terminal_ws


def test_detect_shell_returns_an_existing_path():
    shell = _detect_shell()
    assert shell and os.path.exists(shell)


def test_set_winsize_on_a_real_pty_does_not_raise():
    master, slave = pty.openpty()
    try:
        _set_winsize(master, 120, 40)  # TIOCSWINSZ — must succeed on a real fd
    finally:
        os.close(master)
        os.close(slave)


def _app(api_key: str = "") -> FastAPI:
    app = FastAPI()
    register_terminal_ws(app, api_key=api_key)
    return app


def test_ws_rejects_a_wrong_operator_key():
    """When a key is configured, the socket closes before accept on a bad key."""
    client = TestClient(_app(api_key="s3cret"))
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/terminal?key=wrong") as ws:
            ws.receive_text()


def test_ws_echo_roundtrip():
    """Open shell with no key (local-dev open mode), run `echo`, see it come
    back over the bridge — proves input → PTY → output end to end."""
    marker = "protopen_term_ok"
    client = TestClient(_app())
    with client.websocket_connect("/ws/terminal") as ws:
        ws.send_text(json.dumps({"type": "input", "data": f"echo {marker}\n"}))
        seen = ""
        for _ in range(400):
            msg = json.loads(ws.receive_text())
            if msg.get("type") == "data":
                seen += msg.get("data", "")
                if marker in seen:
                    break
        assert marker in seen


def test_ws_resize_is_accepted_mid_session():
    """A resize frame is handled without tearing the session down."""
    client = TestClient(_app())
    with client.websocket_connect("/ws/terminal") as ws:
        ws.send_text(json.dumps({"type": "resize", "cols": 100, "rows": 30}))
        ws.send_text(json.dumps({"type": "ping"}))
        # The bridge replies pong to a ping (drain any interleaved shell output).
        for _ in range(400):
            msg = json.loads(ws.receive_text())
            if msg.get("type") == "pong":
                break
        else:
            pytest.fail("no pong after resize+ping")
