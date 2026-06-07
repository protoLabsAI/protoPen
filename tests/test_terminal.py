"""Integrated terminal — PTY-over-WebSocket bridge (server/terminal.py)."""

import asyncio
import json
import os
import pty

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from server.terminal import (
    _detect_shell,
    _enable_ws_tcp_nodelay,
    _set_winsize,
    register_terminal_ws,
)


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


def test_enable_ws_tcp_nodelay_is_idempotent_and_patches():
    """The Nagle-disabling patch marks the uvicorn WS protocol and is safe to
    call repeatedly (kills the ~40ms keystroke-echo stall)."""
    from uvicorn.protocols.websockets.websockets_impl import WebSocketProtocol

    _enable_ws_tcp_nodelay()
    assert getattr(WebSocketProtocol, "_protopen_nodelay", False) is True
    made = WebSocketProtocol.connection_made
    _enable_ws_tcp_nodelay()  # second call is a no-op (no double-wrap)
    assert WebSocketProtocol.connection_made is made


@pytest.fixture(autouse=True)
def _cleanup_sessions():
    """Sessions now outlive a WS disconnect (protopen-330) — kill any the test
    left behind so shells don't leak between tests."""
    import signal as _signal

    import server.terminal as _term

    yield
    for sess in list(_term._SESSIONS.values()):
        try:
            os.killpg(os.getpgid(sess.proc.pid), _signal.SIGKILL)
        except OSError:
            pass
        try:
            os.close(sess.master_fd)
        except OSError:
            pass
    _term._SESSIONS.clear()


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


@pytest.mark.asyncio
async def test_ws_reconnect_replays_scrollback():
    """A session survives a WS disconnect (protopen-330): reconnecting with the
    same ?session= id replays the prior output so a browser reload restores the
    terminal. Run against a REAL uvicorn server — starlette's TestClient can't
    drive the concurrent pump-send + reconnect path (the production path can)."""
    import socket as _socket
    import threading

    import uvicorn
    import websockets

    app = _app()
    sk = _socket.socket()
    sk.bind(("127.0.0.1", 0))
    port = sk.getsockname()[1]
    sk.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(50):
            if server.started:
                break
            await asyncio.sleep(0.1)
        url = f"ws://127.0.0.1:{port}/ws/terminal?session=rex"
        marker = "scrollback_marker_42"
        async with websockets.connect(url) as ws:
            await ws.send(json.dumps({"type": "input", "data": f"echo {marker}\n"}))
            seen = ""
            for _ in range(50):
                m = json.loads(await asyncio.wait_for(ws.recv(), timeout=3))
                if m.get("type") == "data":
                    seen += m.get("data", "")
                    if marker in seen:
                        break
            assert marker in seen
        await asyncio.sleep(0.3)  # let the detach settle
        async with websockets.connect(url) as ws2:
            seen2 = ""
            for _ in range(20):
                try:
                    m = json.loads(await asyncio.wait_for(ws2.recv(), timeout=2))
                except (TimeoutError, asyncio.TimeoutError):
                    break
                if m.get("type") == "data":
                    seen2 += m.get("data", "")
                    if marker in seen2:
                        break
            assert marker in seen2, "scrollback was not replayed on reconnect"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_ws_clear_wipes_scrollback():
    """⌘/Ctrl+K sends {type:'clear'}, which empties the server scrollback so a
    later reconnect doesn't replay the cleared output."""
    import server.terminal as _term

    sid = "test-clear-1"
    tc = TestClient(_app())
    with tc.websocket_connect(f"/ws/terminal?session={sid}") as ws:
        ws.send_text(json.dumps({"type": "input", "data": "echo CLEARME_MARKER\n"}))
        seen = ""
        for _ in range(400):
            m = json.loads(ws.receive_text())
            if m.get("type") == "data":
                seen += m.get("data", "")
            if "CLEARME_MARKER" in seen:
                break
        assert "CLEARME_MARKER" in seen
        ws.send_text(json.dumps({"type": "clear"}))
        # ping→pong fences the clear (processed in receive order) before we assert.
        ws.send_text(json.dumps({"type": "ping"}))
        for _ in range(400):
            if json.loads(ws.receive_text()).get("type") == "pong":
                break
        sess = _term._SESSIONS.get(sid)
        assert sess is not None
        assert b"CLEARME_MARKER" not in bytes(sess.scrollback)


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
