"""Integrated terminal — a PTY bridged to xterm.js over a WebSocket.

The operator console's Terminal rail connects a browser xterm.js to `/ws/terminal`;
this runs a real login shell in a pseudo-terminal and pipes it both ways, so the
operator can run tools directly when the agent's loop isn't the right fit.

Operator-key gated with the same key as the REST API. Browser WebSockets can't
set custom headers, so the key rides the `key` query param (the console reads it
from the same localStorage slot it uses for `x-api-key`). When no key is
configured (local dev), the socket is open like the rest of the console.

Wire protocol — JSON text frames:
    client → server: {"type":"input","data": str}
                     {"type":"resize","cols": int,"rows": int}
                     {"type":"ping"}
    server → client: {"type":"data","data": str}
                     {"type":"exit","code": int}
                     {"type":"pong"}

This is the only WebSocket on the server (everything else is REST/SSE). It is
NOT part of the OpenAPI schema, so it does not affect the api-spec drift checks.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import pty
import secrets
import shutil
import signal
import struct
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

import fcntl
import termios

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

_READ_CHUNK = 65536
# Persistent-session tuning (protopen-330).
_SCROLLBACK_BYTES = 256 * 1024  # replayed on reconnect
_IDLE_TTL_SECONDS = 30 * 60  # reap a detached session after this idle
_MAX_SESSIONS = 24
_REAP_INTERVAL = 60


def _detect_shell() -> str:
    """Best interactive shell for the host: $SHELL, then bash/zsh, then sh."""
    return os.environ.get("SHELL") or shutil.which("bash") or shutil.which("zsh") or shutil.which("sh") or "/bin/sh"


def _set_winsize(fd: int, cols: int, rows: int) -> None:
    """Push the terminal size onto the PTY (TIOCSWINSZ) so full-screen TUIs and
    line wrapping match the browser viewport."""
    cols = max(1, min(int(cols), 1000))
    rows = max(1, min(int(rows), 1000))
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def _enable_ws_tcp_nodelay() -> None:
    """Disable Nagle on uvicorn's WebSocket connections (idempotent).

    A terminal keystroke echo is a tiny frame; with Nagle + delayed-ACK the
    server's send stalls ~40ms waiting for an ACK before flushing, which is felt
    directly as input lag (measured: ~53ms median echo RTT vs ~12ms base over the
    network, min ~6ms when no stall). uvicorn doesn't set TCP_NODELAY and the
    accepted socket isn't reachable from the ASGI scope, so patch the protocol's
    ``connection_made`` to set it on each connection. Applied at registration,
    before the server accepts anything. Best-effort: a missing/changed uvicorn
    internal just leaves Nagle on (correctness unaffected, only latency)."""
    import socket as _socket

    try:
        from uvicorn.protocols.websockets.websockets_impl import WebSocketProtocol
    except Exception:  # noqa: BLE001 — uvicorn layout changed / wsproto in use
        return
    if getattr(WebSocketProtocol, "_protopen_nodelay", False):
        return

    _orig_connection_made = WebSocketProtocol.connection_made

    def connection_made(self, transport):  # type: ignore[no-untyped-def]
        _orig_connection_made(self, transport)
        try:
            sock = transport.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

    WebSocketProtocol.connection_made = connection_made
    WebSocketProtocol._protopen_nodelay = True


# ── Persistent sessions (protopen-330) ───────────────────────────────────────
# A terminal is a PTY session decoupled from any single WebSocket, so it survives
# a browser reload. A background pump always drains the PTY into a scrollback ring
# buffer and forwards to the attached socket when one is present; reconnecting
# with the same ?session= id re-attaches and replays the scrollback. A detached
# session is reaped after an idle TTL; an exited shell is cleaned up immediately.


@dataclass
class _Session:
    sid: str
    master_fd: int
    proc: subprocess.Popen
    pump: asyncio.Task | None = None
    ws: Any = None  # the currently attached WebSocket, or None when detached
    scrollback: bytearray = field(default_factory=bytearray)
    last_active: float = 0.0
    closed: bool = False


_SESSIONS: dict[str, _Session] = {}
_reaper: asyncio.Task | None = None


def _spawn_session(sid: str) -> _Session | None:
    """Start a PTY-backed shell session and its background pump. Returns None if
    the shell can't spawn."""
    shell = _detect_shell()
    # A writable cwd: the engagement sandbox if set, else $HOME. (In the hardened
    # container the rootfs is read-only; SANDBOX_DIR is tmpfs.)
    cwd = os.environ.get("SANDBOX_DIR") or os.path.expanduser("~") or "/tmp"
    if not os.path.isdir(cwd):
        cwd = "/tmp"
    master_fd, slave_fd = pty.openpty()
    try:
        _set_winsize(master_fd, 80, 24)
    except OSError:
        pass
    try:
        proc = subprocess.Popen(  # noqa: S603 — operator-gated interactive shell
            [shell],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            cwd=cwd,
            env={**os.environ, "TERM": "xterm-256color"},
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        os.close(master_fd)
        os.close(slave_fd)
        logger.warning("[terminal] shell spawn failed: %r", exc)
        return None
    os.close(slave_fd)  # the child owns the slave now
    sess = _Session(sid=sid, master_fd=master_fd, proc=proc, last_active=time.monotonic())
    _SESSIONS[sid] = sess
    sess.pump = asyncio.create_task(_pump(sess))
    return sess


async def _pump(sess: _Session) -> None:
    """Drain the PTY for the session's whole life — into the scrollback ring and,
    when attached, the socket. Runs independently of any WebSocket so output keeps
    accumulating while detached (across a reload)."""
    loop = asyncio.get_running_loop()
    try:
        while True:
            try:
                data = await loop.run_in_executor(None, os.read, sess.master_fd, _READ_CHUNK)
            except OSError:
                break
            if not data:  # shell exited (EOF)
                break
            sess.last_active = time.monotonic()
            sess.scrollback += data
            if len(sess.scrollback) > _SCROLLBACK_BYTES:
                del sess.scrollback[: len(sess.scrollback) - _SCROLLBACK_BYTES]
            ws = sess.ws
            if ws is not None:
                try:
                    await ws.send_text(json.dumps({"type": "data", "data": data.decode("utf-8", errors="replace")}))
                except Exception:  # noqa: BLE001 — detached/broken socket; keep buffering
                    pass
    finally:
        await _destroy_session(sess, exited=True)


async def _destroy_session(sess: _Session, *, exited: bool = False) -> None:
    """SIGHUP the shell, reap it, and drop the session. Idempotent."""
    if sess.closed:
        return
    sess.closed = True
    _SESSIONS.pop(sess.sid, None)
    try:
        os.killpg(os.getpgid(sess.proc.pid), signal.SIGHUP)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            sess.proc.terminate()
        except OSError:
            pass
    try:
        os.close(sess.master_fd)  # unblocks the pump's executor read
    except OSError:
        pass
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(loop.run_in_executor(None, sess.proc.wait), timeout=3)
    except (TimeoutError, asyncio.TimeoutError):
        try:
            sess.proc.kill()
        except OSError:
            pass
    ws = sess.ws
    if exited and ws is not None:
        try:
            await ws.send_text(json.dumps({"type": "exit", "code": sess.proc.returncode or 0}))
            await ws.close()
        except Exception:  # noqa: BLE001 — already tearing down
            pass


async def _reap_idle_sessions() -> None:
    """Kill detached sessions idle past the TTL so orphaned shells don't leak."""
    while True:
        await asyncio.sleep(_REAP_INTERVAL)
        now = time.monotonic()
        for sess in list(_SESSIONS.values()):
            if sess.ws is None and (now - sess.last_active) > _IDLE_TTL_SECONDS:
                await _destroy_session(sess)


def register_terminal_ws(app, *, api_key: str = "") -> None:
    """Register the `/ws/terminal` PTY bridge on the FastAPI app."""
    _enable_ws_tcp_nodelay()  # kill ~40ms Nagle stall on keystroke echo

    @app.websocket("/ws/terminal")
    async def terminal_ws(ws: WebSocket) -> None:
        # Auth before accept: browser WS can't send headers, so the operator key
        # rides ?key=. No configured key → open (local dev), like the REST routes.
        if api_key and ws.query_params.get("key") != api_key:
            await ws.close(code=1008)  # policy violation
            return
        await ws.accept()

        global _reaper
        if _reaper is None:
            _reaper = asyncio.create_task(_reap_idle_sessions())

        # Reconnect by session id; replay scrollback. A new/unknown id (or a
        # reaped one) spawns a fresh shell. Cap total sessions.
        sid = (ws.query_params.get("session") or "").strip() or secrets.token_hex(8)
        sess = _SESSIONS.get(sid)
        if sess is not None and sess.closed:
            sess = None
        if sess is None:
            if len(_SESSIONS) >= _MAX_SESSIONS:
                await ws.send_text(json.dumps({"type": "data", "data": "\r\ntoo many terminal sessions\r\n"}))
                await ws.close()
                return
            sess = _spawn_session(sid)
            if sess is None:
                await ws.send_text(json.dumps({"type": "data", "data": "\r\nshell spawn failed\r\n"}))
                await ws.close()
                return

        sess.ws = ws  # attach (single attachment; a new connect takes over)
        await ws.send_text(json.dumps({"type": "session", "id": sid}))
        if sess.scrollback:  # replay prior output into the fresh xterm
            await ws.send_text(
                json.dumps({"type": "data", "data": bytes(sess.scrollback).decode("utf-8", errors="replace")})
            )

        try:
            while True:
                raw = await ws.receive_text()
                try:
                    msg = json.loads(raw)
                except (ValueError, TypeError):
                    continue
                kind = msg.get("type")
                if kind == "input":
                    try:
                        os.write(sess.master_fd, str(msg.get("data", "")).encode("utf-8"))
                    except OSError:
                        break
                elif kind == "resize":
                    try:
                        _set_winsize(sess.master_fd, msg.get("cols", 80), msg.get("rows", 24))
                    except OSError:
                        pass
                elif kind == "clear":
                    # ⌘/Ctrl+K cleared the view — drop the server scrollback too
                    # so a reload doesn't replay the cleared output.
                    sess.scrollback.clear()
                elif kind == "ping":
                    await ws.send_text(json.dumps({"type": "pong"}))
        except WebSocketDisconnect:
            pass
        finally:
            # Detach but KEEP the PTY + pump alive so a reload can re-attach.
            if sess.ws is ws:
                sess.ws = None
                sess.last_active = time.monotonic()
