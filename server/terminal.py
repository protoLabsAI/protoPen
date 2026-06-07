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
import shutil
import signal
import struct
import subprocess

import fcntl
import termios

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

_READ_CHUNK = 65536


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


def register_terminal_ws(app, *, api_key: str = "") -> None:
    """Register the `/ws/terminal` PTY bridge on the FastAPI app."""
    _enable_ws_tcp_nodelay()  # kill ~40ms Nagle stall on keystroke echo

    @app.websocket("/ws/terminal")
    async def terminal_ws(ws: WebSocket) -> None:  # noqa: C901 — one cohesive bridge
        # Auth before accept: browser WS can't send headers, so the operator key
        # rides ?key=. No configured key → open (local dev), like the REST routes.
        if api_key and ws.query_params.get("key") != api_key:
            await ws.close(code=1008)  # policy violation
            return
        await ws.accept()

        shell = _detect_shell()
        # A writable cwd: the engagement sandbox if set, else $HOME. (In the
        # hardened container the rootfs is read-only; SANDBOX_DIR is tmpfs.)
        cwd = os.environ.get("SANDBOX_DIR") or os.path.expanduser("~") or "/tmp"
        if not os.path.isdir(cwd):
            cwd = "/tmp"

        # openpty + a session-leading child: cleaner than pty.fork() under an
        # asyncio server (no forking the event loop). The slave becomes the
        # shell's stdio + controlling tty via start_new_session.
        master_fd, slave_fd = pty.openpty()
        try:
            _set_winsize(master_fd, 80, 24)
        except OSError:
            pass

        env = {**os.environ, "TERM": "xterm-256color"}
        try:
            proc = subprocess.Popen(  # noqa: S603 — operator-gated interactive shell
                [shell],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=cwd,
                env=env,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            os.close(master_fd)
            os.close(slave_fd)
            await ws.send_text(json.dumps({"type": "data", "data": f"\r\nshell spawn failed: {exc}\r\n"}))
            await ws.close()
            return
        os.close(slave_fd)  # the child owns the slave now

        loop = asyncio.get_running_loop()

        async def pty_to_ws() -> None:
            # Blocking read in a thread (one per live terminal). On shell exit /
            # fd close the read returns EOF and we fall through to cleanup.
            while True:
                try:
                    data = await loop.run_in_executor(None, os.read, master_fd, _READ_CHUNK)
                except OSError:
                    break
                if not data:
                    break
                await ws.send_text(json.dumps({"type": "data", "data": data.decode("utf-8", errors="replace")}))

        async def ws_to_pty() -> None:
            while True:
                raw = await ws.receive_text()
                try:
                    msg = json.loads(raw)
                except (ValueError, TypeError):
                    continue
                kind = msg.get("type")
                if kind == "input":
                    os.write(master_fd, str(msg.get("data", "")).encode("utf-8"))
                elif kind == "resize":
                    try:
                        _set_winsize(master_fd, msg.get("cols", 80), msg.get("rows", 24))
                    except OSError:
                        pass
                elif kind == "ping":
                    await ws.send_text(json.dumps({"type": "pong"}))

        reader = asyncio.create_task(pty_to_ws())
        writer = asyncio.create_task(ws_to_pty())
        try:
            done, pending = await asyncio.wait({reader, writer}, return_when=asyncio.FIRST_COMPLETED)
            # Surface a non-disconnect crash in the writer for logs.
            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, WebSocketDisconnect):
                    logger.warning("[terminal] task ended: %r", exc)
        finally:
            # Tear down the shell first — terminating the process closes the PTY,
            # which unblocks the executor read so pty_to_ws can finish.
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGHUP)
            except (ProcessLookupError, PermissionError, OSError):
                proc.terminate()
            try:
                os.close(master_fd)
            except OSError:
                pass
            for task in (reader, writer):
                task.cancel()
            # Popen.wait() is blocking/sync — reap it off the loop with a timeout.
            try:
                await asyncio.wait_for(loop.run_in_executor(None, proc.wait), timeout=3)
            except (TimeoutError, asyncio.TimeoutError):
                proc.kill()
            if ws.client_state.name != "DISCONNECTED":
                try:
                    await ws.send_text(json.dumps({"type": "exit", "code": proc.returncode or 0}))
                    await ws.close()
                except Exception:  # noqa: BLE001 — already tearing down
                    pass
