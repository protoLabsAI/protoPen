"""A2A protocol handler — streaming, async task lifecycle, push notifications.

Implements the A2A spec (https://a2a-protocol.org/latest/) as a FastAPI route
factory.  All route logic lives here; server.py calls register_a2a_routes()
once during startup and otherwise stays out of the way.

Supported operations
────────────────────
  POST /a2a                            JSON-RPC 2.0 (legacy, backwards-compat)
    method: message/send               → async, returns submitted immediately
    method: message/sendStream         → SSE stream

  POST /message:send                   REST alias for message/send  (HTTP 202)
  POST /message:stream                 REST alias for message/sendStream (SSE)
  GET  /tasks/{id}                     Poll task state + artifact
  GET  /tasks/{id}:subscribe           SSE reconnect to in-progress task
  POST /tasks/{id}:cancel              Cancel a running task
  POST /tasks/{id}/pushNotificationConfigs   Register webhook after task creation
  GET  /.well-known/agent.json         Agent card
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Callable
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

logger = logging.getLogger(__name__)

# Module-level set keeps fire-and-forget tasks alive until done (prevents GC)
_background_tasks: set[asyncio.Task] = set()


def _fire_and_forget(coro) -> asyncio.Task:
    """Schedule a coroutine as a background task with a strong GC-safe reference."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


# ── Task state constants ──────────────────────────────────────────────────────

SUBMITTED = "submitted"
WORKING = "working"
COMPLETED = "completed"
FAILED = "failed"
CANCELED = "canceled"
INPUT_REQUIRED = "input-required"

_TERMINAL = {COMPLETED, FAILED, CANCELED}

# ── Data types ────────────────────────────────────────────────────────────────


@dataclass
class PushNotificationConfig:
    url: str
    token: str | None = None
    id: str = field(default_factory=lambda: str(uuid4()))


@dataclass
class TaskRecord:
    """In-memory record for a single A2A task.

    The asyncio primitives (_cancel_event, _update_event, _bg_task) are never
    serialised — _task_to_response() reads only primitive fields.
    """

    id: str
    context_id: str
    state: str
    created_at: str
    updated_at: str
    message_text: str
    accumulated_text: str = ""
    error_message: str | None = None
    last_status_message: str | None = None
    push_config: PushNotificationConfig | None = None
    # ── asyncio primitives (not serialised) ──
    _cancel_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    _update_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    _bg_task: asyncio.Task | None = field(default=None, repr=False)


# ── Task store ────────────────────────────────────────────────────────────────


class A2ATaskStore:
    """Asyncio-safe in-memory task store.

    Uses a rotate-event pattern: each call to update_state() replaces
    _update_event with a new asyncio.Event and sets the old one so all current
    subscribers wake up in lock-step.  The new event is ready for the next
    batch of waiters.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._tasks: dict[str, TaskRecord] = {}

    async def create(self, record: TaskRecord) -> TaskRecord:
        async with self._lock:
            self._tasks[record.id] = record
        return record

    async def get(self, task_id: str) -> TaskRecord | None:
        return self._tasks.get(task_id)

    async def update_state(
        self,
        task_id: str,
        state: str,
        accumulated_text: str | None = None,
        error: str | None = None,
        last_status_message: str | None = None,
    ) -> TaskRecord | None:
        async with self._lock:
            record = self._tasks.get(task_id)
            if record is None:
                return None
            record.state = state
            record.updated_at = _now_iso()
            if accumulated_text is not None:
                record.accumulated_text = accumulated_text
            if error is not None:
                record.error_message = error
            if last_status_message is not None:
                record.last_status_message = last_status_message
            old_event = record._update_event
            record._update_event = asyncio.Event()
        # Wake subscribers outside the lock so they can re-acquire it
        old_event.set()
        return record

    async def cancel(self, task_id: str) -> bool:
        record = self._tasks.get(task_id)
        if record is None:
            return False
        record._cancel_event.set()
        if record._bg_task and not record._bg_task.done():
            record._bg_task.cancel()
        return True

    async def cleanup_expired(self, ttl_seconds: int = 3600) -> int:
        """Remove terminal tasks older than ttl_seconds. Returns eviction count."""
        now = datetime.now(timezone.utc)
        async with self._lock:
            to_delete = [
                tid
                for tid, rec in self._tasks.items()
                if rec.state in _TERMINAL
                and (now - datetime.fromisoformat(rec.updated_at)).total_seconds() > ttl_seconds
            ]
            for tid in to_delete:
                del self._tasks[tid]
        if to_delete:
            logger.debug("[a2a] evicted %d expired tasks", len(to_delete))
        return len(to_delete)

    async def start_cleanup_loop(self, ttl_seconds: int = 3600, interval: int = 300) -> None:
        """Background loop that evicts expired terminal tasks every *interval* seconds."""
        while True:
            await asyncio.sleep(interval)
            try:
                await self.cleanup_expired(ttl_seconds)
            except Exception:
                logger.exception("[a2a] cleanup loop error")


# Module-level singleton — one store per process
_store = A2ATaskStore()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _is_safe_webhook_url(url: str) -> bool:
    """Return True if *url* is safe to deliver webhooks to (SSRF protection).

    Rejects: loopback, RFC-1918 private, link-local, multicast, reserved ranges,
    unspecified addresses, and non-http(s) schemes.  One-time DNS resolution is
    used so dynamic DNS rebinding is caught at registration time.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False
        # Resolve hostname → IP (raises gaierror if unresolvable)
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except (socket.gaierror, ValueError):
            return False
        return not (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except Exception:
        return False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _task_to_response(record: TaskRecord) -> dict:
    resp: dict[str, Any] = {
        "id": record.id,
        "contextId": record.context_id,
        "status": {"state": record.state, "timestamp": record.updated_at},
    }
    if record.accumulated_text:
        resp["artifacts"] = [{"parts": [{"kind": "text", "text": record.accumulated_text}]}]
    if record.error_message:
        resp["status"]["message"] = {
            "role": "agent",
            "parts": [{"kind": "text", "text": record.error_message}],
        }
    return resp


def _build_status_event(record: TaskRecord) -> dict:
    evt: dict[str, Any] = {
        "task_id": record.id,
        "context_id": record.context_id,
        "status": {"state": record.state, "timestamp": record.updated_at},
    }
    if record.error_message:
        evt["status"]["message"] = {
            "role": "agent",
            "parts": [{"kind": "text", "text": record.error_message}],
        }
    return evt


def _build_artifact_event(record: TaskRecord, *, last_chunk: bool) -> dict:
    return {
        "task_id": record.id,
        "context_id": record.context_id,
        "artifact": {"parts": [{"kind": "text", "text": record.accumulated_text}]},
        "append": True,
        "last_chunk": last_chunk,
    }


def _extract_text_and_context(message: dict, context_id: str = "") -> tuple[str, str]:
    """Pull text + contextId out of an A2A Message dict."""
    parts = message.get("parts", [])
    text = next((p.get("text", "") for p in parts if p.get("kind") == "text"), "")
    if not text:
        text = next((p.get("text", "") for p in parts), "")
    context_id = context_id or f"a2a-{uuid4()}"
    return text, context_id


# Sentinel returned by _parse_push_config when a URL was provided but blocked.
# Callers must check `is _PUSH_SSRF_BLOCKED` and return -32602 rather than
# silently dropping the webhook configuration.
_PUSH_SSRF_BLOCKED = object()


def _parse_push_config(configuration: dict) -> "PushNotificationConfig | None":
    """Parse push notification config from A2A params.

    Returns:
        PushNotificationConfig  — valid config ready to use
        None                    — no push config requested
        _PUSH_SSRF_BLOCKED      — URL provided but rejected; caller should error
    """
    cfg = (configuration or {}).get("pushNotificationConfig") or (configuration or {}).get("taskPushNotificationConfig")
    if not cfg:
        return None
    url = cfg.get("url") or cfg.get("webhookUrl", "")
    if not url:
        return None
    if not _is_safe_webhook_url(url):
        logger.warning("[a2a] rejected unsafe webhook URL: %s", url)
        return _PUSH_SSRF_BLOCKED  # type: ignore[return-value]
    auth = cfg.get("authentication") or {}
    return PushNotificationConfig(
        url=url,
        token=auth.get("credentials") or cfg.get("token"),
        id=cfg.get("id", str(uuid4())),
    )


# ── Webhook delivery ──────────────────────────────────────────────────────────


async def _deliver_webhook(record: TaskRecord, push_config: PushNotificationConfig) -> None:
    """POST a TaskStatusUpdateEvent to the configured webhook URL.

    Retries 3× with exponential backoff (1s / 3s / 9s).
    Skips retry on 4xx (client error — retrying won't help).
    """
    payload = _build_status_event(record)
    if record.state == COMPLETED and record.accumulated_text:
        payload["artifact"] = {
            "parts": [{"kind": "text", "text": record.accumulated_text}],
            "append": False,
            "last_chunk": True,
        }

    headers = {"Content-Type": "application/json"}
    if push_config.token:
        headers["Authorization"] = f"Bearer {push_config.token}"

    backoff = [1, 3, 9]
    async with httpx.AsyncClient(timeout=10) as client:
        for attempt, delay in enumerate(backoff):
            try:
                resp = await client.post(push_config.url, json=payload, headers=headers)
                if resp.status_code < 500:
                    logger.debug("[a2a] webhook delivered → %s (%s)", push_config.url, resp.status_code)
                    return
                logger.warning("[a2a] webhook 5xx (attempt %d): %s", attempt + 1, resp.status_code)
            except httpx.RequestError as exc:
                logger.warning("[a2a] webhook request error (attempt %d): %s", attempt + 1, exc)
            if attempt < len(backoff) - 1:
                await asyncio.sleep(delay)

    logger.error("[a2a] webhook failed after %d attempts: %s", len(backoff), push_config.url)


def _make_push_fn(push_config: PushNotificationConfig | None):
    async def _push(record: TaskRecord) -> None:
        if push_config and record.state in _TERMINAL | {WORKING}:
            _fire_and_forget(_deliver_webhook(record, push_config))

    return _push


# ── Background task runner ────────────────────────────────────────────────────


async def _run_task_background(
    task_id: str,
    stream_fn: Callable[[], AsyncGenerator],
    push_fn,
) -> None:
    """Run LangGraph in the background, writing state updates to the task store."""
    record = await _store.update_state(task_id, WORKING)
    if record is None:
        return
    await push_fn(record)

    accumulated = ""
    try:
        async for event_type, payload in stream_fn():
            record = await _store.get(task_id)
            if record is None:
                return
            if record._cancel_event.is_set():
                await _store.update_state(task_id, CANCELED)
                return

            if event_type == "text":
                accumulated += payload
                await _store.update_state(task_id, WORKING, accumulated_text=accumulated)

            elif event_type in ("tool_start", "tool_end"):
                # Persist tool message so :subscribe reconnects can show it
                await _store.update_state(task_id, WORKING, accumulated_text=accumulated, last_status_message=payload)

            elif event_type == "done":
                record = await _store.update_state(
                    task_id,
                    COMPLETED,
                    accumulated_text=payload or accumulated,
                )
                await push_fn(record)
                return

            elif event_type == "error":
                record = await _store.update_state(task_id, FAILED, error=payload)
                await push_fn(record)
                return

    except asyncio.CancelledError:
        await _store.update_state(task_id, CANCELED)
        raise
    except Exception as exc:
        logger.exception("[a2a] background task %s crashed", task_id)
        record = await _store.update_state(task_id, FAILED, error=str(exc))
        await push_fn(record)


# ── SSE helpers ───────────────────────────────────────────────────────────────

_SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _sse_rpc(rpc_id: Any, result: dict) -> str:
    return _sse({"jsonrpc": "2.0", "id": rpc_id, "result": result})


# ── Auth helper ───────────────────────────────────────────────────────────────


def _check_auth(request: Request, api_key: str) -> None:
    if api_key and request.headers.get("x-api-key") != api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")


# ── Route factory ─────────────────────────────────────────────────────────────


def register_a2a_routes(
    app: FastAPI,
    chat_stream_fn_factory: Callable[[str, str], AsyncGenerator],
    chat_fn: Callable,  # kept for potential future use / testing
    api_key: str,
    agent_card: dict,
) -> None:
    """Register all A2A routes on *app* and update *agent_card* capabilities."""

    # Update agent card capabilities
    agent_card.setdefault("capabilities", {})
    agent_card["capabilities"]["streaming"] = True
    agent_card["capabilities"]["pushNotifications"] = True

    # ── Agent card ────────────────────────────────────────────────────────────

    @app.get("/.well-known/agent.json", include_in_schema=False)
    async def _agent_card_route():
        return agent_card

    # ── Shared submit helper ──────────────────────────────────────────────────

    async def _submit_task(
        text: str,
        context_id: str,
        push_config: PushNotificationConfig | None,
        caller_trace: dict | None = None,
    ) -> TaskRecord:
        """Create a TaskRecord, fire the background runner, return immediately.

        *caller_trace* is optional A2A trace metadata from the parent caller
        (params.metadata["a2a.trace"]).  When present it is propagated into the
        Langfuse trace as caller_trace_id / caller_span_id for cross-agent
        correlation.  asyncio.create_task() inherits the current context so the
        contextvars set here flow into the background coroutine automatically.
        """
        if caller_trace:
            try:
                import tracing as _tracing

                _tracing.set_caller_context(caller_trace)
            except Exception:
                pass

        task_id = str(uuid4())
        now = _now_iso()
        record = TaskRecord(
            id=task_id,
            context_id=context_id,
            state=SUBMITTED,
            created_at=now,
            updated_at=now,
            message_text=text,
            push_config=push_config,
        )
        await _store.create(record)

        push_fn = _make_push_fn(push_config)
        bg = asyncio.create_task(
            _run_task_background(
                task_id,
                lambda: chat_stream_fn_factory(text, context_id),
                push_fn,
            )
        )
        record._bg_task = bg
        logger.info("[a2a] task %s submitted (context=%s)", task_id, context_id)
        return record

    # ── Shared subscribe SSE generator ───────────────────────────────────────

    async def _subscribe_sse_gen(task_id: str, rpc_id: Any = None):
        """Fan-out SSE generator that reads from the task store.

        Emits current snapshot immediately on (re)connect, then waits for
        _update_event to wake and yields deltas.  Producer runs independently —
        consumer disconnection cannot cancel it.
        """
        r = await _store.get(task_id)
        if r is None:
            return

        # Snapshot on connect
        status_payload: dict[str, Any] = {"state": r.state, "timestamp": r.updated_at}
        if r.error_message:
            status_payload["message"] = {"role": "agent", "parts": [{"kind": "text", "text": r.error_message}]}
        yield _sse_rpc(rpc_id, {"id": task_id, "contextId": r.context_id, "status": status_payload})
        if r.accumulated_text:
            yield _sse_rpc(
                rpc_id,
                {
                    "id": task_id,
                    "contextId": r.context_id,
                    "artifacts": [
                        {
                            "parts": [{"kind": "text", "text": r.accumulated_text}],
                            "append": r.state not in _TERMINAL,
                            "last_chunk": r.state in _TERMINAL,
                        }
                    ],
                },
            )
        if r.state in _TERMINAL:
            return

        last_text_len = len(r.accumulated_text)
        while True:
            r = await _store.get(task_id)
            if r is None:
                return
            if r.state in _TERMINAL:
                # Emit any remaining text then terminal status
                if r.accumulated_text and len(r.accumulated_text) > last_text_len:
                    yield _sse_rpc(
                        rpc_id,
                        {
                            "id": task_id,
                            "contextId": r.context_id,
                            "artifacts": [
                                {
                                    "parts": [{"kind": "text", "text": r.accumulated_text[last_text_len:]}],
                                    "append": False,
                                    "last_chunk": True,
                                }
                            ],
                        },
                    )
                terminal_status: dict[str, Any] = {"state": r.state, "timestamp": r.updated_at}
                if r.error_message:
                    terminal_status["message"] = {
                        "role": "agent",
                        "parts": [{"kind": "text", "text": r.error_message}],
                    }
                yield _sse_rpc(rpc_id, {"id": task_id, "contextId": r.context_id, "status": terminal_status})
                return

            next_event = r._update_event
            try:
                await asyncio.wait_for(next_event.wait(), timeout=25)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue

            r = await _store.get(task_id)
            if r is None:
                return

            # Status frame (include tool message if present)
            status_evt: dict[str, Any] = {"state": r.state, "timestamp": r.updated_at}
            if r.last_status_message:
                status_evt["message"] = {
                    "role": "agent",
                    "parts": [{"kind": "text", "text": r.last_status_message}],
                }
            yield _sse_rpc(rpc_id, {"id": task_id, "contextId": r.context_id, "status": status_evt})

            # Delta-only text frame
            if r.accumulated_text and len(r.accumulated_text) > last_text_len:
                new_text = r.accumulated_text[last_text_len:]
                last_text_len = len(r.accumulated_text)
                yield _sse_rpc(
                    rpc_id,
                    {
                        "id": task_id,
                        "contextId": r.context_id,
                        "artifacts": [
                            {"parts": [{"kind": "text", "text": new_text}], "append": True, "last_chunk": False}
                        ],
                    },
                )

            if r.state in _TERMINAL:
                return

    # ── Streaming SSE generator (submit + fan-out) ────────────────────────────

    async def _stream_new_task(
        text: str,
        context_id: str,
        push_config: PushNotificationConfig | None,
        rpc_id: Any = None,
        caller_trace: dict | None = None,
    ):
        """Submit task (independent background producer) then fan-out via store.

        The producer survives consumer disconnection — SSE reconnection via
        :subscribe or tasks/resubscribe will resume from where text left off.
        """
        record = await _submit_task(text, context_id, push_config, caller_trace=caller_trace)
        task_id = record.id

        # Frame 0: submitted — client can extract task_id as polling fallback
        yield _sse_rpc(
            rpc_id,
            {"id": task_id, "contextId": context_id, "status": {"state": SUBMITTED, "timestamp": record.created_at}},
        )

        # Fan-out via shared subscribe generator
        async for frame in _subscribe_sse_gen(task_id, rpc_id=rpc_id):
            yield frame

    # ── POST /a2a  (JSON-RPC 2.0 — legacy, backwards-compat) ─────────────────

    @app.post("/a2a", include_in_schema=False)
    async def _a2a_rpc(request: Request, req: dict):
        if api_key and request.headers.get("x-api-key") != api_key:
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)

        rpc_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params", {})

        # ── message/send + message/sendStream extract message body ──────────────
        if method in ("message/send", "message/sendStream", "message/stream"):
            message = params.get("message", {})
            context_id = params.get("contextId", "")
            configuration = params.get("configuration", {})
            caller_trace = (params.get("metadata") or {}).get("a2a.trace")

            parts = message.get("parts", [])
            text = next((p.get("text", "") for p in parts if p.get("kind") == "text"), "")
            if not text:
                text = next((p.get("text", "") for p in parts), "")

            if not text:
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32602, "message": "No text content in message"},
                }

            context_id = context_id or f"a2a-{uuid4()}"
            push_config = _parse_push_config(configuration)
            if push_config is _PUSH_SSRF_BLOCKED:
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32602, "message": "Unsafe or invalid webhook URL (SSRF protection)"},
                }

            # ── message/sendStream / message/stream → SSE ─────────────────────
            if method in ("message/sendStream", "message/stream"):
                return StreamingResponse(
                    _stream_new_task(text, context_id, push_config, rpc_id=rpc_id, caller_trace=caller_trace),
                    media_type="text/event-stream",
                    headers=_SSE_HEADERS,
                )

            # ── message/send → async, returns submitted immediately ───────────
            record = await _submit_task(text, context_id, push_config, caller_trace=caller_trace)
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "id": record.id,
                    "contextId": record.context_id,
                    "status": {"state": SUBMITTED, "timestamp": record.created_at},
                },
            }

        # ── tasks/get ─────────────────────────────────────────────────────────
        if method == "tasks/get":
            task_id = params.get("id") or params.get("taskId", "")
            if not task_id:
                return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32602, "message": "id required"}}
            record = await _store.get(task_id)
            if record is None:
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32001, "message": f"Task not found: {task_id}"},
                }
            return {"jsonrpc": "2.0", "id": rpc_id, "result": _task_to_response(record)}

        # ── tasks/cancel ──────────────────────────────────────────────────────
        if method == "tasks/cancel":
            task_id = params.get("id") or params.get("taskId", "")
            if not task_id:
                return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32602, "message": "id required"}}
            record = await _store.get(task_id)
            if record is None:
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32001, "message": f"Task not found: {task_id}"},
                }
            if record.state in _TERMINAL:
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32002, "message": f"Task already terminal: {record.state}"},
                }
            await _store.cancel(task_id)
            record = await _store.update_state(task_id, CANCELED)
            return {"jsonrpc": "2.0", "id": rpc_id, "result": _task_to_response(record)}

        # ── tasks/resubscribe → SSE ───────────────────────────────────────────
        if method == "tasks/resubscribe":
            task_id = params.get("id") or params.get("taskId", "")
            if not task_id:
                return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32602, "message": "id required"}}
            if await _store.get(task_id) is None:
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32001, "message": f"Task not found: {task_id}"},
                }
            return StreamingResponse(
                _subscribe_sse_gen(task_id, rpc_id=rpc_id),
                media_type="text/event-stream",
                headers=_SSE_HEADERS,
            )

        # ── tasks/pushNotificationConfig/set ──────────────────────────────────
        if method == "tasks/pushNotificationConfig/set":
            task_id = params.get("id") or params.get("taskId", "")
            cfg_data = params.get("pushNotificationConfig") or params
            if not task_id:
                return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32602, "message": "id required"}}
            record = await _store.get(task_id)
            if record is None:
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32001, "message": f"Task not found: {task_id}"},
                }
            webhook_url = cfg_data.get("url") or cfg_data.get("webhookUrl", "")
            if not webhook_url or not _is_safe_webhook_url(webhook_url):
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32602, "message": "Invalid or unsafe webhook URL"},
                }
            auth = cfg_data.get("authentication") or {}
            cfg = PushNotificationConfig(
                url=webhook_url,
                token=auth.get("credentials") or cfg_data.get("token"),
                id=cfg_data.get("id", str(uuid4())),
            )
            async with _store._lock:
                record.push_config = cfg
            if record.state in _TERMINAL:
                _fire_and_forget(_deliver_webhook(record, cfg))
            logger.info("[a2a] push config set for task %s → %s", task_id, cfg.url)
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"id": cfg.id, "task_id": task_id, "url": cfg.url}}

        # ── tasks/pushNotificationConfig/get ──────────────────────────────────
        if method == "tasks/pushNotificationConfig/get":
            task_id = params.get("id") or params.get("taskId", "")
            if not task_id:
                return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32602, "message": "id required"}}
            record = await _store.get(task_id)
            if record is None:
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32001, "message": f"Task not found: {task_id}"},
                }
            result = None
            if record.push_config:
                result = {"id": record.push_config.id, "task_id": task_id, "url": record.push_config.url}
            return {"jsonrpc": "2.0", "id": rpc_id, "result": result}

        # ── tasks/pushNotificationConfig/list ─────────────────────────────────
        if method == "tasks/pushNotificationConfig/list":
            task_id = params.get("id") or params.get("taskId", "")
            if not task_id:
                return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32602, "message": "id required"}}
            record = await _store.get(task_id)
            if record is None:
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32001, "message": f"Task not found: {task_id}"},
                }
            configs = []
            if record.push_config:
                configs = [{"id": record.push_config.id, "task_id": task_id, "url": record.push_config.url}]
            return {"jsonrpc": "2.0", "id": rpc_id, "result": configs}

        # ── tasks/pushNotificationConfig/delete ───────────────────────────────
        if method == "tasks/pushNotificationConfig/delete":
            task_id = params.get("id") or params.get("taskId", "")
            if not task_id:
                return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32602, "message": "id required"}}
            record = await _store.get(task_id)
            if record is None:
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32001, "message": f"Task not found: {task_id}"},
                }
            async with _store._lock:
                record.push_config = None
            return {"jsonrpc": "2.0", "id": rpc_id, "result": None}

        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    # ── POST /message:send  (REST) ────────────────────────────────────────────

    @app.post("/message:send", include_in_schema=False)
    async def _rest_send(request: Request, body: dict):
        _check_auth(request, api_key)
        message = body.get("message", {})
        configuration = body.get("configuration", {})
        context_id = body.get("contextId", "")
        text, context_id = _extract_text_and_context(message, context_id)
        if not text:
            raise HTTPException(400, "No text content in message")
        push_config = _parse_push_config(configuration)
        if push_config is _PUSH_SSRF_BLOCKED:
            raise HTTPException(422, "Unsafe or invalid webhook URL (SSRF protection)")
        record = await _submit_task(text, context_id, push_config)
        return JSONResponse(_task_to_response(record), status_code=202)

    # ── POST /message:stream  (REST SSE) ─────────────────────────────────────

    @app.post("/message:stream", include_in_schema=False)
    async def _rest_stream(request: Request, body: dict):
        _check_auth(request, api_key)
        message = body.get("message", {})
        configuration = body.get("configuration", {})
        context_id = body.get("contextId", "")
        text, context_id = _extract_text_and_context(message, context_id)
        if not text:
            raise HTTPException(400, "No text content in message")
        push_config = _parse_push_config(configuration)
        if push_config is _PUSH_SSRF_BLOCKED:
            raise HTTPException(422, "Unsafe or invalid webhook URL (SSRF protection)")
        return StreamingResponse(
            _stream_new_task(text, context_id, push_config),
            media_type="text/event-stream",
            headers=_SSE_HEADERS,
        )

    # ── GET /tasks/{task_id} ──────────────────────────────────────────────────

    @app.get("/tasks/{task_id}", include_in_schema=False)
    async def _get_task(task_id: str, request: Request):
        _check_auth(request, api_key)
        record = await _store.get(task_id)
        if record is None:
            raise HTTPException(404, f"Task not found: {task_id}")
        return _task_to_response(record)

    # ── GET /tasks/{task_id}:subscribe  (SSE reconnect — plain SSE) ──────────

    @app.get("/tasks/{task_id}:subscribe", include_in_schema=False)
    async def _subscribe_task(task_id: str, request: Request):
        _check_auth(request, api_key)
        if await _store.get(task_id) is None:
            raise HTTPException(404, f"Task not found: {task_id}")
        return StreamingResponse(
            _subscribe_sse_gen(task_id, rpc_id=None),
            media_type="text/event-stream",
            headers=_SSE_HEADERS,
        )

    # ── POST /tasks/{task_id}:cancel ──────────────────────────────────────────

    @app.post("/tasks/{task_id}:cancel", include_in_schema=False)
    async def _cancel_task(task_id: str, request: Request):
        _check_auth(request, api_key)
        record = await _store.get(task_id)
        if record is None:
            raise HTTPException(404, f"Task not found: {task_id}")
        if record.state in _TERMINAL:
            raise HTTPException(409, f"Task already terminal: {record.state}")
        await _store.cancel(task_id)
        record = await _store.update_state(task_id, CANCELED)
        return _task_to_response(record)

    # ── POST /tasks/{task_id}/pushNotificationConfigs ─────────────────────────

    @app.post("/tasks/{task_id}/pushNotificationConfigs", include_in_schema=False)
    async def _create_push_config(task_id: str, request: Request, body: dict):
        _check_auth(request, api_key)
        record = await _store.get(task_id)
        if record is None:
            raise HTTPException(404, f"Task not found: {task_id}")

        webhook_url = body.get("url") or body.get("webhookUrl", "")
        if not webhook_url:
            raise HTTPException(400, "url is required")
        if not _is_safe_webhook_url(webhook_url):
            raise HTTPException(422, "Unsafe webhook URL (SSRF protection)")

        auth = body.get("authentication") or {}
        cfg = PushNotificationConfig(
            url=webhook_url,
            token=auth.get("credentials") or body.get("token"),
            id=body.get("id", str(uuid4())),
        )
        async with _store._lock:
            record.push_config = cfg

        if record.state in _TERMINAL:
            _fire_and_forget(_deliver_webhook(record, cfg))

        logger.info("[a2a] push config registered for task %s → %s", task_id, cfg.url)
        return {"id": cfg.id, "task_id": task_id, "url": cfg.url}

    # ── Start TTL eviction loop on server startup ─────────────────────────────
    # Must run inside the event loop — use a startup handler, not bare create_task()
    # which would fail when called during synchronous app construction.
    @app.on_event("startup")
    async def _start_a2a_cleanup():
        _fire_and_forget(_store.start_cleanup_loop())

    logger.info("[a2a] routes registered (streaming=True, pushNotifications=True, ttl=3600s)")
