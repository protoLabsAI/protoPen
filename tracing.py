"""Langfuse tracing for protoPen.

Provides trace/span context for LLM calls and tool executions.
Compatible with Langfuse 4.x API (start_as_current_observation).
Falls back silently if Langfuse is not configured.
"""

from __future__ import annotations

import contextvars
import os
from typing import Any

_langfuse = None
_enabled = False

# Context vars — inherited by asyncio.create_task() children
_trace_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("_trace_id_ctx", default="")
_session_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("_session_id_ctx", default="")
_caller_trace_ctx: contextvars.ContextVar[dict] = contextvars.ContextVar("_caller_trace_ctx", default={})


def current_trace_id() -> str:
    """Return the active Langfuse trace ID, or '' if none."""
    return _trace_id_ctx.get("")


def current_session_id() -> str:
    """Return the active session ID, or '' if none."""
    return _session_id_ctx.get("")


def set_caller_context(caller_trace: dict) -> None:
    """Store incoming A2A trace metadata so start_trace() can stamp it.

    Call this before asyncio.create_task() — the child inherits the context.
    Expected keys: traceId, spanId, project.
    """
    _caller_trace_ctx.set(caller_trace or {})


def init():
    global _langfuse, _enabled

    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    host = os.environ.get("LANGFUSE_HOST") or os.environ.get("LANGFUSE_URL", "http://host.docker.internal:3001")

    if not public_key or not secret_key:
        print("[tracing] Langfuse not configured. Tracing disabled.")
        return

    try:
        from langfuse import Langfuse

        _langfuse = Langfuse(
            public_key=public_key,
            secret_key=secret_key,
            host=host,
        )
        _enabled = True
        print(f"[tracing] Langfuse initialized -> {host}")
    except ImportError:
        print("[tracing] langfuse not installed. Tracing disabled.")
    except Exception as e:
        print(f"[tracing] Langfuse init failed: {e}. Tracing disabled.")


def is_enabled() -> bool:
    return _enabled


def start_trace(session_id: str, name: str = "researcher-chat", metadata: dict | None = None) -> Any:
    """Start a new trace for a chat session.

    Automatically stamps caller_trace_id / caller_span_id when set_caller_context()
    was called by the A2A handler before spawning this coroutine.
    """
    _session_id_ctx.set(session_id)

    if not _enabled:
        return None

    try:
        from langfuse import Langfuse

        trace_id = Langfuse.create_trace_id(seed=session_id)
        _trace_id_ctx.set(trace_id)

        # Merge caller trace context for cross-agent Langfuse correlation
        caller_trace = _caller_trace_ctx.get({})
        trace_meta: dict[str, Any] = {
            **(metadata or {}),
            "session_id": session_id,
            "tags": ["protopen"],
        }
        if caller_trace.get("traceId"):
            trace_meta["caller_trace_id"] = caller_trace["traceId"]
        if caller_trace.get("spanId"):
            trace_meta["caller_span_id"] = caller_trace["spanId"]
        if caller_trace.get("project"):
            trace_meta["caller_project"] = caller_trace["project"]

        span = _langfuse.start_as_current_observation(
            name=name,
            metadata=trace_meta,
        )
        return span
    except Exception as e:
        print(f"[tracing] start_trace failed: {e}")
        return None


def end_trace():
    """End the current trace."""
    if not _enabled:
        _trace_id_ctx.set("")
        _session_id_ctx.set("")
        _caller_trace_ctx.set({})
        return
    try:
        _langfuse.flush()
    except Exception:
        pass
    _trace_id_ctx.set("")
    _session_id_ctx.set("")
    _caller_trace_ctx.set({})


def trace_llm_call(
    model: str,
    messages: list[dict],
    response_content: str | None,
    response_tool_calls: list | None = None,
    tokens_input: int = 0,
    tokens_output: int = 0,
    duration_ms: int = 0,
    finish_reason: str = "",
    error: str | None = None,
    metadata: dict | None = None,
):
    """Log an LLM call as a generation observation."""
    if not _enabled:
        return None

    try:
        gen = _langfuse.start_observation(
            name="llm-call",
            as_type="generation",
            model=model,
            input=messages,
            output=response_content or "",
            metadata={
                **(metadata or {}),
                "finish_reason": finish_reason,
                "tool_calls": len(response_tool_calls) if response_tool_calls else 0,
                **({"error": error} if error else {}),
            },
            usage_details={
                "input": tokens_input,
                "output": tokens_output,
                "total": tokens_input + tokens_output,
            },
            level="ERROR" if error else "DEFAULT",
        )
        gen.end()
        return gen
    except Exception:
        return None


def trace_tool_call(
    tool_name: str,
    args: dict,
    result: str,
    duration_ms: int,
    success: bool,
    session_id: str = "",
):
    """Log a tool execution as a span observation."""
    if not _enabled:
        return None

    safe_args = {}
    for k, v in (args or {}).items():
        sv = str(v)
        safe_args[k] = sv[:500] if len(sv) > 500 else v

    try:
        span = _langfuse.start_observation(
            name=f"tool:{tool_name}",
            as_type="tool",
            input=safe_args,
            output=result[:1000] if result else "",
            metadata={
                "duration_ms": duration_ms,
                "success": success,
                "session_id": session_id,
            },
            level="ERROR" if not success else "DEFAULT",
        )
        span.end()
        return span
    except Exception:
        return None


def score_trace(name: str, value: float, comment: str = ""):
    """Score the current trace."""
    if not _enabled:
        return
    try:
        _langfuse.score_current_trace(
            name=name,
            value=value,
            comment=comment,
        )
    except Exception:
        pass


def flush():
    if _enabled and _langfuse:
        try:
            _langfuse.flush()
        except Exception:
            pass
