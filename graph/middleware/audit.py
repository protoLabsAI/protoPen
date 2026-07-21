"""AuditMiddleware — logs tool calls to audit.py, Langfuse, and Prometheus.

Wraps every tool execution with timing, success/failure tracking,
and observability integration. Reuses existing audit/tracing/metrics modules.
"""

import time
from typing import Any, Callable

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import AIMessage, ToolMessage

from langgraph.prebuilt.chat_agent_executor import AgentState

from graph.state import session_id_from_state

_ROLE_MAP = {"human": "user", "ai": "assistant", "system": "system", "tool": "tool"}


def _model_name(model) -> str:
    """Best-effort model identifier off a BaseChatModel (provider-dependent)."""
    if model is None:
        return "unknown"
    return getattr(model, "model_name", None) or getattr(model, "model", None) or type(model).__name__


def _serialize_messages(system_message, messages) -> list[dict]:
    """Serialize the model input to clean ChatML-ish dicts for trajectory capture.

    Assistant messages keep their emitted ``tool_calls`` and tool messages keep
    their ``tool_call_id`` so a session's generations stitch back into an ordered
    ``system -> user -> assistant[tool_calls] -> tool[obs]`` trajectory.
    """
    import tracing

    out: list[dict] = []
    if system_message is not None:
        out.append({"role": "system", "content": getattr(system_message, "content", "")})
    for m in messages or []:
        role = _ROLE_MAP.get(getattr(m, "type", ""), getattr(m, "type", "unknown"))
        entry: dict = {"role": role, "content": getattr(m, "content", "")}
        tcs = getattr(m, "tool_calls", None)
        if tcs:
            entry["tool_calls"] = tracing._normalize_tool_calls(tcs)
        tcid = getattr(m, "tool_call_id", None)
        if tcid:
            entry["tool_call_id"] = tcid
        out.append(entry)
    return out


def _first_ai_message(result):
    """Return the first AIMessage in a ModelResponse result list, or None."""
    for m in result or []:
        if isinstance(m, AIMessage):
            return m
    return None


class AuditMiddleware(AgentMiddleware):
    """Log all tool calls to audit, Langfuse, and Prometheus."""

    def __init__(self):
        super().__init__()

    def wrap_tool_call(self, request, handler):
        return self._handle_tool_call(request, handler)

    async def awrap_tool_call(self, request, handler):
        return await self._ahandle_tool_call(request, handler)

    def wrap_model_call(self, request, handler):
        t0 = time.monotonic()
        try:
            response = handler(request)
        except Exception as exc:
            self._trace_model_call(request, None, int((time.monotonic() - t0) * 1000), error=exc)
            raise
        self._trace_model_call(request, response, int((time.monotonic() - t0) * 1000))
        return response

    async def awrap_model_call(self, request, handler):
        t0 = time.monotonic()
        try:
            response = await handler(request)
        except Exception as exc:
            self._trace_model_call(request, None, int((time.monotonic() - t0) * 1000), error=exc)
            raise
        self._trace_model_call(request, response, int((time.monotonic() - t0) * 1000))
        return response

    def _trace_model_call(self, request, response, duration_ms: int, error: Exception | None = None):
        """Capture the assistant message (content + emitted tool_calls) as a trace.

        The tool wrappers only see tool *executions*; without this the model call
        that decided which tools to run — and the exact args it emitted — is never
        recorded. Fully best-effort: a tracing failure must never break the turn.
        """
        import tracing

        try:
            session_id = session_id_from_state(getattr(request, "state", None))
            messages = _serialize_messages(getattr(request, "system_message", None), getattr(request, "messages", None))

            content: Any = ""
            tool_calls = None
            tokens_in = tokens_out = 0
            finish_reason = ""
            if response is not None:
                ai = _first_ai_message(getattr(response, "result", None))
                if ai is not None:
                    content = ai.content
                    tool_calls = getattr(ai, "tool_calls", None) or None
                    usage = getattr(ai, "usage_metadata", None) or {}
                    tokens_in = usage.get("input_tokens", 0) or 0
                    tokens_out = usage.get("output_tokens", 0) or 0
                    meta = getattr(ai, "response_metadata", None) or {}
                    finish_reason = meta.get("finish_reason") or meta.get("stop_reason") or ""

            tracing.trace_llm_call(
                model=_model_name(getattr(request, "model", None)),
                messages=messages,
                response_content=content,
                response_tool_calls=tool_calls,
                tokens_input=tokens_in,
                tokens_output=tokens_out,
                duration_ms=duration_ms,
                finish_reason=finish_reason,
                error=str(error)[:500] if error else None,
                metadata={"session_id": session_id},
            )
        except Exception:
            # Tracing is best-effort observability; never let it disturb the loop.
            pass

    def _handle_tool_call(self, request, handler):
        """Sync wrapper — times and logs tool execution."""
        from audit import audit_logger
        import tracing
        import metrics

        tool_name = request.tool_call.get("name", "unknown")
        args = request.tool_call.get("args", {})
        session_id = session_id_from_state(getattr(request, "state", None))

        t0 = time.monotonic()
        try:
            result = handler(request)
            duration_ms = int((time.monotonic() - t0) * 1000)

            content = ""
            if isinstance(result, ToolMessage):
                content = str(result.content)[:200]
            success = not content.startswith("Error")

            audit_logger.log(
                session_id=session_id,
                tool=tool_name,
                args=args,
                result_summary=content,
                duration_ms=duration_ms,
                success=success,
            )
            tracing.trace_tool_call(
                tool_name=tool_name,
                args=args,
                result=content,
                duration_ms=duration_ms,
                success=success,
                session_id=session_id,
            )
            metrics.record_tool_call(tool_name, success, duration_ms / 1000)

            return result
        except Exception as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            audit_logger.log(
                session_id=session_id,
                tool=tool_name,
                args=args,
                result_summary=str(exc)[:200],
                duration_ms=duration_ms,
                success=False,
            )
            tracing.trace_tool_call(
                tool_name=tool_name,
                args=args,
                result=str(exc)[:200],
                duration_ms=duration_ms,
                success=False,
                session_id=session_id,
            )
            metrics.record_tool_call(tool_name, False, duration_ms / 1000)
            raise

    async def _ahandle_tool_call(self, request, handler):
        """Async wrapper — same logic, async execution."""
        from audit import audit_logger
        import tracing
        import metrics

        tool_name = request.tool_call.get("name", "unknown")
        args = request.tool_call.get("args", {})
        session_id = session_id_from_state(getattr(request, "state", None))

        t0 = time.monotonic()
        try:
            result = await handler(request)
            duration_ms = int((time.monotonic() - t0) * 1000)

            content = ""
            if isinstance(result, ToolMessage):
                content = str(result.content)[:200]
            success = not content.startswith("Error")

            audit_logger.log(
                session_id=session_id,
                tool=tool_name,
                args=args,
                result_summary=content,
                duration_ms=duration_ms,
                success=success,
            )
            tracing.trace_tool_call(
                tool_name=tool_name,
                args=args,
                result=content,
                duration_ms=duration_ms,
                success=success,
                session_id=session_id,
            )
            metrics.record_tool_call(tool_name, success, duration_ms / 1000)

            return result
        except Exception as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            audit_logger.log(
                session_id=session_id,
                tool=tool_name,
                args=args,
                result_summary=str(exc)[:200],
                duration_ms=duration_ms,
                success=False,
            )
            tracing.trace_tool_call(
                tool_name=tool_name,
                args=args,
                result=str(exc)[:200],
                duration_ms=duration_ms,
                success=False,
                session_id=session_id,
            )
            metrics.record_tool_call(tool_name, False, duration_ms / 1000)
            raise
