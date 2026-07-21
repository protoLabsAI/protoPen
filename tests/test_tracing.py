"""LLM-call tracing — the emitted assistant tool_calls must be persisted, not counted.

Guards protoPen#289 item 1: today's traces recorded only ``len(tool_calls)``, so the
actual calls the model made (name + args) were unrecoverable and runs couldn't be mined
into SFT trajectories. These tests pin that the real calls now survive into the
generation ``output`` and flow through the AuditMiddleware model-call hook.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

import tracing
from graph.middleware.audit import AuditMiddleware, _serialize_messages


class _FakeGen:
    def end(self):
        pass


class _FakeLangfuse:
    def __init__(self):
        self.captured = {}

    def start_observation(self, **kwargs):
        self.captured.update(kwargs)
        return _FakeGen()


def _fake_langfuse(monkeypatch):
    fake = _FakeLangfuse()
    monkeypatch.setattr(tracing, "_enabled", True)
    monkeypatch.setattr(tracing, "_langfuse", fake)
    return fake


# ---- _normalize_tool_calls -------------------------------------------------


def test_normalize_tool_calls_dict_and_object_shapes():
    obj = NS(id="call_2", name="dns_enum", args={"domain": "example.com"})
    out = tracing._normalize_tool_calls(
        [{"name": "nmap", "args": {"target": "10.0.0.1"}, "id": "call_1", "type": "tool_call"}, obj]
    )
    assert out == [
        {"id": "call_1", "name": "nmap", "args": {"target": "10.0.0.1"}},
        {"id": "call_2", "name": "dns_enum", "args": {"domain": "example.com"}},
    ]


def test_normalize_tool_calls_empty():
    assert tracing._normalize_tool_calls(None) == []
    assert tracing._normalize_tool_calls([]) == []


# ---- trace_llm_call output persistence -------------------------------------


def test_trace_llm_call_persists_emitted_tool_calls(monkeypatch):
    fake = _fake_langfuse(monkeypatch)

    tracing.trace_llm_call(
        model="claude-sonnet-5",
        messages=[{"role": "user", "content": "scan the host"}],
        response_content="",
        response_tool_calls=[{"name": "nmap", "args": {"target": "10.0.0.1"}, "id": "call_1", "type": "tool_call"}],
        tokens_input=12,
        tokens_output=7,
    )

    output = fake.captured["output"]
    assert isinstance(output, dict), "tool-call turns must persist a structured output"
    assert output["content"] == ""
    assert output["tool_calls"] == [{"id": "call_1", "name": "nmap", "args": {"target": "10.0.0.1"}}]
    # back-compat: the count still rides in metadata
    assert fake.captured["metadata"]["tool_calls"] == 1


def test_trace_llm_call_content_only_stays_a_string(monkeypatch):
    fake = _fake_langfuse(monkeypatch)

    tracing.trace_llm_call(
        model="claude-sonnet-5",
        messages=[{"role": "user", "content": "hi"}],
        response_content="hello there",
        response_tool_calls=None,
    )

    assert fake.captured["output"] == "hello there"
    assert fake.captured["metadata"]["tool_calls"] == 0


def test_trace_llm_call_disabled_is_noop(monkeypatch):
    monkeypatch.setattr(tracing, "_enabled", False)
    assert tracing.trace_llm_call(model="m", messages=[], response_content="x") is None


# ---- AuditMiddleware.wrap_model_call seam ----------------------------------


def test_serialize_messages_keeps_roles_tool_calls_and_ids():
    msgs = [
        HumanMessage(content="scan 10.0.0.1"),
        AIMessage(
            content="", tool_calls=[{"name": "nmap", "args": {"t": "10.0.0.1"}, "id": "c1", "type": "tool_call"}]
        ),
        ToolMessage(content="port 22 open", tool_call_id="c1"),
    ]
    out = _serialize_messages(SystemMessage(content="you are protoPen"), msgs)
    assert out[0] == {"role": "system", "content": "you are protoPen"}
    assert out[1]["role"] == "user"
    assert out[2]["role"] == "assistant"
    assert out[2]["tool_calls"] == [{"id": "c1", "name": "nmap", "args": {"t": "10.0.0.1"}}]
    assert out[3] == {"role": "tool", "content": "port 22 open", "tool_call_id": "c1"}


def test_wrap_model_call_traces_emitted_tool_calls(monkeypatch):
    captured = {}
    monkeypatch.setattr(tracing, "trace_llm_call", lambda **kw: captured.update(kw))

    ai = AIMessage(
        content="",
        tool_calls=[{"name": "nmap", "args": {"target": "10.0.0.1"}, "id": "call_1", "type": "tool_call"}],
        usage_metadata={"input_tokens": 20, "output_tokens": 8, "total_tokens": 28},
        response_metadata={"finish_reason": "tool_calls"},
    )
    request = NS(
        state={"session_id": "sess-1"},
        model=NS(model_name="claude-sonnet-5"),
        system_message=None,
        messages=[HumanMessage(content="scan 10.0.0.1")],
    )
    response = NS(result=[ai])

    out = AuditMiddleware().wrap_model_call(request, lambda req: response)

    assert out is response, "the response must pass through unchanged"
    assert captured["model"] == "claude-sonnet-5"
    assert captured["response_content"] == ""
    assert captured["response_tool_calls"][0]["name"] == "nmap"
    assert captured["response_tool_calls"][0]["args"] == {"target": "10.0.0.1"}
    assert captured["tokens_input"] == 20
    assert captured["tokens_output"] == 8
    assert captured["finish_reason"] == "tool_calls"
    assert captured["metadata"]["session_id"] == "sess-1"


async def test_awrap_model_call_traces_emitted_tool_calls(monkeypatch):
    captured = {}
    monkeypatch.setattr(tracing, "trace_llm_call", lambda **kw: captured.update(kw))

    ai = AIMessage(
        content="",
        tool_calls=[{"name": "dns_enum", "args": {"domain": "example.com"}, "id": "c9", "type": "tool_call"}],
        usage_metadata={"input_tokens": 5, "output_tokens": 3, "total_tokens": 8},
        response_metadata={"finish_reason": "tool_calls"},
    )
    request = NS(
        state={"session_id": "sess-async"},
        model=NS(model_name="claude-sonnet-5"),
        system_message=None,
        messages=[HumanMessage(content="enumerate example.com")],
    )
    response = NS(result=[ai])

    async def _handler(req):
        return response

    out = await AuditMiddleware().awrap_model_call(request, _handler)

    assert out is response
    assert captured["response_tool_calls"][0]["name"] == "dns_enum"
    assert captured["tokens_output"] == 3
    assert captured["metadata"]["session_id"] == "sess-async"


def test_wrap_model_call_tracing_failure_never_breaks_the_turn(monkeypatch):
    def _boom(**kw):
        raise RuntimeError("langfuse down")

    monkeypatch.setattr(tracing, "trace_llm_call", _boom)

    ai = AIMessage(content="done")
    response = NS(result=[ai])
    request = NS(state={"session_id": "s"}, model=NS(model_name="m"), system_message=None, messages=[])

    # Tracing raising must not propagate — the model response is returned intact.
    out = AuditMiddleware().wrap_model_call(request, lambda req: response)
    assert out is response


def test_wrap_model_call_reraises_handler_error_after_tracing(monkeypatch):
    calls = {}
    monkeypatch.setattr(tracing, "trace_llm_call", lambda **kw: calls.update(kw))

    def _handler(req):
        raise ValueError("gateway exploded")

    request = NS(state={"session_id": "s"}, model=NS(model_name="m"), system_message=None, messages=[])

    import pytest

    with pytest.raises(ValueError, match="gateway exploded"):
        AuditMiddleware().wrap_model_call(request, _handler)
    # the error was traced before re-raising
    assert calls["error"] == "gateway exploded"


# ---- trace_tool_call full-fidelity output -----------------------------------


def test_trace_tool_call_stores_full_result(monkeypatch):
    """Tool spans store the full result (was capped at 1000) so it can feed trajectories."""
    fake = _fake_langfuse(monkeypatch)
    long_result = "OPEN PORTS\n" + ("22/tcp open ssh\n" * 400)  # well past the old 1000 cap
    tracing.trace_tool_call("nmap", {"t": "10.0.0.1"}, long_result, 12, True, "s1")
    assert fake.captured["output"] == long_result
    assert len(fake.captured["output"]) > 1000


def test_trace_tool_call_caps_at_safety_max(monkeypatch):
    """A pathological result is still bounded by the safety cap."""
    monkeypatch.setattr(tracing, "_TOOL_OUTPUT_MAX", 100)
    fake = _fake_langfuse(monkeypatch)
    tracing.trace_tool_call("dump", {}, "x" * 5000, 1, True, "s1")
    assert fake.captured["output"] == "x" * 100


def test_tool_wrapper_traces_full_result_but_audits_short_summary(monkeypatch):
    """The tool wrapper sends the full result to the trace but a 200-char summary to audit.jsonl."""
    import audit as audit_mod
    import metrics as metrics_mod

    audited: dict = {}
    traced: dict = {}
    monkeypatch.setattr(audit_mod.audit_logger, "log", lambda **kw: audited.update(kw))
    monkeypatch.setattr(tracing, "trace_tool_call", lambda **kw: traced.update(kw))
    monkeypatch.setattr(metrics_mod, "record_tool_call", lambda *a, **k: None)

    long_content = "finding\n" + ("detail line\n" * 300)  # far more than 200 chars
    tool_msg = ToolMessage(content=long_content, tool_call_id="c1")
    request = NS(state={"session_id": "sess-tool"}, tool_call={"name": "cve_search", "args": {"id": "CVE-1"}})

    out = AuditMiddleware().wrap_tool_call(request, lambda req: tool_msg)

    assert out is tool_msg
    assert traced["result"] == long_content  # full fidelity reaches the trace
    assert audited["result_summary"] == long_content[:200]  # audit.jsonl stays a summary
    assert len(audited["result_summary"]) == 200
