"""Trajectory export — a session's Langfuse generations stitch into one untruncated
ChatML trajectory, labeled with an outcome score (protoPen#289 items 2-4).

The load-bearing property is fidelity: the exporter must reconstruct tool observations
from the *generation inputs* (full ChatML), not the ``tool:<name>`` spans (capped at
200 chars by audit.py). These tests fake the Langfuse read API so they run host-free,
mirroring tests/test_tracing.py.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace as NS

from evals import export_trajectories as ex


# --------------------------------------------------------------------------- #
# Fakes shaped like the Langfuse 4.x read API (attribute access)
# --------------------------------------------------------------------------- #
def _obs(**kw):
    kw.setdefault("type", "GENERATION")
    kw.setdefault("name", "llm-call")
    kw.setdefault("start_time", datetime(2026, 7, 21, tzinfo=timezone.utc))
    kw.setdefault("metadata", {})
    kw.setdefault("level", "DEFAULT")
    kw.setdefault("input", None)
    kw.setdefault("output", None)
    return NS(**kw)


def _trace(**kw):
    kw.setdefault("id", "trace-1")
    kw.setdefault("session_id", "eval-langgraph-cve_analysis-1712345678")
    kw.setdefault("timestamp", datetime(2026, 7, 21, tzinfo=timezone.utc))
    kw.setdefault("tags", ["protopen"])
    kw.setdefault("scores", [])
    return NS(**kw)


class _FakeApi:
    """Minimal ``lf.api`` stand-in: one page of traces, per-trace observations."""

    def __init__(self, traces, obs_by_trace):
        _traces, _obs = traces, obs_by_trace

        class _TraceEP:
            def list(self, *, page=1, limit=50, from_timestamp=None, session_id=None, tags=None):
                data = _traces if page == 1 else []
                if session_id is not None:
                    data = [t for t in data if getattr(t, "session_id", None) == session_id]
                return NS(data=data, meta=NS(page=page, limit=limit, total_items=len(data), total_pages=1))

        class _ObsEP:
            def get_many(self, *, trace_id=None, cursor=None, limit=100):
                return NS(data=list(_obs.get(trace_id, [])), meta=NS(cursor=None))

        self.trace = _TraceEP()
        self.observations = _ObsEP()


TASKS = {
    "cve_analysis": {
        "id": "cve_analysis",
        "expected_tools": ["cve_search"],
        "expected_patterns": ["CVE", "xz", "backdoor"],
    }
}

# A tool result far longer than the 200-char span cap — proves untruncated capture.
LONG_OBS = "xz backdoor (CVE-2024-3094): malicious code in liblzma. " + ("DETAIL " * 100)


def _cve_session_observations():
    """Two generations of a real tool-using turn, plus a truncated tool span."""
    sys_user = [
        {"role": "system", "content": "You are protoPen."},
        {"role": "user", "content": "Analyze CVE-2024-3094 (xz backdoor)."},
    ]
    gen1 = _obs(
        input=sys_user,
        output={"content": "", "tool_calls": [{"id": "c1", "name": "cve_search", "args": {"id": "CVE-2024-3094"}}]},
        start_time=datetime(2026, 7, 21, 0, 0, 0, tzinfo=timezone.utc),
    )
    gen2 = _obs(
        input=sys_user
        + [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"id": "c1", "name": "cve_search", "args": {"id": "CVE-2024-3094"}}],
            },
            {"role": "tool", "tool_call_id": "c1", "content": LONG_OBS},
        ],
        output="The xz backdoor CVE-2024-3094 is a supply-chain implant in liblzma.",
        start_time=datetime(2026, 7, 21, 0, 0, 5, tzinfo=timezone.utc),
    )
    tool_span = _obs(type="TOOL", name="tool:cve_search", output=LONG_OBS[:200], metadata={"success": True})
    return [gen1, gen2, tool_span]


# --------------------------------------------------------------------------- #
# build_trajectory
# --------------------------------------------------------------------------- #
def test_reconstructs_ordered_chatml_from_generations():
    rec = ex.build_trajectory(_trace(), _cve_session_observations(), tasks_by_id=TASKS)
    roles = [m["role"] for m in rec["messages"]]
    assert roles == ["system", "user", "assistant", "tool", "assistant"]
    # The emitted tool_calls survive on the assistant turn.
    assert rec["messages"][2]["tool_calls"][0]["name"] == "cve_search"
    # The final assistant turn is the generation output.
    assert "supply-chain" in rec["messages"][-1]["content"]


def test_tool_observation_is_untruncated():
    """The tool observation in the trajectory is the FULL result, not the 200-char span."""
    rec = ex.build_trajectory(_trace(), _cve_session_observations(), tasks_by_id=TASKS)
    tool_msg = next(m for m in rec["messages"] if m["role"] == "tool")
    assert tool_msg["content"] == LONG_OBS
    assert len(tool_msg["content"]) > 200


def test_outcome_score_from_task_patterns():
    rec = ex.build_trajectory(_trace(), _cve_session_observations(), tasks_by_id=TASKS)
    # final text contains CVE, xz, backdoor -> all three patterns hit.
    assert rec["score"] == 1.0
    assert rec["labels"]["pattern_score"] == 1.0
    assert rec["labels"]["tools_ok"] is True
    assert "cve_search" in rec["labels"]["tools_called"]
    assert rec["labels"]["expected_tools_coverage"] == 1.0
    assert rec["labels"]["num_tool_calls"] == 1


def test_partial_pattern_score():
    obs = _cve_session_observations()
    obs[1].output = "This response never names the vulnerability."  # 0/3 patterns
    rec = ex.build_trajectory(_trace(), obs, tasks_by_id=TASKS)
    assert rec["score"] == 0.0


def test_content_only_single_generation():
    trace = _trace(session_id="eval-langgraph-simple_question-1712345678")
    gen = _obs(
        input=[{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}],
        output="A buffer overflow is a memory-safety bug.",
    )
    rec = ex.build_trajectory(trace, [gen], tasks_by_id={})
    assert [m["role"] for m in rec["messages"]] == ["system", "user", "assistant"]
    assert rec["labels"]["num_tool_calls"] == 0
    # No matching task -> fallback pass score (non-empty answer, no failed tools).
    assert rec["score"] == 1.0


def test_longest_input_generation_is_the_spine():
    """Spine selection ignores start-time order and picks the most complete input."""
    obs = _cve_session_observations()
    obs[0], obs[1] = obs[1], obs[0]  # shuffle generation order
    rec = ex.build_trajectory(_trace(), obs, tasks_by_id=TASKS)
    assert len(rec["messages"]) == 5  # still the deep conversation, not the 2-msg one


def test_no_generations_returns_none():
    span_only = [_obs(type="SPAN", name="researcher-chat", input=None, output=None)]
    assert ex.build_trajectory(_trace(), span_only, tasks_by_id=TASKS) is None


def test_langfuse_score_overrides_when_named():
    trace = _trace(scores=[NS(name="quality", value=0.42)])
    rec = ex.build_trajectory(trace, _cve_session_observations(), tasks_by_id=TASKS, score_name="quality")
    assert rec["score"] == 0.42
    assert rec["labels"]["langfuse_scores"] == {"quality": 0.42}


# --------------------------------------------------------------------------- #
# export() end-to-end over the fake API + min-score gate
# --------------------------------------------------------------------------- #
def test_export_applies_min_score_gate():
    good = _trace(id="t-good", session_id="eval-langgraph-cve_analysis-1")
    bad = _trace(id="t-bad", session_id="eval-langgraph-cve_analysis-2")
    bad_obs = _cve_session_observations()
    bad_obs[1].output = "no keywords here"
    api = _FakeApi(
        [good, bad],
        {"t-good": _cve_session_observations(), "t-bad": bad_obs},
    )
    kept = list(ex.export(api, min_score=0.8, tasks_by_id=TASKS))
    assert [r["trace_id"] for r in kept] == ["t-good"]


def test_export_session_filter_and_full_record_shape():
    api = _FakeApi([_trace(id="t1")], {"t1": _cve_session_observations()})
    recs = list(ex.export(api, session_id="eval-langgraph-cve_analysis-1712345678", tasks_by_id=TASKS))
    assert len(recs) == 1
    r = recs[0]
    assert r["task_id"] == "cve_analysis"
    assert r["trace_id"] == "t1"
    assert set(r) == {"session_id", "trace_id", "task_id", "score", "messages", "labels"}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def test_task_id_from_session():
    assert ex._task_id_from_session("eval-langgraph-cve_analysis-1712345678") == "cve_analysis"
    assert ex._task_id_from_session("eval-langgraph-multi_step_scan_analyze-1") == "multi_step_scan_analyze"
    assert ex._task_id_from_session("chat-abc123") is None
    assert ex._task_id_from_session(None) is None


def test_parse_since_relative_and_iso():
    assert ex._parse_since(None) is None
    dt = ex._parse_since("2026-07-01")
    assert dt.year == 2026 and dt.tzinfo is not None
    rel = ex._parse_since("24h")
    assert rel.tzinfo is not None


def test_coerce_json_string_input():
    assert ex._messages_from_input('[{"role": "user", "content": "hi"}]') == [{"role": "user", "content": "hi"}]
    assert (
        ex._final_assistant('{"content": "x", "tool_calls": [{"id": "1", "name": "t", "args": {}}]}')["tool_calls"][0][
            "name"
        ]
        == "t"
    )
