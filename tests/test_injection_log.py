"""Injected-memory forensic log (ADR 0069 phase 5 / D6-D7, h34.16).

Covers the append-only InjectionLogger, the console reader (recent_injections), and the
KnowledgeMiddleware wiring that records what recalled memory was injected each turn.
Host-free: a tmp-path log + a fake store.
"""

from __future__ import annotations

from observability.injection_log import InjectionLogger
from operator_api.injections import recent_injections


def _logger(tmp_path):
    return InjectionLogger(path=tmp_path / "injections.jsonl")


def _hits():
    return [
        {"id": "cves:c1", "table": "cves", "source_type": None, "trust_tier": 3, "preview": "curated cve"},
        {"id": "facts:f1", "table": "facts", "source_type": "osint", "trust_tier": 1, "preview": "scraped claim"},
    ]


# ── logger ────────────────────────────────────────────────────────────────────


def test_log_and_get_recent_roundtrip(tmp_path):
    log = _logger(tmp_path)
    log.log(session_id="a2a:s1", hits=_hits(), min_trust=1)
    recent = log.get_recent(10)
    assert len(recent) == 1
    ev = recent[0]
    assert ev["session_id"] == "a2a:s1"
    assert ev["min_trust"] == 1
    assert ev["count"] == 2
    assert {h["id"] for h in ev["hits"]} == {"cves:c1", "facts:f1"}
    assert ev["hits"][1]["trust_tier"] == 1  # provenance preserved


def test_empty_hits_is_noop(tmp_path):
    log = _logger(tmp_path)
    log.log(session_id="a2a:s1", hits=[], min_trust=2)
    assert log.get_recent(10) == []


def test_get_recent_is_session_scoped(tmp_path):
    log = _logger(tmp_path)
    log.log(session_id="a2a:s1", hits=_hits(), min_trust=1)
    log.log(session_id="a2a:s2", hits=_hits(), min_trust=1)
    assert len(log.get_recent(10, session_id="a2a:s1")) == 1
    assert len(log.get_recent(10)) == 2


def test_preview_is_capped(tmp_path):
    log = _logger(tmp_path)
    big = [{"id": "facts:f1", "table": "facts", "trust_tier": 2, "preview": "x" * 5000}]
    log.log(session_id="s", hits=big, min_trust=1)
    assert len(log.get_recent(1)[0]["hits"][0]["preview"]) == 200


# ── console reader ────────────────────────────────────────────────────────────


def test_recent_injections_summary(tmp_path):
    log = _logger(tmp_path)
    log.log(session_id="s", hits=_hits(), min_trust=1)
    payload = recent_injections(log, n=10)
    assert payload["count"] == 1
    assert payload["summary"]["by_tier"] == {"1": 1, "2": 0, "3": 1}  # one external, one operator
    assert payload["events"][0]["hits"]


def test_recent_injections_missing_logger_is_empty():
    payload = recent_injections(None)
    assert payload == {"count": 0, "events": [], "summary": {"total": 0, "by_tier": {"1": 0, "2": 0, "3": 0}}}


# ── middleware wiring ─────────────────────────────────────────────────────────


class _FakeStore:
    def __init__(self, hits):
        self._hits = hits

    def hybrid_search(self, query, k=10):
        return list(self._hits)


def test_middleware_logs_injected_memory(monkeypatch):
    import observability.injection_log as il
    from langchain_core.messages import HumanMessage
    from graph.middleware.knowledge import KnowledgeMiddleware

    captured = {}

    class _Cap:
        def log(self, *, session_id, hits, min_trust):
            captured["session_id"] = session_id
            captured["hits"] = hits
            captured["min_trust"] = min_trust

    monkeypatch.setattr(il, "injection_logger", _Cap())

    store = _FakeStore([{"table": "cves", "source_id": "c1", "preview": "curated cve detail"}])
    mw = KnowledgeMiddleware(store, inject_min_trust=1)
    state = {"session_id": "a2a:sX", "messages": [HumanMessage(content="what cves are relevant")]}
    mw.before_model(state, None)

    assert captured.get("session_id") == "a2a:sX"
    assert captured.get("min_trust") == 1
    assert captured["hits"] and captured["hits"][0]["trust_tier"] == 3  # ranked hit passed through
