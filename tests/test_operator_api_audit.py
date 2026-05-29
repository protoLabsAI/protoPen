from __future__ import annotations

from operator_api.audit import recent_audit


class _Logger:
    def __init__(self, entries):
        # Stored oldest-first, mirroring AuditLogger.get_recent's contract.
        self._entries = entries
        self.calls = []

    def get_recent(self, n=20, session_id=None):
        self.calls.append((n, session_id))
        items = self._entries
        if session_id:
            items = [e for e in items if e.get("session_id") == session_id]
        return items[-n:]


def _entry(tool, success, **extra):
    return {
        "tool": tool,
        "success": success,
        "session_id": "s1",
        "duration_ms": 5,
        "ts": "2026-05-29T00:00:00Z",
        **extra,
    }


def test_recent_audit_returns_newest_first_with_summary() -> None:
    logger = _Logger([_entry("nmap", True), _entry("nikto", False), _entry("hydra", True)])
    result = recent_audit(logger, n=50)

    assert logger.calls == [(50, None)]
    assert [e["tool"] for e in result["entries"]] == ["hydra", "nikto", "nmap"]  # newest first
    assert result["count"] == 3
    assert result["summary"] == {"total": 3, "successes": 2, "failures": 1}


def test_recent_audit_normalizes_entry_fields() -> None:
    logger = _Logger([{"tool": "nmap", "success": True}])  # missing optional fields
    entry = recent_audit(logger, n=10)["entries"][0]
    assert entry["session_id"] == ""
    assert entry["duration_ms"] == 0
    assert entry["trace_id"] == ""
    assert entry["args"] == {}


def test_recent_audit_clamps_n() -> None:
    logger = _Logger([])
    recent_audit(logger, n=9999)
    assert logger.calls[0][0] == 200


def test_recent_audit_passes_session_filter() -> None:
    logger = _Logger([_entry("nmap", True, session_id="a"), _entry("nikto", True, session_id="b")])
    result = recent_audit(logger, n=50, session_id="b")
    assert logger.calls == [(50, "b")]
    assert [e["tool"] for e in result["entries"]] == ["nikto"]


def test_recent_audit_tolerates_missing_logger() -> None:
    result = recent_audit(None)
    assert result == {"count": 0, "entries": [], "summary": {"total": 0, "successes": 0, "failures": 0}}
