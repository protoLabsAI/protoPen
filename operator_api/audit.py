"""Audit-trail access for the operator console.

Wraps the append-only AuditLogger JSONL trail into a UI-safe, newest-first
payload with a window summary. Tool/status filtering is left to the console
(presentational over the loaded window) so this stays a thin reader and avoids
filter-after-limit surprises.
"""

from __future__ import annotations

from typing import Any


def recent_audit(
    logger: Any,
    *,
    n: int = 50,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Return the most recent audit entries (newest first) plus a summary.

    Tolerant of a missing logger (returns an empty payload rather than raising)
    so the console degrades gracefully when auditing is unavailable.
    """
    n = max(1, min(int(n or 50), 200))
    if logger is None:
        return {"count": 0, "entries": [], "summary": {"total": 0, "successes": 0, "failures": 0}}

    raw = logger.get_recent(n, session_id) or []

    entries: list[dict[str, Any]] = []
    successes = 0
    for item in reversed(raw):  # get_recent is oldest-first; show newest first.
        success = bool(item.get("success", False))
        if success:
            successes += 1
        entries.append(
            {
                "ts": str(item.get("ts", "")),
                "session_id": str(item.get("session_id", "")),
                "tool": str(item.get("tool", "")),
                "success": success,
                "duration_ms": int(item.get("duration_ms", 0) or 0),
                "result_summary": str(item.get("result_summary", "")),
                "trace_id": str(item.get("trace_id", "")),
                "args": item.get("args", {}) or {},
            }
        )

    total = len(entries)
    return {
        "count": total,
        "entries": entries,
        "summary": {"total": total, "successes": successes, "failures": total - successes},
    }
