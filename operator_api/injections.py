"""Injected-memory log access for the operator console (ADR 0069 D7).

Wraps the append-only InjectionLogger trail into a UI-safe, newest-first payload with a
window summary (how many injections, tier distribution) so the console can surface what
memory the agent has been recalling — the inspector half of the poisoning forensics.
"""

from __future__ import annotations

from typing import Any


def recent_injections(logger: Any, *, n: int = 50, session_id: str | None = None) -> dict[str, Any]:
    """Return the most recent injection events (newest first) plus a tier summary.

    Tolerant of a missing logger (returns an empty payload rather than raising), so the
    console degrades gracefully when the injection log is unavailable.
    """
    n = max(1, min(int(n or 50), 200))
    empty = {"count": 0, "events": [], "summary": {"total": 0, "by_tier": {"1": 0, "2": 0, "3": 0}}}
    if logger is None:
        return empty

    raw = logger.get_recent(n, session_id) or []
    events: list[dict[str, Any]] = []
    by_tier = {1: 0, 2: 0, 3: 0}
    for item in reversed(raw):  # get_recent is oldest-first; show newest first.
        hits = item.get("hits") or []
        for h in hits:
            tier = h.get("trust_tier")
            if tier in by_tier:
                by_tier[tier] += 1
        events.append(
            {
                "ts": str(item.get("ts", "")),
                "session_id": str(item.get("session_id", "")),
                "min_trust": item.get("min_trust"),
                "count": item.get("count", len(hits)),
                "hits": hits,
                "trace_id": item.get("trace_id"),
            }
        )

    return {
        "count": len(events),
        "events": events,
        "summary": {"total": len(events), "by_tier": {str(k): v for k, v in by_tier.items()}},
    }
