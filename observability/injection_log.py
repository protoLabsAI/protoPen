"""Injected-memory forensic log (ADR 0069 phase 5 / D6, protopen-h34.16).

Containment (the `<injected_memory>` envelope + trust tiers, phases 2-4) decides what
recalled memory reaches the model and how it's framed. This is the *forensic* counterpart:
a durable record of exactly what memory was auto-injected into each turn — the recalled
hits, their provenance tier, and the trust floor in effect — so a suspected memory-poisoning
incident can be reconstructed after the fact ("what did the agent recall the turn it went
sideways, and from where?").

Append-only JSONL, same shape and path convention as ``audit.py`` (``/sandbox/knowledge/``
with a ``~/.protopen`` fallback). Writes are best-effort and never break a turn.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PREVIEW_CAP = 200


class InjectionLogger:
    """Append-only JSONL log of auto-injected recalled memory."""

    def __init__(self, path: str | Path = "/sandbox/knowledge/injections.jsonl"):
        self.path = Path(path)
        # Configured path, then ~/.protopen (like AuditLogger). Both unwritable →
        # keep the path but don't raise: a missing workspace must never crash a turn.
        for candidate in (self.path, Path.home() / ".protopen" / "knowledge" / "injections.jsonl"):
            try:
                candidate.parent.mkdir(parents=True, exist_ok=True)
                self.path = candidate
                return
            except OSError:
                continue

    def log(self, *, session_id: str, hits: list[dict[str, Any]], min_trust: int) -> None:
        """Record one turn's injected memory. ``hits`` are the trust-ranked recall
        results actually injected (each carrying id/table/source_type/trust_tier)."""
        if not hits:
            return
        trace_id = None
        try:
            import tracing

            trace_id = tracing._trace_id_ctx.get("") or None
        except Exception:  # noqa: BLE001
            pass

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id or "",
            "min_trust": int(min_trust),
            "count": len(hits),
            "hits": [
                {
                    "id": h.get("id") or f"{h.get('table')}:{h.get('source_id')}",
                    "table": h.get("table"),
                    "source_type": h.get("source_type"),
                    "trust_tier": h.get("trust_tier"),
                    "preview": (str(h.get("preview") or ""))[:_PREVIEW_CAP],
                }
                for h in hits
            ],
        }
        if trace_id:
            entry["trace_id"] = trace_id

        try:
            with self.path.open("a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            pass

    def get_recent(self, n: int = 20, session_id: str | None = None) -> list[dict[str, Any]]:
        """Most recent injection events, oldest-first within the returned window."""
        if not self.path.exists():
            return []
        try:
            lines = self.path.read_text().strip().splitlines()
        except OSError:
            return []

        entries: list[dict[str, Any]] = []
        for line in reversed(lines):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if session_id and entry.get("session_id") != session_id:
                continue
            entries.append(entry)
            if len(entries) >= n:
                break
        entries.reverse()
        return entries


injection_logger = InjectionLogger()
