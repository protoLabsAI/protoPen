"""Knowledge-store search for the operator console.

Wraps the hybrid-search KnowledgeStore (sqlite-vec + FTS5, fused via RRF) into a
UI-safe contract: a ranked list of hits with table, source id, preview, and a
0..1 relevance score derived from result rank (the store returns RRF-ordered
results without an absolute score, so we synthesize a monotonic one for display).
"""

from __future__ import annotations

from typing import Any

# Tables the store indexes — surfaced as the UI filter options.
KNOWLEDGE_TABLES = ("cves", "exploits", "advisories", "threat_intel", "topics", "digests")


def search_knowledge(
    store: Any,
    *,
    query: str,
    k: int = 10,
    table: str | None = None,
) -> dict[str, Any]:
    """Run a hybrid search and return a UI-safe payload.

    Tolerant of a missing store (returns an empty result set rather than raising)
    so the console degrades gracefully when the knowledge subsystem is disabled.
    """
    cleaned = (query or "").strip()
    if not cleaned:
        raise ValueError("query is required")

    k = max(1, min(int(k or 10), 50))
    filter_table = table if table in KNOWLEDGE_TABLES else None

    if store is None:
        return {"query": cleaned, "table": filter_table, "count": 0, "hits": []}

    raw = store.hybrid_search(cleaned, k=k, filter_table=filter_table) or []

    total = len(raw)
    hits: list[dict[str, Any]] = []
    for rank, item in enumerate(raw):
        # Rank-based score in (0, 1]; top hit ~1.0, tapering down the list.
        score = round((total - rank) / total, 4) if total else 0.0
        hits.append(
            {
                "table": str(item.get("table", "")),
                "source_id": str(item.get("source_id", "")),
                "preview": str(item.get("preview", "")),
                "score": score,
            }
        )

    return {"query": cleaned, "table": filter_table, "count": len(hits), "hits": hits}
