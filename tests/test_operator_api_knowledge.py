from __future__ import annotations

import pytest

from operator_api.knowledge import search_knowledge


class _Store:
    def __init__(self, results):
        self._results = results
        self.calls = []

    def hybrid_search(self, query, k=10, filter_table=None):
        self.calls.append((query, k, filter_table))
        return self._results


def test_search_knowledge_shapes_hits_and_synthesizes_scores() -> None:
    store = _Store(
        [
            {"table": "cves", "source_id": "CVE-2026-1", "preview": "rce in foo", "distance": 0.1},
            {"table": "exploits", "source_id": "EDB-42", "preview": "poc", "distance": 0.4},
        ]
    )
    result = search_knowledge(store, query="  rce  ", k=5, table="cves")

    assert store.calls == [("rce", 5, "cves")]
    assert result["query"] == "rce"
    assert result["table"] == "cves"
    assert result["count"] == 2
    # Rank-based scores: top hit highest, monotonically decreasing.
    assert result["hits"][0]["score"] > result["hits"][1]["score"]
    assert result["hits"][0]["source_id"] == "CVE-2026-1"


def test_search_knowledge_rejects_blank_query() -> None:
    with pytest.raises(ValueError):
        search_knowledge(_Store([]), query="   ")


def test_search_knowledge_ignores_unknown_table_filter() -> None:
    store = _Store([])
    search_knowledge(store, query="x", table="not_a_table")
    assert store.calls == [("x", 10, None)]


def test_search_knowledge_clamps_k() -> None:
    store = _Store([])
    search_knowledge(store, query="x", k=999)
    assert store.calls[0][1] == 50


def test_search_knowledge_tolerates_missing_store() -> None:
    result = search_knowledge(None, query="x")
    assert result == {"query": "x", "table": None, "count": 0, "hits": []}
