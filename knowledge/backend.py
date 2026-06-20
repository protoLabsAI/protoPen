"""KnowledgeBackend — the retrieval + semantic-memory contract (ADR 0031 seam).

The thin interface a knowledge backend honors so the store is swappable — a future
pgvector / Qdrant / managed-vector backend could drop in without touching the agent,
middleware, tools, or memory-consolidation code that consume it.

This is the *seam only*, not a plugin system: ``KnowledgeStore`` (knowledge/store.py)
is the default and currently only implementation, wired directly. There is no
registry or config selector yet — adding one (register_knowledge_backend +
``knowledge.backend: "<name>"``) is the natural next step if an alternative backend
is ever built.

The Protocol captures exactly the cross-cutting surface consumers call today
(KnowledgeMiddleware retrieval, the semantic-facts path, the dream curation tools,
the operator API). protoPen's security-domain methods (``add_cve`` / ``add_exploit``
/ ``add_advisory`` / topics / digests) are NOT part of the swappable contract — they
live on the concrete store as the domain layer above it.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class KnowledgeBackend(Protocol):
    """Retrieval + durable-fact + introspection surface every backend implements."""

    # ── retrieval ────────────────────────────────────────────────────────────
    def search(self, query: str, k: int = 10, filter_table: Optional[str] = None) -> list[dict[str, Any]]:
        """Vector (semantic) search, with a keyword fallback when embeddings are down."""
        ...

    def keyword_search(self, query: str, k: int = 10, filter_table: Optional[str] = None) -> list[dict[str, Any]]:
        """BM25 keyword search."""
        ...

    def hybrid_search(self, query: str, k: int = 10, filter_table: Optional[str] = None) -> list[dict[str, Any]]:
        """Reciprocal-rank fusion of vector + keyword results."""
        ...

    # ── durable semantic facts (ADR 0021 / dream consolidation, ADR 0054) ──────
    def add_fact(
        self,
        content: str,
        namespace: Optional[str] = None,
        source: str = "harvest",
        source_type: str = "extracted",
    ) -> Optional[str]:
        """Store a durable fact; return its id (or None on failure)."""
        ...

    def list_facts(self, namespace: Optional[str] = None, limit: int = 500) -> list[dict[str, Any]]:
        """List stored facts (newest first), optionally namespace-scoped."""
        ...

    def delete_fact(self, fact_id: str) -> bool:
        """Delete one fact by id. Returns True if a row was removed."""
        ...

    # ── introspection ─────────────────────────────────────────────────────────
    def get_stats(self) -> dict[str, int]:
        """Row counts per store, for status surfaces."""
        ...
