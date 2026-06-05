"""Knowledge store for protoPen — SQLite + sqlite-vec backed.

Stores CVEs, exploits, advisories, threat intel with semantic search
via embedding server (OpenAI-compatible) and sqlite-vec.
"""

import json
import os
import sqlite3
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

_EMBED_URL = os.environ.get("EMBED_URL", os.environ.get("API_BASE", "http://ava:4000"))
_EMBED_MODEL = os.environ.get("EMBED_MODEL", "qwen3-embedding")
_EMBED_API_KEY = os.environ.get("OPENAI_API_KEY", "")
_EMBED_TIMEOUT = 20
_EMBED_DIM = 1024
_DB_PATH = Path("/sandbox/knowledge/security.db")
_SCHEMA_PATH = Path(__file__).parent / "schema.sql"
_CONTENT_PREVIEW_LEN = 1000  # chars stored for search result display
_RRF_K = 60  # RRF fusion constant
_CONTEXT_PROMPT = (
    "Given a document and a chunk from it, write 1-2 sentences of context "
    "to situate the chunk within the document for search retrieval. "
    "Answer only with the context, nothing else.\n\n"
    "Document:\n{document}\n\nChunk:\n{chunk}"
)


class KnowledgeStore:
    """Security knowledge store with semantic vector search."""

    def __init__(
        self,
        db_path: Path = _DB_PATH,
        embed_url: str = _EMBED_URL,
        model: str = _EMBED_MODEL,
        enrich_chunks: bool = False,
        enrich_fn: Any = None,
    ):
        self.db_path = db_path
        self.embed_url = embed_url
        self.model = model
        self.enrich_chunks = enrich_chunks
        self._enrich_fn = enrich_fn  # fn(doc_context: str, chunk: str) -> str
        self._db: Optional[sqlite3.Connection] = None

    def _get_db(self) -> Optional[sqlite3.Connection]:
        if self._db is not None:
            return self._db
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            import sqlite_vec

            db = sqlite3.connect(str(self.db_path), check_same_thread=False)
            db.enable_load_extension(True)
            sqlite_vec.load(db)
            db.enable_load_extension(False)

            # Apply schema
            schema_sql = _SCHEMA_PATH.read_text()
            db.executescript(schema_sql)

            # Create vector tables
            db.execute(f"""
                CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_vec
                USING vec0(embedding float[{_EMBED_DIM}])
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS knowledge_vec_map (
                    rowid INTEGER PRIMARY KEY,
                    source_table TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    content_preview TEXT
                )
            """)
            db.commit()
            self._db = db
            return db
        except Exception as e:
            print(f"[knowledge] DB init failed: {e}")
            return None

    def _embed(self, text: str) -> Optional[list[float]]:
        try:
            api_key = _EMBED_API_KEY or os.environ.get("OPENAI_API_KEY", "")
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            resp = httpx.post(
                f"{self.embed_url}/v1/embeddings",
                headers=headers,
                json={"model": self.model, "input": text[:2000]},
                timeout=_EMBED_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()["data"][0]["embedding"]
        except Exception as e:
            print(f"[knowledge] Embedding failed: {e}")
            return None

    def _contextualize(self, doc_context: str, chunk: str) -> str:
        """Prepend contextual prefix to chunk for better embeddings."""
        if self._enrich_fn:
            try:
                prefix = self._enrich_fn(doc_context, chunk)
                if prefix:
                    return f"{prefix.strip()} {chunk}"
            except Exception:
                pass
        if doc_context and len(doc_context) > len(chunk):
            header = doc_context[:100].split("\n")[0].strip()
            if header:
                return f"[{header}] {chunk}"
        return chunk

    def _store_vector(
        self,
        db: sqlite3.Connection,
        text: str,
        table: str,
        source_id: str,
        doc_context: str = "",
    ) -> bool:
        embed_text = text
        if self.enrich_chunks and doc_context:
            embed_text = self._contextualize(doc_context, text)
        embedding = self._embed(embed_text)
        if embedding is None:
            return False
        vec_bytes = struct.pack(f"{len(embedding)}f", *embedding)
        cursor = db.execute("INSERT INTO knowledge_vec (embedding) VALUES (?)", (vec_bytes,))
        db.execute(
            "INSERT INTO knowledge_vec_map (rowid, source_table, source_id, content_preview) VALUES (?, ?, ?, ?)",
            (cursor.lastrowid, table, str(source_id), text[:_CONTENT_PREVIEW_LEN]),
        )
        db.execute(
            "INSERT INTO knowledge_fts (content, source_table, source_id) VALUES (?, ?, ?)",
            (text[:_CONTENT_PREVIEW_LEN], table, str(source_id)),
        )
        return True

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # --- Facts (semantic memory, ADR 0021) ---

    def add_fact(
        self,
        content: str,
        namespace: Optional[str] = None,
        source: str = "harvest",
        source_type: str = "extracted",
    ) -> Optional[str]:
        """Store a durable semantic fact; return its id, or None on failure.

        The ``facts`` row is the durable record. Vector + FTS indexing is
        best-effort: when embeddings are unavailable, the fact is still inserted
        into the FTS index directly so it stays keyword-recoverable (never
        silently lost).
        """
        content = (content or "").strip()
        if not content:
            return None
        db = self._get_db()
        if db is None:
            return None
        import uuid

        fact_id = uuid.uuid4().hex
        try:
            db.execute(
                "INSERT INTO facts (id, content, namespace, source, source_type, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (fact_id, content, namespace, source, source_type, self._now_iso()),
            )
            if not self._store_vector(db, content, "facts", fact_id):
                # Embeddings down — keep the fact at least keyword-searchable.
                db.execute(
                    "INSERT INTO knowledge_fts (content, source_table, source_id) VALUES (?, ?, ?)",
                    (content[:_CONTENT_PREVIEW_LEN], "facts", fact_id),
                )
            db.commit()
            return fact_id
        except Exception as e:
            print(f"[knowledge] add_fact failed: {e}")
            return None

    def list_facts(self, namespace: Optional[str] = None, limit: int = 500) -> list[dict[str, Any]]:
        """Return stored facts (newest first), optionally namespace-scoped, for
        consolidation/dedup. ``namespace=None`` returns the global bucket."""
        db = self._get_db()
        if db is None:
            return []
        try:
            # ``IS`` is null-safe: namespace=None matches the NULL (global) rows.
            rows = db.execute(
                "SELECT id, content, namespace, created_at FROM facts "
                "WHERE namespace IS ? ORDER BY created_at DESC LIMIT ?",
                (namespace, limit),
            ).fetchall()
            return [{"id": r[0], "content": r[1], "namespace": r[2], "created_at": r[3]} for r in rows]
        except Exception:
            return []

    # --- CVEs ---

    def add_cve(
        self,
        cve_id: str,
        title: str = "",
        description: str = "",
        severity: str = "",
        cvss_score: float = 0.0,
        cvss_vector: str = "",
        affected_products: Optional[list[str]] = None,
        references: Optional[list[str]] = None,
        exploit_available: bool = False,
        exploit_maturity: str = "none",
        tags: Optional[list[str]] = None,
        published_at: str = "",
        notes: str = "",
    ) -> bool:
        db = self._get_db()
        if db is None:
            return False

        now = self._now_iso()
        db.execute(
            """INSERT OR REPLACE INTO cves
               (id, title, description, severity, cvss_score, cvss_vector,
                affected_products, "references", exploit_available, exploit_maturity,
                tags, published_at, discovered_at, analyzed_at, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cve_id,
                title,
                description,
                severity,
                cvss_score,
                cvss_vector,
                json.dumps(affected_products or []),
                json.dumps(references or []),
                int(exploit_available),
                exploit_maturity,
                json.dumps(tags or []),
                published_at,
                now,
                "",
                notes,
            ),
        )
        embed_text = f"{cve_id} {title}\n{description}".strip()
        doc_context = f"CVE: {cve_id} ({severity}). {title}"
        self._store_vector(db, embed_text, "cves", cve_id, doc_context=doc_context)
        db.commit()
        return True

    def get_cve(self, cve_id: str) -> Optional[dict]:
        db = self._get_db()
        if db is None:
            return None
        row = db.execute("SELECT * FROM cves WHERE id = ?", (cve_id,)).fetchone()
        if not row:
            return None
        cols = [d[0] for d in db.execute("SELECT * FROM cves LIMIT 0").description]
        return dict(zip(cols, row))

    def get_cves(
        self,
        severity: Optional[str] = None,
        since: Optional[str] = None,
        exploit_available: Optional[bool] = None,
        limit: int = 20,
    ) -> list[dict]:
        db = self._get_db()
        if db is None:
            return []
        query = "SELECT * FROM cves WHERE 1=1"
        params: list[Any] = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if since:
            query += " AND discovered_at >= ?"
            params.append(since)
        if exploit_available is not None:
            query += " AND exploit_available = ?"
            params.append(int(exploit_available))
        query += " ORDER BY discovered_at DESC LIMIT ?"
        params.append(limit)
        rows = db.execute(query, params).fetchall()
        cols = [d[0] for d in db.execute("SELECT * FROM cves LIMIT 0").description]
        return [dict(zip(cols, row)) for row in rows]

    # --- Exploits ---

    def add_exploit(
        self,
        title: str,
        cve_id: str = "",
        description: str = "",
        source: str = "",
        source_url: str = "",
        platform: str = "",
        exploit_type: str = "",
        verified: bool = False,
        code_path: str = "",
        notes: str = "",
    ) -> bool:
        db = self._get_db()
        if db is None:
            return False
        now = self._now_iso()
        cursor = db.execute(
            """INSERT INTO exploits
               (cve_id, title, description, source, source_url, platform,
                exploit_type, verified, code_path, discovered_at, tested_at, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cve_id or None,
                title,
                description,
                source,
                source_url,
                platform,
                exploit_type,
                int(verified),
                code_path,
                now,
                "",
                notes,
            ),
        )
        embed_text = f"{title}\n{description}".strip()
        doc_context = f"Exploit: {title}. CVE: {cve_id or 'N/A'}. Platform: {platform}"
        self._store_vector(db, embed_text, "exploits", str(cursor.lastrowid), doc_context=doc_context)
        db.commit()
        return True

    # --- Advisories ---

    def add_advisory(
        self,
        source: str,
        title: str,
        content: str = "",
        severity: str = "",
        affected_products: Optional[list[str]] = None,
        cve_ids: Optional[list[str]] = None,
        url: str = "",
        published_at: str = "",
        notes: str = "",
    ) -> bool:
        db = self._get_db()
        if db is None:
            return False
        now = self._now_iso()
        cursor = db.execute(
            """INSERT INTO advisories
               (source, title, content, severity, affected_products, cve_ids,
                url, published_at, discovered_at, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                source,
                title,
                content,
                severity,
                json.dumps(affected_products or []),
                json.dumps(cve_ids or []),
                url,
                published_at,
                now,
                notes,
            ),
        )
        embed_text = f"{title}\n{content[:500]}".strip()
        doc_context = f"Advisory from {source}: {title} ({severity})"
        self._store_vector(db, embed_text, "advisories", str(cursor.lastrowid), doc_context=doc_context)
        db.commit()
        return True

    # --- Threat Intel ---

    def add_threat_intel(
        self,
        content: str,
        source: str = "",
        source_type: str = "",
        topic: str = "",
        intel_type: str = "indicator",
        severity: str = "",
        target_relevance: str = "",
    ) -> bool:
        db = self._get_db()
        if db is None:
            return False
        now = self._now_iso()
        cursor = db.execute(
            """INSERT INTO threat_intel
               (content, source, source_type, topic, intel_type, severity,
                target_relevance, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (content, source, source_type, topic, intel_type, severity, target_relevance, now),
        )
        doc_context = f"Threat intel ({intel_type}) on topic: {topic or 'general'}. Source: {source or 'unknown'}"
        self._store_vector(db, content, "threat_intel", str(cursor.lastrowid), doc_context=doc_context)
        db.commit()
        return True

    # --- Topics ---

    def add_topic(
        self,
        name: str,
        description: str = "",
        keywords: Optional[list[str]] = None,
        priority: int = 2,
    ) -> bool:
        db = self._get_db()
        if db is None:
            return False
        now = self._now_iso()
        db.execute(
            """INSERT OR REPLACE INTO topics (name, description, keywords, priority, active, created_at)
               VALUES (?, ?, ?, ?, 1, ?)""",
            (name, description, json.dumps(keywords or []), priority, now),
        )
        db.commit()
        return True

    def get_topics(self, active_only: bool = True) -> list[dict]:
        db = self._get_db()
        if db is None:
            return []
        query = "SELECT * FROM topics"
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY priority, name"
        rows = db.execute(query).fetchall()
        cols = [d[0] for d in db.execute("SELECT * FROM topics LIMIT 0").description]
        return [dict(zip(cols, row)) for row in rows]

    # --- Digests ---

    def add_digest(
        self,
        title: str,
        content: str,
        digest_type: str = "weekly",
        topic: str = "",
        cves_referenced: Optional[list[str]] = None,
    ) -> bool:
        db = self._get_db()
        if db is None:
            return False
        now = self._now_iso()
        cursor = db.execute(
            """INSERT INTO digests (title, content, digest_type, topic, cves_referenced, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (title, content, digest_type, topic, json.dumps(cves_referenced or []), now),
        )
        doc_context = f"Security digest ({digest_type}) on topic: {topic or 'general'}"
        self._store_vector(db, f"{title}\n{content[:500]}", "digests", str(cursor.lastrowid), doc_context=doc_context)
        db.commit()
        return True

    def get_digests(self, topic: Optional[str] = None, limit: int = 10) -> list[dict]:
        db = self._get_db()
        if db is None:
            return []
        query = "SELECT * FROM digests"
        params: list[Any] = []
        if topic:
            query += " WHERE topic = ?"
            params.append(topic)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = db.execute(query, params).fetchall()
        cols = [d[0] for d in db.execute("SELECT * FROM digests LIMIT 0").description]
        return [dict(zip(cols, row)) for row in rows]

    # --- Semantic Search ---

    def search(
        self,
        query: str,
        k: int = 10,
        filter_table: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        db = self._get_db()
        if db is None:
            return []
        embedding = self._embed(query)
        if embedding is None:
            print("[knowledge] Embedding unavailable, falling back to keyword search")
            return self.keyword_search(query, k=k, filter_table=filter_table)
        vec_bytes = struct.pack(f"{len(embedding)}f", *embedding)
        rows = db.execute(
            """SELECT m.source_table, m.source_id, m.content_preview, v.distance
               FROM knowledge_vec v
               JOIN knowledge_vec_map m ON m.rowid = v.rowid
               WHERE v.embedding MATCH ? AND k = ?
               ORDER BY v.distance""",
            (vec_bytes, k),
        ).fetchall()

        results = []
        for table, source_id, preview, distance in rows:
            if filter_table and table != filter_table:
                continue
            results.append(
                {
                    "table": table,
                    "source_id": source_id,
                    "preview": preview,
                    "distance": distance,
                }
            )
        return results

    # --- Keyword Search (BM25 via FTS5) ---

    def keyword_search(
        self,
        query: str,
        k: int = 10,
        filter_table: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """BM25 keyword search via FTS5."""
        db = self._get_db()
        if db is None:
            return []
        try:
            rows = db.execute(
                """SELECT source_table, source_id, content, rank
                   FROM knowledge_fts
                   WHERE knowledge_fts MATCH ?
                   ORDER BY rank
                   LIMIT ?""",
                (query, k * 2),
            ).fetchall()
        except Exception:
            return []

        results = []
        for table, source_id, content, rank in rows:
            if filter_table and table != filter_table:
                continue
            results.append(
                {
                    "table": table,
                    "source_id": source_id,
                    "preview": content,
                    "distance": 0.0,
                    "bm25_rank": rank,
                }
            )
            if len(results) >= k:
                break
        return results

    # --- Hybrid Search (RRF fusion of vector + keyword) ---

    def hybrid_search(
        self,
        query: str,
        k: int = 10,
        filter_table: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Hybrid search: reciprocal rank fusion of vector + BM25 results."""
        vec_results = self.search(query, k=k * 2, filter_table=filter_table)
        kw_results = self.keyword_search(query, k=k * 2, filter_table=filter_table)

        scores: dict[str, float] = {}
        result_map: dict[str, dict] = {}

        for rank, r in enumerate(vec_results):
            key = f"{r['table']}:{r['source_id']}"
            scores[key] = scores.get(key, 0) + 1.0 / (_RRF_K + rank + 1)
            result_map[key] = r

        for rank, r in enumerate(kw_results):
            key = f"{r['table']}:{r['source_id']}"
            scores[key] = scores.get(key, 0) + 1.0 / (_RRF_K + rank + 1)
            if key not in result_map:
                result_map[key] = r

        ranked = sorted(scores.items(), key=lambda x: -x[1])
        return [result_map[key] for key, _ in ranked[:k]]

    # --- Migration ---

    def backfill_fts(self) -> int:
        """Backfill FTS5 index from existing knowledge_vec_map data."""
        db = self._get_db()
        if db is None:
            return 0
        db.execute("DELETE FROM knowledge_fts")
        cursor = db.execute("SELECT source_table, source_id, content_preview FROM knowledge_vec_map")
        count = 0
        for table, source_id, preview in cursor:
            if preview:
                db.execute(
                    "INSERT INTO knowledge_fts (content, source_table, source_id) VALUES (?, ?, ?)",
                    (preview, table, str(source_id)),
                )
                count += 1
        db.commit()
        print(f"[knowledge] Backfilled FTS5 index: {count} entries")
        return count

    # --- Stats ---

    def get_stats(self) -> dict[str, int]:
        db = self._get_db()
        if db is None:
            return {}
        stats = {}
        for table in ("cves", "exploits", "advisories", "threat_intel", "topics", "digests", "facts"):
            count = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            stats[table] = count
        return stats
