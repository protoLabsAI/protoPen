"""KB provenance migration + supersede-don't-delete (ADR 0069 phases 3-4, h34.14/h34.15).

Covers the idempotent additive migration (source_type/created_at on knowledge_vec_map,
invalidated_at on facts), the stable id + provenance on search hits, and supersede_fact
(drop from recall, keep the row as history). Uses a real KnowledgeStore with an
unreachable embed endpoint (FTS-fallback path), so it runs host-free.
"""

from __future__ import annotations

import sqlite3

from knowledge.store import KnowledgeStore


def _real_store(tmp_path):
    return KnowledgeStore(db_path=tmp_path / "k.db", embed_url="http://127.0.0.1:1")


# ── migration ─────────────────────────────────────────────────────────────────


def test_provenance_migration_is_idempotent(tmp_path):
    # An OLD-schema DB: vec_map without provenance cols, facts without invalidated_at.
    p = tmp_path / "old.db"
    db = sqlite3.connect(p)
    db.execute(
        "CREATE TABLE knowledge_vec_map "
        "(rowid INTEGER PRIMARY KEY, source_table TEXT, source_id TEXT, content_preview TEXT)"
    )
    db.execute(
        "CREATE TABLE facts (id TEXT PRIMARY KEY, content TEXT, namespace TEXT, source TEXT, "
        "source_type TEXT, created_at TEXT)"
    )
    db.commit()

    # Run twice — must be idempotent (no duplicate-column error).
    KnowledgeStore._migrate_provenance(db)
    KnowledgeStore._migrate_provenance(db)

    vec_cols = {r[1] for r in db.execute("PRAGMA table_info(knowledge_vec_map)").fetchall()}
    fact_cols = {r[1] for r in db.execute("PRAGMA table_info(facts)").fetchall()}
    assert {"source_type", "created_at"} <= vec_cols
    assert "invalidated_at" in fact_cols
    db.close()


def test_new_store_has_provenance_columns(tmp_path):
    store = _real_store(tmp_path)
    db = store._get_db()  # init runs the migration
    vec_cols = {r[1] for r in db.execute("PRAGMA table_info(knowledge_vec_map)").fetchall()}
    fact_cols = {r[1] for r in db.execute("PRAGMA table_info(facts)").fetchall()}
    assert {"source_type", "created_at"} <= vec_cols
    assert "invalidated_at" in fact_cols


# ── search hits carry id + provenance ─────────────────────────────────────────


def test_keyword_search_returns_stable_id_and_provenance(tmp_path):
    store = _real_store(tmp_path)
    fid = store.add_fact("The lab subnet is 10.10.0.0/24.")
    assert fid
    # Simulate an embeddings-up vec_map row so the keyword LEFT JOIN surfaces provenance.
    db = store._get_db()
    db.execute(
        "INSERT INTO knowledge_vec_map (source_table, source_id, content_preview, source_type, created_at) "
        "VALUES ('facts', ?, ?, 'osint', '2026-07-21T00:00:00')",
        (fid, "The lab subnet is 10.10.0.0/24."),
    )
    db.commit()

    hit = next(h for h in store.keyword_search("subnet", k=5) if h["source_id"] == fid)
    assert hit["id"] == f"facts:{fid}"
    assert hit["source_type"] == "osint"
    assert hit["created_at"] == "2026-07-21T00:00:00"


def test_keyword_hit_without_vecmap_row_degrades_to_null_provenance(tmp_path):
    # FTS-only fact (embeddings were down at write) → no vec_map row → NULL provenance,
    # which tiers by table default. Still gets a stable id.
    store = _real_store(tmp_path)
    fid = store.add_fact("Operator runs everything headless.")
    hit = next(h for h in store.keyword_search("headless", k=5) if h["source_id"] == fid)
    assert hit["id"] == f"facts:{fid}"
    assert hit["source_type"] is None


# ── supersede-don't-delete ────────────────────────────────────────────────────


def test_supersede_fact_drops_from_recall_keeps_history(tmp_path):
    store = _real_store(tmp_path)
    fid = store.add_fact("Operator uses the callsign Vortex.")
    assert fid
    assert any(f["id"] == fid for f in store.list_facts())
    assert store.keyword_search("Vortex", k=5)  # recalled

    assert store.supersede_fact(fid) is True

    assert not any(f["id"] == fid for f in store.list_facts())  # gone from the default list
    assert not store.keyword_search("Vortex", k=5)  # gone from recall
    # The row survives as history (invalidated), visible only when explicitly requested.
    assert any(f["id"] == fid for f in store.list_facts(include_invalidated=True))


def test_supersede_is_idempotent(tmp_path):
    store = _real_store(tmp_path)
    fid = store.add_fact("A fact to retire.")
    assert store.supersede_fact(fid) is True
    assert store.supersede_fact(fid) is False  # already superseded
    assert store.supersede_fact("nonexistent") is False


def test_facts_row_retained_with_invalidated_at(tmp_path):
    store = _real_store(tmp_path)
    fid = store.add_fact("Keep my history.")
    store.supersede_fact(fid)
    db = store._get_db()
    row = db.execute("SELECT id, invalidated_at FROM facts WHERE id = ?", (fid,)).fetchone()
    assert row is not None and row[0] == fid  # row kept
    assert row[1] is not None  # invalidated_at stamped
