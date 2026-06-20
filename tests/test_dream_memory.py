"""dream memory consolidation + forget_memory (ADR 0054, protopen-1hw.7).

Covers KnowledgeStore.delete_fact (prune one fact across facts/FTS/vector), the
scoped curation tools (memory_list / forget_memory / recent_activity), and the
dream subagent's safe, shell/SQL-free tool allowlist.
"""

from __future__ import annotations

import asyncio

from knowledge.store import KnowledgeStore


def _store(tmp_path):
    return KnowledgeStore(db_path=tmp_path / "k.db", embed_url="http://127.0.0.1:1")


# ── store.delete_fact ────────────────────────────────────────────────────────


def test_delete_fact_removes_from_facts_and_fts(tmp_path):
    store = _store(tmp_path)
    fid = store.add_fact("The DMZ host 10.0.0.9 runs an outdated Apache.")
    assert fid
    assert store.delete_fact(fid) is True
    assert store.list_facts() == []
    # gone from the keyword index too (no stale recall)
    assert not any(h["table"] == "facts" for h in store.keyword_search("Apache", k=5))


def test_delete_fact_unknown_id_is_false(tmp_path):
    store = _store(tmp_path)
    store.add_fact("keep me")
    assert store.delete_fact("does-not-exist") is False
    assert store.delete_fact("") is False
    assert len(store.list_facts()) == 1  # the real one survives


# ── curation tools ───────────────────────────────────────────────────────────


def test_memory_list_and_forget_memory_tools(tmp_path):
    from tools.lg_tools import create_memory_curation_tools

    store = _store(tmp_path)
    fid = store.add_fact("duplicate fact about the gateway")
    memory_list, forget_memory = create_memory_curation_tools(store)

    listed = asyncio.run(memory_list.coroutine())
    assert f"#{fid}" in listed and "gateway" in listed

    # forget accepts the id with or without a leading '#'
    out = asyncio.run(forget_memory.coroutine(fact_id=f"#{fid}", reason="duplicate"))
    assert "Forgot fact" in out and "duplicate" in out
    assert store.list_facts() == []

    assert "No fact deleted" in asyncio.run(forget_memory.coroutine(fact_id="nope"))
    assert asyncio.run(forget_memory.coroutine(fact_id="")).startswith("Error:")


def test_recent_activity_tool_is_robust():
    """recent_activity returns a string and never raises — even where the audit
    subsystem's log dir isn't writable (dev/CI without /sandbox)."""
    from tools.lg_tools import recent_activity

    out = asyncio.run(recent_activity.coroutine(limit=10))
    assert isinstance(out, str) and out  # digest, "No recent activity[ available]."


# ── dream subagent ───────────────────────────────────────────────────────────


def test_dream_subagent_registered_and_scoped():
    from graph.subagents.config import SUBAGENT_REGISTRY
    from tools.lg_tools import get_combined_tools

    assert "dream" in SUBAGENT_REGISTRY
    cfg = SUBAGENT_REGISTRY["dream"]
    names = {t.name for t in get_combined_tools()}
    assert set(cfg.tools) <= names  # every allowlisted tool resolves
    # No shell/SQL/code-exec tool in the consolidation pass.
    assert not (set(cfg.tools) & {"execute_code", "shell", "browser", "device_manager"})
    assert "task" in cfg.disallowed_tools  # can't recurse
