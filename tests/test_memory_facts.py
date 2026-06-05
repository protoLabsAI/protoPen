"""Semantic fact extraction + storage (ADR 0021).

Covers the pure logic (parse / dedup / consolidate), the round-trip through a
real KnowledgeStore (add_fact -> list_facts -> keyword_search, including the
embeddings-down FTS fallback), and the MemoryMiddleware trigger.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from graph.memory_facts import (
    _jaccard,
    _parse_facts,
    _tokens,
    consolidate_and_store,
    extract_and_store_facts,
)


# ── parse: defensive JSON-array extraction ──────────────────────────────────────


@pytest.mark.parametrize(
    "raw, expected",
    [
        ('["a", "b"]', ["a", "b"]),
        ('```json\n["a", "b"]\n```', ["a", "b"]),
        ('Here are the facts: ["x"] hope that helps', ["x"]),
        ("[]", []),
        ("no array here", []),
        ("", []),
        ('{"not": "a list"}', []),
        ('[1, "ok", 2, "  ", "two"]', ["ok", "two"]),  # non-strings / blanks dropped
    ],
)
def test_parse_facts(raw, expected):
    assert _parse_facts(raw) == expected


def test_parse_facts_caps_count_and_length():
    raw = "[" + ", ".join(f'"f{i}"' for i in range(50)) + "]"
    assert len(_parse_facts(raw)) == 12  # _MAX_FACTS
    long_fact = "x" * 1000
    out = _parse_facts(f'["{long_fact}"]')
    assert len(out[0]) == 300  # _MAX_FACT_CHARS


def test_jaccard():
    assert _jaccard(_tokens("the cat sat"), _tokens("the cat sat")) == 1.0
    assert _jaccard(_tokens("the cat"), _tokens("a dog")) == 0.0
    assert 0 < _jaccard(_tokens("the cat sat"), _tokens("the cat ran")) < 1


# ── consolidate: dedup against a fake store ─────────────────────────────────────


class _FakeStore:
    """Minimal store double recording add_fact calls."""

    def __init__(self, existing=None):
        self._existing = [{"content": c} for c in (existing or [])]
        self.added: list[str] = []

    def list_facts(self, namespace=None, limit=500):
        return list(self._existing)

    def add_fact(self, content, namespace=None, **kw):
        self.added.append(content)
        return f"id-{len(self.added)}"


def test_consolidate_skips_near_duplicates():
    store = _FakeStore(existing=["The operator prefers Neovim with Catppuccin."])
    facts = [
        "The operator prefers Neovim with the Catppuccin theme.",  # near-dup -> skip
        "The operator runs protoPen headless on a Steam Deck.",  # new -> add
    ]
    counts = consolidate_and_store(store, facts)
    assert counts == {"added": 1, "skipped": 1}
    assert store.added == ["The operator runs protoPen headless on a Steam Deck."]


def test_consolidate_dedups_within_batch():
    store = _FakeStore()
    facts = ["The sky is blue today.", "The sky is blue today."]
    counts = consolidate_and_store(store, facts)
    assert counts == {"added": 1, "skipped": 1}


def test_consolidate_add_only_when_no_list_facts():
    """A stub store without list_facts degrades to add-only, never raises."""

    class _AddOnly:
        def __init__(self):
            self.added = []

        def add_fact(self, content, namespace=None, **kw):
            self.added.append(content)
            return "x"

    store = _AddOnly()
    counts = consolidate_and_store(store, ["one", "two"])
    assert counts == {"added": 2, "skipped": 0}


def test_consolidate_empty_is_noop():
    store = _FakeStore()
    assert consolidate_and_store(store, []) == {"added": 0, "skipped": 0}


# ── extract_and_store: orchestration, never raises ──────────────────────────────


def test_extract_and_store_with_stub_extractor():
    store = _FakeStore()
    counts = extract_and_store_facts(
        "User: I use Neovim.\nAssistant: Noted.",
        store=store,
        config=None,
        extractor=lambda transcript, config: ["The operator uses Neovim."],
    )
    assert counts["added"] == 1
    assert store.added == ["The operator uses Neovim."]


def test_extract_swallows_extractor_failure():
    store = _FakeStore()

    def _boom(transcript, config):
        raise RuntimeError("model down")

    counts = extract_and_store_facts("x y z", store=store, config=None, extractor=_boom)
    assert counts == {"added": 0, "skipped": 0}
    assert store.added == []


def test_extract_noop_on_empty_transcript_or_store():
    assert extract_and_store_facts("   ", store=_FakeStore(), config=None) == {"added": 0, "skipped": 0}
    assert extract_and_store_facts("x", store=None, config=None) == {"added": 0, "skipped": 0}


# ── round-trip through a real KnowledgeStore (sqlite-vec + FTS) ──────────────────


def _real_store(tmp_path):
    """A real KnowledgeStore with an unreachable embed endpoint, so writes take
    the embeddings-down FTS fallback (fast, no network)."""
    from knowledge.store import KnowledgeStore

    return KnowledgeStore(
        db_path=tmp_path / "k.db",
        embed_url="http://127.0.0.1:1",  # refused instantly -> _embed returns None
    )


def test_add_fact_roundtrip_and_keyword_search(tmp_path):
    store = _real_store(tmp_path)
    fid = store.add_fact("The operator prefers Neovim with the Catppuccin theme.")
    assert fid

    facts = store.list_facts()
    assert len(facts) == 1
    assert "Neovim" in facts[0]["content"]
    assert facts[0]["id"] == fid

    # FTS fallback kept it keyword-searchable despite embeddings being down.
    hits = store.keyword_search("Catppuccin", k=5)
    assert any(h["table"] == "facts" and "Catppuccin" in h["preview"] for h in hits)

    assert store.get_stats().get("facts") == 1


def test_add_fact_rejects_blank(tmp_path):
    store = _real_store(tmp_path)
    assert store.add_fact("   ") is None
    assert store.list_facts() == []


def test_consolidate_against_real_store_dedups(tmp_path):
    store = _real_store(tmp_path)
    store.add_fact("The operator runs protoPen headless on a Steam Deck.")
    counts = consolidate_and_store(
        store,
        [
            "The operator runs protoPen headless on a Steam Deck.",  # exact dup
            "The operator's HackRF is a PortaPack H4M.",  # new
        ],
    )
    assert counts == {"added": 1, "skipped": 1}
    assert len(store.list_facts()) == 2


def test_namespace_scoping(tmp_path):
    store = _real_store(tmp_path)
    store.add_fact("global fact")
    store.add_fact("engagement fact", namespace="eng-1")
    assert len(store.list_facts()) == 1  # None bucket = global only
    assert len(store.list_facts(namespace="eng-1")) == 1


# ── MemoryMiddleware trigger ────────────────────────────────────────────────────

try:
    import langchain_core  # noqa: F401

    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False

needs_langchain = pytest.mark.skipif(not HAS_LANGCHAIN, reason="langchain not installed")


@needs_langchain
def test_middleware_spawns_extraction(monkeypatch):
    import graph.memory_facts as mf
    from langchain_core.messages import AIMessage, HumanMessage

    from graph.middleware.memory import MemoryMiddleware

    seen = {}
    done = threading.Event()

    def _fake(transcript, *, store, config, namespace=None, **kw):
        seen["transcript"] = transcript
        done.set()
        return {"added": 1, "skipped": 0}

    monkeypatch.setattr(mf, "extract_and_store_facts", _fake)

    mw = MemoryMiddleware(object(), SimpleNamespace(knowledge_facts=True, aux_model=""))
    state = {
        "messages": [
            HumanMessage(content="I run protoPen headless on a Steam Deck."),
            AIMessage(content="Got it — noted that you run headless on the Deck."),
        ]
    }
    mw.after_agent(state, None)
    assert done.wait(timeout=5)
    assert "Steam Deck" in seen["transcript"]
    assert seen["transcript"].startswith("User:")


@needs_langchain
def test_middleware_skips_when_disabled_or_trivial(monkeypatch):
    import graph.memory_facts as mf
    from langchain_core.messages import AIMessage, HumanMessage

    from graph.middleware.memory import MemoryMiddleware

    called = threading.Event()
    monkeypatch.setattr(mf, "extract_and_store_facts", lambda *a, **k: called.set() or {"added": 0, "skipped": 0})

    msgs = [HumanMessage(content="hi"), AIMessage(content="hello")]

    # disabled by config
    off = MemoryMiddleware(object(), SimpleNamespace(knowledge_facts=False, aux_model=""))
    off.after_agent({"messages": msgs}, None)
    # trivial transcript (below the min length) is skipped even when enabled
    on = MemoryMiddleware(object(), SimpleNamespace(knowledge_facts=True, aux_model=""))
    on.after_agent({"messages": msgs}, None)

    assert not called.wait(timeout=1)
