"""KnowledgeMiddleware injection — facts vs. research knowledge framing (ADR 0021)."""

from __future__ import annotations

import pytest

try:
    import langchain_core  # noqa: F401

    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False

needs_langchain = pytest.mark.skipif(not HAS_LANGCHAIN, reason="langchain not installed")


class _FakeStore:
    def __init__(self, results):
        self._results = results

    def hybrid_search(self, query, k=10):
        return self._results

    def search(self, query, k=10):
        return self._results


def _state(text):
    from langchain_core.messages import HumanMessage

    return {"messages": [HumanMessage(content=text)]}


@needs_langchain
def test_facts_injected_as_authoritative_block_separate_from_knowledge():
    from graph.middleware.knowledge import KnowledgeMiddleware

    store = _FakeStore(
        [
            {"table": "facts", "source_id": "f1", "preview": "User prefers reports in Markdown."},
            {"table": "cves", "source_id": "CVE-2024-1", "preview": "Some CVE about RomPager."},
        ]
    )
    mw = KnowledgeMiddleware(store, top_k=10, search_mode="hybrid")
    out = mw.before_model(_state("what format do I like for reports?"), None)
    ctx = out["context"]

    # Facts get their own authoritative, operator-framed block...
    assert "Known facts about the operator" in ctx
    assert "User prefers reports in Markdown." in ctx
    # ...and are NOT lumped under the research-knowledge heading with a table tag.
    assert "[facts:f1]" not in ctx
    # Research knowledge still renders under its own heading with the table tag.
    assert "Relevant knowledge from previous research" in ctx
    assert "[cves:CVE-2024-1]" in ctx
    # Facts block precedes the research block (recall first).
    assert ctx.index("Known facts about the operator") < ctx.index("previous research")


@needs_langchain
def test_only_knowledge_no_facts_block():
    from graph.middleware.knowledge import KnowledgeMiddleware

    store = _FakeStore([{"table": "cves", "source_id": "CVE-1", "preview": "x"}])
    out = KnowledgeMiddleware(store).before_model(_state("ssh cves?"), None)
    assert "Known facts about the operator" not in out["context"]
    assert "[cves:CVE-1]" in out["context"]


@needs_langchain
def test_only_facts_no_research_block():
    from graph.middleware.knowledge import KnowledgeMiddleware

    store = _FakeStore([{"table": "facts", "source_id": "f1", "preview": "Operator runs headless."}])
    out = KnowledgeMiddleware(store).before_model(_state("how do I run it?"), None)
    assert "Known facts about the operator" in out["context"]
    assert "Relevant knowledge from previous research" not in out["context"]


@needs_langchain
def test_no_hits_no_context():
    from graph.middleware.knowledge import KnowledgeMiddleware

    out = KnowledgeMiddleware(_FakeStore([])).before_model(_state("anything"), None)
    assert out is None
