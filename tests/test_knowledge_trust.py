"""KB trust tiers — rank/gate auto-injected memory by provenance (ADR 0069 D8, h34.13).

tier_for defaults by source table (zero store change) and refines by source_type;
rank_by_trust drops sub-floor hits and stable-sorts curated-first. The middleware wiring
is checked with a fake store so it stays host-free.
"""

from __future__ import annotations

from knowledge.trust import TIER_AGENT, TIER_EXTERNAL, TIER_OPERATOR, rank_by_trust, tier_for


# ── tier_for ──────────────────────────────────────────────────────────────────


def test_tier_for_table_defaults():
    assert tier_for("cves") == TIER_OPERATOR
    assert tier_for("advisories") == TIER_OPERATOR
    assert tier_for("facts") == TIER_AGENT
    assert tier_for("threat_intel") == TIER_EXTERNAL
    assert tier_for("sources") == TIER_EXTERNAL


def test_tier_for_unknown_table_is_agent_grade():
    assert tier_for("something_new") == TIER_AGENT
    assert tier_for(None) == TIER_AGENT


def test_source_type_refines_over_table():
    # An OSINT-sourced row is EXTERNAL even if it landed in an otherwise-trusted table.
    assert tier_for("facts", source_type="osint") == TIER_EXTERNAL
    assert tier_for("cves", source_type="vulnerability_scan") == TIER_EXTERNAL
    assert tier_for("facts", source_type="extracted") == TIER_AGENT


# ── rank_by_trust ─────────────────────────────────────────────────────────────


def _hits():
    return [
        {"table": "threat_intel", "source_id": "ti1", "preview": "scraped"},
        {"table": "facts", "source_id": "f1", "preview": "extracted"},
        {"table": "cves", "source_id": "c1", "preview": "curated"},
    ]


def test_rank_sorts_curated_first_keeps_all_at_min1():
    ranked = rank_by_trust(_hits(), min_trust=1)
    assert [h["source_id"] for h in ranked] == ["c1", "f1", "ti1"]  # operator → agent → external
    assert [h["trust_tier"] for h in ranked] == [TIER_OPERATOR, TIER_AGENT, TIER_EXTERNAL]


def test_min_trust_2_drops_external():
    ranked = rank_by_trust(_hits(), min_trust=2)
    assert [h["source_id"] for h in ranked] == ["c1", "f1"]  # threat_intel excluded
    assert all(h["trust_tier"] >= 2 for h in ranked)


def test_stable_within_a_tier():
    hits = [
        {"table": "facts", "source_id": "a"},
        {"table": "facts", "source_id": "b"},
        {"table": "facts", "source_id": "c"},
    ]
    # All same tier → original relevance order preserved.
    assert [h["source_id"] for h in rank_by_trust(hits)] == ["a", "b", "c"]


def test_rank_does_not_mutate_input():
    hits = _hits()
    rank_by_trust(hits, min_trust=2)
    assert len(hits) == 3 and "trust_tier" not in hits[0]  # inputs untouched


# ── middleware wiring ─────────────────────────────────────────────────────────


class _FakeStore:
    def __init__(self, hits):
        self._hits = hits

    def hybrid_search(self, query, k=10):
        return list(self._hits)


def _run_before_model(store, min_trust):
    from langchain_core.messages import HumanMessage
    from graph.middleware.knowledge import KnowledgeMiddleware

    mw = KnowledgeMiddleware(store, inject_min_trust=min_trust)
    state = {"messages": [HumanMessage(content="what do we know about the target")]}
    return mw.before_model(state, None)


def test_middleware_min_trust_2_excludes_external_from_injection():
    store = _FakeStore(
        [
            {"table": "threat_intel", "source_id": "ti1", "preview": "ATTACKER CONTROLLED intel"},
            {"table": "cves", "source_id": "c1", "preview": "curated cve detail"},
        ]
    )
    out = _run_before_model(store, min_trust=2)
    ctx = out["context"]
    assert "curated cve detail" in ctx
    assert "ATTACKER CONTROLLED" not in ctx  # tier-1 external memory refused


def test_middleware_min_trust_1_injects_all_but_curated_first():
    store = _FakeStore(
        [
            {"table": "threat_intel", "source_id": "ti1", "preview": "external note"},
            {"table": "cves", "source_id": "c1", "preview": "curated note"},
        ]
    )
    ctx = _run_before_model(store, min_trust=1)["context"]
    assert "external note" in ctx and "curated note" in ctx
    assert ctx.index("curated note") < ctx.index("external note")  # curated ranked first


def test_curated_is_framed_before_facts():
    # Guards the CodeRabbit finding: the old facts/other split emitted facts (tier-2)
    # before curated (tier-3), undoing the trust order. Now framing follows tier.
    store = _FakeStore(
        [
            {"table": "facts", "source_id": "f1", "preview": "an extracted fact"},
            {"table": "cves", "source_id": "c1", "preview": "a curated cve"},
        ]
    )
    ctx = _run_before_model(store, min_trust=1)["context"]
    assert ctx.index("a curated cve") < ctx.index("an extracted fact")
    assert ctx.index("Curated reference") < ctx.index("Recalled memory")


def test_osint_sourced_fact_is_framed_external_not_extracted():
    # An OSINT-sourced facts row is tier-1 EXTERNAL — it must be framed untrusted,
    # not labeled "model-extracted" (the other half of the CodeRabbit finding).
    store = _FakeStore(
        [{"table": "facts", "source_id": "f1", "preview": "scraped osint claim", "source_type": "osint"}]
    )
    ctx = _run_before_model(store, min_trust=1)["context"]
    assert "scraped osint claim" in ctx
    assert "UNTRUSTED" in ctx  # external framing applied
    assert "model-extracted" not in ctx  # not mislabeled as agent memory


def test_osint_sourced_fact_dropped_at_min_trust_2():
    store = _FakeStore(
        [
            {"table": "facts", "source_id": "f1", "preview": "scraped osint claim", "source_type": "osint"},
            {"table": "cves", "source_id": "c1", "preview": "curated cve"},
        ]
    )
    ctx = _run_before_model(store, min_trust=2)["context"]
    assert "scraped osint claim" not in ctx  # tier-1 osint fact refused even from the facts table
    assert "curated cve" in ctx
