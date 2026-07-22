"""Trust tiers for recalled knowledge (ADR 0069 phase 2 / D8, protopen-h34.13).

Auto-injected memory is a prompt-injection / poisoning surface (OWASP ASI06). The
<injected_memory> envelope (#286) is the containment *minimum* — it tells the model the
recalled text is untrusted reference. This adds a second layer: rank what gets injected
by how much we trust its origin, and let the operator refuse to auto-inject anything
below a floor.

Three tiers, by provenance:
  1 EXTERNAL  — third-party / attacker-controllable: scraped threat intel, OSINT feeds.
  2 AGENT     — model-extracted / agent-generated: semantic facts, digests.
  3 OPERATOR  — curated authoritative security data: CVEs, advisories, exploit records.

``tier_for`` works with ZERO store change: it defaults by source *table* (which every
search hit already carries) and refines by ``source_type`` when a hit has one (phase 3
surfaces that per row). Ranking is deterministic — no LLM freshness judging.
"""

from __future__ import annotations

TIER_EXTERNAL = 1
TIER_AGENT = 2
TIER_OPERATOR = 3

# Per-table default tier (every search hit carries its source ``table``).
_TABLE_TIER = {
    "cves": TIER_OPERATOR,
    "advisories": TIER_OPERATOR,
    "exploits": TIER_OPERATOR,
    "facts": TIER_AGENT,
    "digests": TIER_AGENT,
    "threat_intel": TIER_EXTERNAL,
    "sources": TIER_EXTERNAL,
}

# Source-type refinements (phase 3 surfaces source_type per row; until then this
# only fires when a hit happens to carry one). Attacker-controllable ingest paths
# resolve to EXTERNAL regardless of which table they landed in.
_SOURCE_TYPE_TIER = {
    "osint": TIER_EXTERNAL,
    "vulnerability_scan": TIER_EXTERNAL,
    "defensive_scan": TIER_EXTERNAL,
    "background_job": TIER_AGENT,
    "extracted": TIER_AGENT,
}

_DEFAULT_TIER = TIER_AGENT  # unknown provenance → treat as agent-grade, not curated


def tier_for(table: str | None, source_type: str | None = None) -> int:
    """Trust tier for a recalled hit. A known ``source_type`` wins over the table default."""
    if source_type and source_type in _SOURCE_TYPE_TIER:
        return _SOURCE_TYPE_TIER[source_type]
    return _TABLE_TIER.get(table or "", _DEFAULT_TIER)


def rank_by_trust(hits: list[dict], min_trust: int = 1) -> list[dict]:
    """Annotate each hit with ``trust_tier``, drop anything below ``min_trust``, and
    stable-sort most-trusted first — so curated data precedes agent-extracted precedes
    external, while the original relevance order is preserved within a tier.

    ``min_trust=1`` (default) keeps every tier and only re-ranks; ``min_trust=2``
    refuses to auto-inject EXTERNAL (attacker-controllable) memory entirely.
    """
    annotated: list[dict] = []
    for h in hits:
        tier = tier_for(h.get("table"), h.get("source_type"))
        if tier < min_trust:
            continue
        annotated.append({**h, "trust_tier": tier})
    # Python's sort is stable, so equal-tier hits keep their incoming relevance order.
    annotated.sort(key=lambda h: h["trust_tier"], reverse=True)
    return annotated
