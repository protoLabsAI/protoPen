"""Semantic fact extraction for the post-turn memory pass (ADR 0021).

Adapted from protoAgent's ADR 0021 onto protoPen's domain-typed KnowledgeStore.
Where protoAgent dumped every raw assistant turn into the store, this distils
discrete, durable *facts* worth recalling in a future, unrelated conversation —
operator preferences, decisions made, stable facts about their world/projects —
and stores them via ``KnowledgeStore.add_fact`` (a ``facts`` row + vector/FTS
index entry).

Two rules from the ADR:

- **Extract, don't dump.** The aux model returns short fact strings, not a
  transcript. Importance gating lives in the prompt — transient task state and
  pleasantries are dropped; a turn with nothing durable yields ``[]``.
- **Consolidate.** Before inserting, near-identical facts already in the store
  (scoped to the same ``namespace``) are skipped, so memory doesn't accrete
  duplicates. (LLM-judged supersession of *outdated* facts is a follow-up; v1
  dedups conservatively.)

Extraction is **synchronous** here on purpose: it runs on ``MemoryMiddleware``'s
daemon thread (off the response hot path), where there is no event loop, so a
sync ``llm.invoke`` is the right fit. Facts carry a ``namespace`` so
per-engagement/owner scoping is a filter later, not a migration.
"""

from __future__ import annotations

import json
import logging
import re

log = logging.getLogger(__name__)

_MAX_FACTS = 12
_MAX_FACT_CHARS = 300
# >= this token-overlap (Jaccard) with an existing fact => treat as a duplicate
# and skip. Intentionally conservative for v1 (only near-identical facts are
# deduped); LLM-judged supersession of outdated facts is the ADR 0021 follow-up.
_DEDUP_JACCARD = 0.85

_FACTS_PROMPT = (
    "Extract durable, reusable FACTS from this conversation — things worth "
    "recalling in a future, unrelated conversation: the operator's stable "
    "preferences, decisions made, and facts about their world, projects, or "
    "setup. Do NOT include pleasantries, transient task state, or one-off "
    "details. Each fact is one short, self-contained sentence.\n\n"
    "Output ONLY a JSON array of strings. If nothing durable was shared, output "
    "[].\n\nConversation:\n{transcript}\n\nFacts (JSON array):"
)


def _parse_facts(raw: str) -> list[str]:
    """Pull a JSON array of fact strings out of a model response, defensively.

    The aux model may wrap the array in prose or a ```json fence; we grab the
    first bracketed array and parse it. Non-string / empty items are dropped,
    each fact is length-capped, and the list is capped at ``_MAX_FACTS``.
    """
    if not raw or not raw.strip():
        return []
    m = re.search(r"\[[\s\S]*\]", raw)
    if not m:
        return []
    try:
        items = json.loads(m.group(0))
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(items, list):
        return []
    facts: list[str] = []
    for it in items:
        if isinstance(it, str) and it.strip():
            facts.append(it.strip()[:_MAX_FACT_CHARS])
        if len(facts) >= _MAX_FACTS:
            break
    return facts


def _default_extractor(transcript: str, config) -> list[str]:
    """Aux-model fact extraction (sync — runs on the memory daemon thread)."""
    from langchain_core.messages import HumanMessage

    from graph.agent import _resolve_aux_model
    from graph.llm import create_llm

    llm = create_llm(config, model_name=_resolve_aux_model(config, ""))
    resp = llm.invoke([HumanMessage(content=_FACTS_PROMPT.format(transcript=transcript))])
    return _parse_facts(str(resp.content))


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[\w']+", text.lower()) if t}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def consolidate_and_store(store, facts: list[str], *, namespace: str | None = None) -> dict:
    """Store ``facts`` via ``store.add_fact``, skipping near-duplicates of facts
    already present in the same ``namespace``. Returns counts.

    Best-effort: a store that lacks ``list_facts`` (e.g. a minimal test stub)
    degrades to add-only. Never raises.
    """
    counts = {"added": 0, "skipped": 0}
    if not facts:
        return counts
    try:
        existing = store.list_facts(namespace=namespace, limit=500)
        existing_tokens = [_tokens(c["content"]) for c in existing]
    except Exception:  # noqa: BLE001 — minimal stub or read failure => add-only
        existing_tokens = []

    for fact in facts:
        ft = _tokens(fact)
        if any(_jaccard(ft, et) >= _DEDUP_JACCARD for et in existing_tokens):
            counts["skipped"] += 1
            continue
        rid = store.add_fact(fact, namespace=namespace)
        if rid is not None:
            counts["added"] += 1
            existing_tokens.append(ft)  # dedup within this batch too
    return counts


def extract_and_store_facts(
    transcript: str,
    *,
    store,
    config,
    namespace: str | None = None,
    extractor=_default_extractor,
) -> dict:
    """Extract durable facts from ``transcript`` and consolidate them into the
    store. Never raises — fact capture is best-effort and must not affect the
    conversation."""
    if store is None or not transcript.strip():
        return {"added": 0, "skipped": 0}
    try:
        facts = extractor(transcript, config)
    except Exception:  # noqa: BLE001
        log.exception("[memory] fact extraction failed")
        return {"added": 0, "skipped": 0}
    counts = consolidate_and_store(store, facts, namespace=namespace)
    if counts["added"] or counts["skipped"]:
        log.info(
            "[memory] facts: +%d new, %d dup-skipped (ns=%s)",
            counts["added"],
            counts["skipped"],
            namespace or "-",
        )
    return counts
