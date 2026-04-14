"""Rabbit Hole Bridge — ships research findings to rabbit-hole.io's knowledge graph.

Converts protoPen data (papers, model releases, free text) into
rabbit-hole bundles and ingests them via direct HTTP calls to the
rabbit-hole API at RABBIT_HOLE_URL (default: http://host.docker.internal:3399).

No MCP needed — just REST.
"""

import json
import os
import re
from typing import Any

import httpx

from tools._tool_base import Tool

_BASE_URL = os.environ.get("RABBIT_HOLE_URL", "http://host.docker.internal:3399")
_TIMEOUT = 30


def _slugify(text: str) -> str:
    """Convert text to snake_case slug for UIDs."""
    s = text.lower().strip()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s-]+", "_", s)
    return s[:80].rstrip("_")


def _today() -> str:
    from datetime import date
    return date.today().isoformat()


# ─── Bundle Builders ─────────────────────────────────────────────────


def paper_to_bundle(paper: dict) -> dict:
    """Convert a KnowledgeStore paper record to a rabbit-hole bundle."""
    arxiv_id = paper.get("id", "")
    title = paper.get("title", "Unknown Paper")
    authors_raw = paper.get("authors", "[]")
    abstract = paper.get("abstract", "")
    summary = paper.get("summary", "")
    significance = paper.get("significance", "unknown")
    source_url = paper.get("source_url", f"https://arxiv.org/abs/{arxiv_id}")
    published_at = paper.get("published_at", "")
    tags_raw = paper.get("tags", "[]")
    categories_raw = paper.get("categories", "[]")

    # Parse JSON lists stored as strings
    authors = json.loads(authors_raw) if isinstance(authors_raw, str) else (authors_raw or [])
    tags = json.loads(tags_raw) if isinstance(tags_raw, str) else (tags_raw or [])
    categories = json.loads(categories_raw) if isinstance(categories_raw, str) else (categories_raw or [])

    slug = _slugify(arxiv_id) if arxiv_id else _slugify(title)
    pub_uid = f"publication:{slug}"

    entities = [
        {
            "uid": pub_uid,
            "type": "publication",
            "name": title,
            "aliases": [arxiv_id] if arxiv_id else [],
            "tags": tags + categories + ([significance] if significance != "unknown" else []),
            "properties": {
                "abstract": abstract[:2000],
                "summary": summary[:2000],
                "significance": significance,
                "arxiv_id": arxiv_id,
                "source_url": source_url,
                "published_at": published_at,
                "sources": [f"auto-extract:protopen:{arxiv_id}"],
            },
        }
    ]

    relationships = []

    # Create author entities + relationships
    for author_name in authors[:20]:  # cap at 20 authors
        author_slug = _slugify(author_name)
        if not author_slug:
            continue
        author_uid = f"person:{author_slug}"
        entities.append({
            "uid": author_uid,
            "type": "person",
            "name": author_name,
            "aliases": [],
            "tags": ["researcher", "author"],
            "properties": {
                "sources": [f"auto-extract:protopen:{arxiv_id}"],
            },
        })
        relationships.append({
            "uid": f"rel:{author_slug}_authored_{slug}",
            "type": "AUTHORED",
            "source": author_uid,
            "target": pub_uid,
            "properties": {},
        })

    evidence = [
        {
            "uid": f"evidence:arxiv_{slug}",
            "kind": "research",
            "title": title,
            "publisher": "arXiv",
            "date": published_at[:10] if published_at else _today(),
            "url": source_url,
            "reliability": 0.9,
            "notes": f"Significance: {significance}",
        }
    ]

    return {"entities": entities, "relationships": relationships, "evidence": evidence}


def model_to_bundle(model: dict) -> dict:
    """Convert a KnowledgeStore model_release record to a rabbit-hole bundle."""
    model_id = model.get("model_id", "")
    name = model.get("name", "") or model_id
    org = model.get("organization", "")
    description = model.get("description", "")
    parameters = model.get("parameters", "")
    architecture = model.get("architecture", "")
    license_ = model.get("license", "")
    source = model.get("source", "huggingface")
    released_at = model.get("released_at", "")
    downloads = model.get("downloads", 0)
    likes = model.get("likes", 0)

    slug = _slugify(model_id) if model_id else _slugify(name)
    model_uid = f"software:{slug}"

    source_url = (
        f"https://huggingface.co/{model_id}" if source == "huggingface"
        else f"https://github.com/{model_id}" if source == "github"
        else model_id
    )

    entities = [
        {
            "uid": model_uid,
            "type": "software",
            "name": name,
            "aliases": [model_id] if model_id != name else [],
            "tags": ["model", "ai", source] + ([architecture] if architecture else []),
            "properties": {
                "description": description[:2000],
                "parameters": parameters,
                "architecture": architecture,
                "license": license_,
                "downloads": downloads,
                "likes": likes,
                "source_platform": source,
                "source_url": source_url,
                "released_at": released_at,
                "sources": [f"auto-extract:protopen:{model_id}"],
            },
        }
    ]

    relationships = []

    if org:
        org_slug = _slugify(org)
        org_uid = f"organization:{org_slug}"
        entities.append({
            "uid": org_uid,
            "type": "organization",
            "name": org,
            "aliases": [],
            "tags": ["ai", "ml"],
            "properties": {
                "sources": [f"auto-extract:protopen:{model_id}"],
            },
        })
        relationships.append({
            "uid": f"rel:{org_slug}_developed_{slug}",
            "type": "DEVELOPED",
            "source": org_uid,
            "target": model_uid,
            "properties": {},
        })

    evidence = [
        {
            "uid": f"evidence:{source}_{slug}",
            "kind": "platform_log",
            "title": name,
            "publisher": "HuggingFace" if source == "huggingface" else "GitHub",
            "date": released_at[:10] if released_at else _today(),
            "url": source_url,
            "reliability": 0.85,
            "notes": f"Downloads: {downloads}, Likes: {likes}",
        }
    ]

    return {"entities": entities, "relationships": relationships, "evidence": evidence}


def merge_bundles(bundles: list[dict]) -> dict:
    """Merge multiple bundles into one, deduplicating by UID."""
    seen_entities = set()
    seen_rels = set()
    seen_evidence = set()
    merged = {"entities": [], "relationships": [], "evidence": []}

    for b in bundles:
        for e in b.get("entities", []):
            if e["uid"] not in seen_entities:
                seen_entities.add(e["uid"])
                merged["entities"].append(e)
        for r in b.get("relationships", []):
            if r["uid"] not in seen_rels:
                seen_rels.add(r["uid"])
                merged["relationships"].append(r)
        for ev in b.get("evidence", []):
            if ev["uid"] not in seen_evidence:
                seen_evidence.add(ev["uid"])
                merged["evidence"].append(ev)

    return merged


# ─── HTTP Calls ──────────────────────────────────────────────────────


async def _post_bundle(bundle: dict) -> dict:
    """POST a bundle to rabbit-hole's ingest endpoint."""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            f"{_BASE_URL}/api/ingest-bundle",
            json={
                "data": bundle,
                "mergeOptions": {
                    "strategy": "merge_smart",
                    "preserveTimestamps": True,
                },
            },
        )
        resp.raise_for_status()
        return resp.json()


async def _search_graph(query: str, limit: int = 10) -> dict:
    """Search rabbit-hole's entity index."""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            f"{_BASE_URL}/api/entity-search",
            json={"searchQuery": query, "limit": limit},
        )
        resp.raise_for_status()
        return resp.json()


# ─── Knowledge Store Access ──────────────────────────────────────────


def _get_store():
    """Get the shared KnowledgeStore instance."""
    from knowledge.store import KnowledgeStore
    return KnowledgeStore()


def _get_paper(arxiv_id: str) -> dict | None:
    return _get_store().get_paper(arxiv_id)


def _get_model(model_id: str) -> dict | None:
    store = _get_store()
    db = store._get_db()
    if db is None:
        return None
    row = db.execute("SELECT * FROM model_releases WHERE model_id = ?", (model_id,)).fetchone()
    if not row:
        return None
    cols = [d[0] for d in db.execute("SELECT * FROM model_releases LIMIT 0").description]
    return dict(zip(cols, row))


# ─── Nanobot Tool ────────────────────────────────────────────────────


class RabbitHoleBridgeTool(Tool):
    """Ship research findings to rabbit-hole.io's knowledge graph."""

    @property
    def name(self) -> str:
        return "rabbit_hole_bridge"

    @property
    def description(self) -> str:
        return (
            "Send research data to rabbit-hole.io's knowledge graph. "
            "Actions: search_graph (check existing), ingest_paper (by arXiv ID), "
            "ingest_model (by model ID), ingest_text (free text extraction), "
            "ingest_batch (multiple papers/models at once)."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["search_graph", "ingest_paper", "ingest_model", "ingest_text", "ingest_batch"],
                    "description": "Action to perform",
                },
                "query": {
                    "type": "string",
                    "description": "Search query (for search_graph)",
                },
                "arxiv_id": {
                    "type": "string",
                    "description": "arXiv paper ID (for ingest_paper)",
                },
                "model_id": {
                    "type": "string",
                    "description": "Model ID e.g. 'Qwen/Qwen3.5-0.8B' (for ingest_model)",
                },
                "text": {
                    "type": "string",
                    "description": "Free text to extract entities from (for ingest_text)",
                },
                "focus_entity": {
                    "type": "string",
                    "description": "Primary entity to focus extraction around (for ingest_text)",
                },
                "paper_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of arXiv IDs (for ingest_batch)",
                },
                "model_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of model IDs (for ingest_batch)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results for search_graph (default: 10)",
                },
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")

        try:
            if action == "search_graph":
                query = kwargs.get("query", "")
                if not query:
                    return "Error: query is required for search_graph"
                limit = kwargs.get("limit", 10)
                result = await _search_graph(query, limit)
                results = result.get("data", {}).get("results", [])
                if not results:
                    return f"No entities found for '{query}' in rabbit-hole graph."
                lines = [f"Found {len(results)} entities for '{query}':"]
                for r in results[:limit]:
                    entity = r.get("entity", r)
                    lines.append(f"  - {entity.get('name', '?')} ({entity.get('type', '?')}) [uid: {entity.get('uid', '?')}]")
                return "\n".join(lines)

            elif action == "ingest_paper":
                arxiv_id = kwargs.get("arxiv_id", "")
                if not arxiv_id:
                    return "Error: arxiv_id is required for ingest_paper"
                paper = _get_paper(arxiv_id)
                if not paper:
                    return f"Paper '{arxiv_id}' not found in local knowledge store. Store it first with security_memory."
                bundle = paper_to_bundle(paper)
                result = await _post_bundle(bundle)
                summary = result.get("data", {}).get("summary", {})
                return (
                    f"Ingested paper '{paper.get('title', arxiv_id)}' into rabbit-hole graph. "
                    f"Entities: {summary.get('entitiesCreated', 0)} created, {summary.get('entitiesKept', 0)} existing. "
                    f"Relationships: {summary.get('relationshipsCreated', 0)} created."
                )

            elif action == "ingest_model":
                model_id = kwargs.get("model_id", "")
                if not model_id:
                    return "Error: model_id is required for ingest_model"
                model = _get_model(model_id)
                if not model:
                    return f"Model '{model_id}' not found in local knowledge store. Store it first with security_memory."
                bundle = model_to_bundle(model)
                result = await _post_bundle(bundle)
                summary = result.get("data", {}).get("summary", {})
                return (
                    f"Ingested model '{model.get('name', model_id)}' into rabbit-hole graph. "
                    f"Entities: {summary.get('entitiesCreated', 0)} created, {summary.get('entitiesKept', 0)} existing. "
                    f"Relationships: {summary.get('relationshipsCreated', 0)} created."
                )

            elif action == "ingest_text":
                text = kwargs.get("text", "")
                if not text:
                    return "Error: text is required for ingest_text"
                focus = kwargs.get("focus_entity", "")
                query = focus or "research findings"
                # Use rabbit-hole's chat/ingest endpoint which does LLM extraction
                # Endpoint expects: {query: str, text: str}
                async with httpx.AsyncClient(timeout=60) as client:
                    resp = await client.post(
                        f"{_BASE_URL}/api/chat/ingest",
                        json={"query": query, "text": text},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                entity_count = data.get("entitiesExtracted", 0)
                rel_count = data.get("relationshipsExtracted", 0)
                return (
                    f"Extracted and ingested from text: {entity_count} entities, {rel_count} relationships. "
                    f"Focus: {focus or 'general'}"
                )

            elif action == "ingest_batch":
                paper_ids = kwargs.get("paper_ids", []) or []
                model_ids = kwargs.get("model_ids", []) or []
                if not paper_ids and not model_ids:
                    return "Error: provide paper_ids and/or model_ids for ingest_batch"

                bundles = []
                errors = []
                for pid in paper_ids[:30]:
                    paper = _get_paper(pid)
                    if paper:
                        bundles.append(paper_to_bundle(paper))
                    else:
                        errors.append(f"Paper '{pid}' not in local store")

                for mid in model_ids[:20]:
                    model = _get_model(mid)
                    if model:
                        bundles.append(model_to_bundle(model))
                    else:
                        errors.append(f"Model '{mid}' not in local store")

                if not bundles:
                    return f"No items found to ingest. Errors: {'; '.join(errors)}"

                merged = merge_bundles(bundles)
                result = await _post_bundle(merged)
                summary = result.get("data", {}).get("summary", {})
                msg = (
                    f"Batch ingested {len(bundles)} items into rabbit-hole graph. "
                    f"Entities: {summary.get('entitiesCreated', 0)} created, {summary.get('entitiesKept', 0)} existing. "
                    f"Relationships: {summary.get('relationshipsCreated', 0)} created."
                )
                if errors:
                    msg += f"\nSkipped: {'; '.join(errors)}"
                return msg

            else:
                return f"Unknown action: {action}. Use: search_graph, ingest_paper, ingest_model, ingest_text, ingest_batch"

        except httpx.ConnectError:
            return f"Cannot reach rabbit-hole at {_BASE_URL}. Is it running?"
        except httpx.HTTPStatusError as e:
            return f"rabbit-hole API error: {e.response.status_code} {e.response.text[:200]}"
        except Exception as e:
            return f"Error: {type(e).__name__}: {e}"
