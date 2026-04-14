"""Security memory tool — LangGraph tool interface for the knowledge store.

Wraps KnowledgeStore as a tool the agent can call to store and search
CVEs, exploits, advisories, threat intel, and digests.
"""

import json
from typing import Any

from tools._tool_base import Tool

from knowledge.store import KnowledgeStore


class SecurityMemoryTool(Tool):
    """Store and search security knowledge — CVEs, exploits, advisories, threat intel."""

    def __init__(self, store: KnowledgeStore | None = None):
        self._store = store or KnowledgeStore()

    @property
    def name(self) -> str:
        return "security_memory"

    @property
    def description(self) -> str:
        return (
            "Persistent security knowledge store with hybrid search. Actions:\n"
            "- store_cve: Save a CVE with metadata and analysis\n"
            "- store_exploit: Save an exploit or PoC\n"
            "- store_advisory: Save a vendor/CERT advisory\n"
            "- store_threat_intel: Save a threat intelligence finding\n"
            "- store_digest: Save a security intelligence digest\n"
            "- search: Hybrid search (vector + keyword) across all stored knowledge\n"
            "- get_topics: List tracked security topics\n"
            "- add_topic: Add a new security topic to track\n"
            "- stats: Show knowledge base statistics"
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "store_cve", "store_exploit", "store_advisory",
                        "store_threat_intel", "store_digest",
                        "search", "get_topics", "add_topic", "stats",
                    ],
                    "description": "Action to perform.",
                },
                "query": {
                    "type": "string",
                    "description": "Search query (for 'search').",
                },
                # store_cve fields
                "cve_id": {"type": "string", "description": "CVE ID (e.g., CVE-2024-12345)."},
                "title": {"type": "string", "description": "Title for CVE, advisory, exploit, or digest."},
                "description": {"type": "string", "description": "Description text."},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Severity rating.",
                },
                "cvss_score": {"type": "number", "description": "CVSS score (0-10)."},
                "cvss_vector": {"type": "string", "description": "CVSS vector string."},
                "affected_products": {"type": "string", "description": "Comma-separated affected products."},
                "exploit_available": {"type": "boolean", "description": "Whether a public exploit exists."},
                "exploit_maturity": {
                    "type": "string",
                    "enum": ["poc", "weaponized", "active", "none"],
                    "description": "Exploit maturity level.",
                },
                "tags": {"type": "string", "description": "Comma-separated tags."},
                # store_exploit fields
                "source": {"type": "string", "description": "Source (exploit-db/github/custom for exploits, vendor/CERT for advisories)."},
                "source_url": {"type": "string", "description": "URL to exploit source."},
                "platform": {"type": "string", "description": "Platform: linux/windows/multi/hardware."},
                "exploit_type": {"type": "string", "description": "Type: remote/local/webapps/dos/shellcode."},
                "verified": {"type": "boolean", "description": "Whether the exploit has been verified."},
                # store_threat_intel fields
                "content": {"type": "string", "description": "Intel or finding content."},
                "source_type": {"type": "string", "description": "Source type: cve/advisory/exploit/engagement/osint."},
                "topic": {"type": "string", "description": "Related topic."},
                "intel_type": {
                    "type": "string",
                    "enum": ["indicator", "technique", "correlation", "recommendation"],
                    "description": "Type of intelligence.",
                },
                "target_relevance": {"type": "string", "description": "Which targets this affects (JSON)."},
                # store_advisory fields
                "url": {"type": "string", "description": "Advisory URL."},
                "cve_ids": {"type": "string", "description": "Comma-separated linked CVE IDs."},
                "published_at": {"type": "string", "description": "Publication date (ISO 8601)."},
                "notes": {"type": "string", "description": "Additional notes."},
                # add_topic fields
                "name": {"type": "string", "description": "Topic name."},
                "keywords": {"type": "string", "description": "Comma-separated keywords."},
                "priority": {"type": "integer", "description": "Priority 0-4 (0=critical)."},
                # search
                "filter_table": {"type": "string", "description": "Filter search to: cves/exploits/advisories/threat_intel/digests."},
                "k": {"type": "integer", "description": "Number of results (default 10)."},
                "search_mode": {
                    "type": "string",
                    "enum": ["hybrid", "vector", "keyword"],
                    "description": "Search mode: hybrid (default), vector (semantic only), keyword (BM25 only).",
                },
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs["action"]

        if action == "store_cve":
            return self._store_cve(kwargs)
        if action == "store_exploit":
            return self._store_exploit(kwargs)
        if action == "store_advisory":
            return self._store_advisory(kwargs)
        if action == "store_threat_intel":
            return self._store_threat_intel(kwargs)
        if action == "store_digest":
            return self._store_digest(kwargs)
        if action == "search":
            return self._search(kwargs)
        if action == "get_topics":
            return self._get_topics()
        if action == "add_topic":
            return self._add_topic(kwargs)
        if action == "stats":
            return self._stats()

        return f"Error: Unknown action '{action}'."

    def _store_cve(self, kwargs: dict) -> str:
        cve_id = kwargs.get("cve_id", "")
        if not cve_id:
            return "Error: 'cve_id' is required."
        products_str = kwargs.get("affected_products", "")
        products = [p.strip() for p in products_str.split(",") if p.strip()] if products_str else []
        tags_str = kwargs.get("tags", "")
        tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []
        ok = self._store.add_cve(
            cve_id=cve_id,
            title=kwargs.get("title", ""),
            description=kwargs.get("description", ""),
            severity=kwargs.get("severity", ""),
            cvss_score=kwargs.get("cvss_score", 0.0),
            cvss_vector=kwargs.get("cvss_vector", ""),
            affected_products=products,
            exploit_available=kwargs.get("exploit_available", False),
            exploit_maturity=kwargs.get("exploit_maturity", "none"),
            tags=tags,
            published_at=kwargs.get("published_at", ""),
            notes=kwargs.get("notes", ""),
        )
        return f"CVE {cve_id} stored." if ok else "Error: Failed to store CVE."

    def _store_exploit(self, kwargs: dict) -> str:
        title = kwargs.get("title", "")
        if not title:
            return "Error: 'title' is required."
        ok = self._store.add_exploit(
            title=title,
            cve_id=kwargs.get("cve_id", ""),
            description=kwargs.get("description", ""),
            source=kwargs.get("source", ""),
            source_url=kwargs.get("source_url", ""),
            platform=kwargs.get("platform", ""),
            exploit_type=kwargs.get("exploit_type", ""),
            verified=kwargs.get("verified", False),
            notes=kwargs.get("notes", ""),
        )
        return f"Exploit '{title}' stored." if ok else "Error: Failed to store exploit."

    def _store_advisory(self, kwargs: dict) -> str:
        title = kwargs.get("title", "")
        source = kwargs.get("source", "")
        if not title or not source:
            return "Error: 'title' and 'source' are required."
        products_str = kwargs.get("affected_products", "")
        products = [p.strip() for p in products_str.split(",") if p.strip()] if products_str else []
        cve_ids_str = kwargs.get("cve_ids", "")
        cve_ids = [c.strip() for c in cve_ids_str.split(",") if c.strip()] if cve_ids_str else []
        ok = self._store.add_advisory(
            source=source,
            title=title,
            content=kwargs.get("content", kwargs.get("description", "")),
            severity=kwargs.get("severity", ""),
            affected_products=products,
            cve_ids=cve_ids,
            url=kwargs.get("url", ""),
            published_at=kwargs.get("published_at", ""),
            notes=kwargs.get("notes", ""),
        )
        return f"Advisory '{title}' stored." if ok else "Error: Failed to store advisory."

    def _store_threat_intel(self, kwargs: dict) -> str:
        content = kwargs.get("content", "")
        if not content:
            return "Error: 'content' is required."
        ok = self._store.add_threat_intel(
            content=content,
            source=kwargs.get("source", ""),
            source_type=kwargs.get("source_type", ""),
            topic=kwargs.get("topic", ""),
            intel_type=kwargs.get("intel_type", "indicator"),
            severity=kwargs.get("severity", ""),
            target_relevance=kwargs.get("target_relevance", ""),
        )
        return "Threat intel stored." if ok else "Error: Failed to store threat intel."

    def _store_digest(self, kwargs: dict) -> str:
        title = kwargs.get("title", "")
        content = kwargs.get("content", "")
        if not title or not content:
            return "Error: 'title' and 'content' are required."
        cves_str = kwargs.get("cve_ids", "")
        cves = [c.strip() for c in cves_str.split(",") if c.strip()] if cves_str else []
        ok = self._store.add_digest(
            title=title,
            content=content,
            digest_type=kwargs.get("intel_type", "weekly"),
            topic=kwargs.get("topic", ""),
            cves_referenced=cves,
        )
        return "Digest stored." if ok else "Error: Failed to store digest."

    def _search(self, kwargs: dict) -> str:
        query = kwargs.get("query", "")
        if not query:
            return "Error: 'query' is required."
        k = kwargs.get("k", 10)
        filter_table = kwargs.get("filter_table")
        search_mode = kwargs.get("search_mode", "hybrid")
        if search_mode == "keyword":
            results = self._store.keyword_search(query, k=k, filter_table=filter_table)
        elif search_mode == "vector":
            results = self._store.search(query, k=k, filter_table=filter_table)
        else:
            results = self._store.hybrid_search(query, k=k, filter_table=filter_table)
        if not results:
            return "No results found."
        lines = []
        for i, r in enumerate(results, 1):
            lines.append(
                f"{i}. [{r['table']}:{r['source_id']}] (dist: {r['distance']:.3f})\n"
                f"   {r['preview']}"
            )
        return "\n".join(lines)

    def _get_topics(self) -> str:
        topics = self._store.get_topics()
        if not topics:
            return "No topics configured. Use 'add_topic' to start tracking security areas."
        lines = ["**Security Topics:**"]
        for t in topics:
            kw = json.loads(t.get("keywords", "[]"))
            kw_str = ", ".join(kw) if kw else ""
            scanned = t.get("last_scanned_at", "never") or "never"
            lines.append(
                f"- **{t['name']}** (P{t['priority']}) — {t.get('description', '')}\n"
                f"  Keywords: {kw_str}\n"
                f"  Last scanned: {scanned}"
            )
        return "\n".join(lines)

    def _add_topic(self, kwargs: dict) -> str:
        name = kwargs.get("name", "")
        if not name:
            return "Error: 'name' is required."
        kw_str = kwargs.get("keywords", "")
        keywords = [k.strip() for k in kw_str.split(",") if k.strip()] if kw_str else []
        ok = self._store.add_topic(
            name=name,
            description=kwargs.get("description", ""),
            keywords=keywords,
            priority=kwargs.get("priority", 2),
        )
        return f"Topic '{name}' added." if ok else "Error: Failed to add topic."

    def _stats(self) -> str:
        stats = self._store.get_stats()
        if not stats:
            return "Knowledge base not initialized."
        lines = ["**Security Knowledge Base Stats:**"]
        for table, count in stats.items():
            lines.append(f"- {table}: {count}")
        return "\n".join(lines)
