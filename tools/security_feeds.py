"""Security advisory RSS/Atom feed aggregator for protoPen.

Fetches and parses entries from well-known security advisory feeds
(NVD, CISA, Exploit-DB, etc.) and presents them as formatted markdown.
"""

import asyncio
import html
import re
import xml.etree.ElementTree as ET
from typing import Any

import httpx

try:
    from nanobot.agent.tools.base import Tool
except ImportError:
    from tools._tool_base import Tool

_TIMEOUT = 30
_MAX_RETRIES = 2
_DESC_LIMIT = 200

_FEEDS: dict[str, dict[str, str]] = {
    "nvd": {
        "name": "NVD Recent CVEs",
        "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
        "type": "rss",
    },
    "us-cert": {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "type": "rss",
    },
    "exploit-db": {
        "name": "Exploit-DB Recent",
        "url": "https://www.exploit-db.com/rss.xml",
        "type": "rss",
    },
    "schneier": {
        "name": "Schneier on Security",
        "url": "https://www.schneier.com/feed/atom/",
        "type": "atom",
    },
    "krebs": {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "type": "rss",
    },
    "hn-security": {
        "name": "Hacker News (Security)",
        "url": "https://hnrss.org/newest?q=CVE+OR+vulnerability+OR+exploit+OR+zero-day",
        "type": "rss",
    },
    "portswigger": {
        "name": "PortSwigger Research",
        "url": "https://portswigger.net/research/rss",
        "type": "rss",
    },
    "project-zero": {
        "name": "Google Project Zero",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "type": "atom",
    },
}


def _strip_html(text: str) -> str:
    """Remove HTML tags and decode entities."""
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(text).strip()


def _truncate(text: str, limit: int = _DESC_LIMIT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "..."


def _parse_rss(xml_bytes: bytes) -> list[dict[str, str]]:
    """Parse RSS 2.0 <item> elements."""
    root = ET.fromstring(xml_bytes)
    entries: list[dict[str, str]] = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        desc_raw = item.findtext("description") or ""
        desc = _truncate(_strip_html(desc_raw))
        entries.append(
            {"title": title, "link": link, "published": pub_date, "description": desc}
        )
    return entries


def _parse_atom(xml_bytes: bytes) -> list[dict[str, str]]:
    """Parse Atom <entry> elements, handling default namespace."""
    root = ET.fromstring(xml_bytes)
    # Detect Atom namespace (if present)
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    entries: list[dict[str, str]] = []
    for entry in root.iter(f"{ns}entry"):
        title = (entry.findtext(f"{ns}title") or "").strip()

        # Atom links live in <link href="..."/>
        link_el = entry.find(f"{ns}link[@rel='alternate']")
        if link_el is None:
            link_el = entry.find(f"{ns}link")
        link = (link_el.get("href", "") if link_el is not None else "").strip()

        published = (
            entry.findtext(f"{ns}published")
            or entry.findtext(f"{ns}updated")
            or ""
        ).strip()

        # Atom content or summary
        desc_raw = (
            entry.findtext(f"{ns}summary")
            or entry.findtext(f"{ns}content")
            or ""
        )
        desc = _truncate(_strip_html(desc_raw))
        entries.append(
            {"title": title, "link": link, "published": published, "description": desc}
        )
    return entries


class SecurityFeedsTool(Tool):
    """Aggregate security advisory feeds from well-known sources."""

    @property
    def name(self) -> str:
        return "security_feeds"

    @property
    def description(self) -> str:
        return (
            "Aggregate security advisory feeds. Actions:\n"
            "- scan: Fetch and parse recent entries from security RSS/Atom feeds\n"
            "- sources: List available feed sources\n"
            "- search: Search feed entries by keyword"
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["scan", "sources", "search"],
                    "description": "Action to perform.",
                },
                "source": {
                    "type": "string",
                    "description": "Feed source name to scan (for 'scan'). Use 'sources' to list available.",
                },
                "query": {
                    "type": "string",
                    "description": "Search keyword (for 'search').",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max entries to return (default 20).",
                },
            },
            "required": ["action"],
        }

    async def _fetch_feed(self, key: str) -> list[dict[str, str]]:
        """Fetch and parse a single feed by its key."""
        feed = _FEEDS[key]
        url = feed["url"]
        feed_type = feed["type"]

        last_err: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    resp = await client.get(
                        url,
                        headers={"User-Agent": "protoPen/1.0 security-feeds"},
                        follow_redirects=True,
                    )
                    resp.raise_for_status()

                if feed_type == "atom":
                    return _parse_atom(resp.content)
                return _parse_rss(resp.content)
            except Exception as exc:
                last_err = exc
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(1 * (attempt + 1))

        raise last_err  # type: ignore[misc]

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs["action"]
        try:
            if action == "scan":
                return await self._scan(kwargs)
            elif action == "sources":
                return self._sources()
            elif action == "search":
                return await self._search(kwargs)
            else:
                return f"Error: Unknown action '{action}'."
        except Exception as e:
            return f"security_feeds {action} failed: {e}"

    async def _scan(self, kwargs: dict) -> str:
        source = kwargs.get("source")
        limit = kwargs.get("limit", 20)

        if source:
            if source not in _FEEDS:
                return (
                    f"Error: Unknown source '{source}'. "
                    f"Available: {', '.join(sorted(_FEEDS))}"
                )
            keys = [source]
        else:
            keys = list(_FEEDS)

        all_entries: list[tuple[str, dict[str, str]]] = []
        for key in keys:
            try:
                entries = await self._fetch_feed(key)
                for entry in entries:
                    all_entries.append((key, entry))
            except Exception as exc:
                all_entries.append(
                    (key, {"title": f"[fetch error: {exc}]", "link": "", "published": "", "description": ""})
                )

        if not all_entries:
            return "No entries found."

        all_entries = all_entries[:limit]
        return self._format_entries(all_entries)

    def _sources(self) -> str:
        lines = ["**Available Security Feed Sources**\n"]
        for key in sorted(_FEEDS):
            feed = _FEEDS[key]
            lines.append(f"- `{key}` -- {feed['name']} ({feed['type']})")
        return "\n".join(lines)

    async def _search(self, kwargs: dict) -> str:
        query = kwargs.get("query", "").lower()
        if not query:
            return "Error: 'query' is required for search."

        limit = kwargs.get("limit", 20)
        matches: list[tuple[str, dict[str, str]]] = []

        for key in _FEEDS:
            try:
                entries = await self._fetch_feed(key)
            except Exception:
                continue

            for entry in entries:
                text = f"{entry.get('title', '')} {entry.get('description', '')}".lower()
                if query in text:
                    matches.append((key, entry))

        if not matches:
            return f"No entries matching '{query}' found across all feeds."

        matches = matches[:limit]
        return self._format_entries(matches)

    @staticmethod
    def _format_entries(entries: list[tuple[str, dict[str, str]]]) -> str:
        lines: list[str] = []
        for i, (source_key, entry) in enumerate(entries, 1):
            title = entry.get("title", "(no title)")
            link = entry.get("link", "")
            published = entry.get("published", "")
            desc = entry.get("description", "")

            line = f"{i}. **{title}**"
            if link:
                line += f"\n   {link}"
            meta_parts: list[str] = []
            if published:
                meta_parts.append(f"Published: {published}")
            meta_parts.append(f"Source: {source_key}")
            line += f"\n   {' | '.join(meta_parts)}"
            if desc:
                line += f"\n   {desc}"
            lines.append(line)

        return "\n\n".join(lines)
