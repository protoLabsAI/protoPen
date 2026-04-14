"""GitHub trending and search tool for protoPen.

Uses the GitHub REST API (search endpoint) for repo discovery.
Unauthenticated: 10 req/min. With GITHUB_TOKEN: 30 req/min.
"""

import asyncio
import os
from typing import Any

import httpx

from tools._tool_base import Tool

_GITHUB_API = "https://api.github.com"
_TIMEOUT = 30
_MAX_RETRIES = 2


class GitHubTrendingTool(Tool):
    """Search GitHub for trending and notable security tool repositories."""

    @property
    def name(self) -> str:
        return "github_trending"

    @property
    def description(self) -> str:
        return (
            "Search GitHub for security tool repositories and releases. Actions:\n"
            "- search: Search repos by query with star/activity filters\n"
            "- recent_repos: Find recently created repos with high engagement\n"
            "- releases: Check latest releases for tracked repos"
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["search", "recent_repos", "releases"],
                    "description": "Action to perform.",
                },
                "query": {
                    "type": "string",
                    "description": "Search query (for 'search').",
                },
                "topic": {
                    "type": "string",
                    "description": "GitHub topic filter (e.g. 'machine-learning', 'llm').",
                },
                "language": {
                    "type": "string",
                    "description": "Language filter (e.g. 'python', 'rust').",
                },
                "min_stars": {
                    "type": "integer",
                    "description": "Minimum stars (default 100).",
                },
                "created_after": {
                    "type": "string",
                    "description": "Only repos created after this date (YYYY-MM-DD).",
                },
                "repos": {
                    "type": "string",
                    "description": "Comma-separated repo list for 'releases' (e.g. 'vllm-project/vllm,huggingface/transformers').",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default 10, max 30).",
                },
                "sort": {
                    "type": "string",
                    "enum": ["stars", "updated", "forks"],
                    "description": "Sort order (default: stars).",
                },
            },
            "required": ["action"],
        }

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def _api_get(self, url: str, params: dict | None = None) -> httpx.Response:
        """GET with retry and backoff."""
        last_err = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    resp = await client.get(url, params=params, headers=self._headers())
                    resp.raise_for_status()
                    return resp
            except Exception as e:
                last_err = e
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(1 * (attempt + 1))
        raise last_err  # type: ignore[misc]

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs["action"]
        try:
            if action == "search":
                return await self._search(kwargs)
            elif action == "recent_repos":
                return await self._recent_repos(kwargs)
            elif action == "releases":
                return await self._releases(kwargs)
            else:
                return f"Error: Unknown action '{action}'."
        except Exception as e:
            return f"GitHub {action} failed: {e}. Try rephrasing your query."

    async def _search(self, kwargs: dict) -> str:
        query = kwargs.get("query", "")
        if not query:
            return "Error: 'query' is required for search."

        topic = kwargs.get("topic", "")
        language = kwargs.get("language", "")
        min_stars = kwargs.get("min_stars", 100)
        sort = kwargs.get("sort", "stars")
        limit = min(kwargs.get("limit", 10), 30)

        q_parts = [query]
        if topic:
            q_parts.append(f"topic:{topic}")
        if language:
            q_parts.append(f"language:{language}")
        q_parts.append(f"stars:>={min_stars}")

        try:
            resp = await self._api_get(
                f"{_GITHUB_API}/search/repositories",
                params={
                    "q": " ".join(q_parts),
                    "sort": sort,
                    "order": "desc",
                    "per_page": limit,
                },
            )
            data = resp.json()
        except Exception as e:
            return f"Error: GitHub API request failed after {_MAX_RETRIES + 1} attempts: {e}"

        repos = data.get("items", [])
        if not repos:
            return "No repositories found matching your GitHub search query."

        return self._format_repos(repos)

    async def _recent_repos(self, kwargs: dict) -> str:
        topic = kwargs.get("topic", "security")
        language = kwargs.get("language", "python")
        created_after = kwargs.get("created_after", "")
        min_stars = kwargs.get("min_stars", 50)
        limit = min(kwargs.get("limit", 10), 30)

        q_parts = [f"topic:{topic}"]
        if language:
            q_parts.append(f"language:{language}")
        q_parts.append(f"stars:>={min_stars}")
        if created_after:
            q_parts.append(f"created:>={created_after}")

        try:
            resp = await self._api_get(
                f"{_GITHUB_API}/search/repositories",
                params={
                    "q": " ".join(q_parts),
                    "sort": "stars",
                    "order": "desc",
                    "per_page": limit,
                },
            )
            data = resp.json()
        except Exception as e:
            return f"Error: GitHub API request failed after {_MAX_RETRIES + 1} attempts: {e}"

        repos = data.get("items", [])
        if not repos:
            return "No recent repositories found matching your GitHub search."

        return self._format_repos(repos)

    async def _releases(self, kwargs: dict) -> str:
        repos_str = kwargs.get("repos", "")
        if not repos_str:
            # Default tracked repos
            repos_str = "projectdiscovery/nuclei,projectdiscovery/httpx,swisskyrepo/PayloadsAllTheThings,carlospolop/PEASS-ng,fortra/impacket,BloodHoundAD/BloodHound,rapid7/metasploit-framework,hashcat/hashcat"

        repos = [r.strip() for r in repos_str.split(",") if r.strip()]
        lines = []

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            for repo in repos[:10]:
                try:
                    resp = await client.get(
                        f"{_GITHUB_API}/repos/{repo}/releases",
                        params={"per_page": 3},
                        headers=self._headers(),
                    )
                    if resp.status_code == 404:
                        lines.append(f"**{repo}**: not found")
                        continue
                    resp.raise_for_status()
                    releases = resp.json()

                    if not releases:
                        lines.append(f"**{repo}**: no releases")
                        continue

                    latest = releases[0]
                    tag = latest.get("tag_name", "?")
                    published = latest.get("published_at", "")[:10]
                    name = latest.get("name", tag)
                    body_preview = (latest.get("body") or "")[:200]

                    lines.append(
                        f"**{repo}** → `{tag}` ({published})\n"
                        f"  {name}\n"
                        f"  {body_preview}{'...' if len(body_preview) >= 200 else ''}"
                    )
                except Exception as e:
                    lines.append(f"**{repo}**: error — {e}")

        return "\n\n".join(lines) if lines else "No release data."

    def _format_repos(self, repos: list[dict]) -> str:
        lines = []
        for i, r in enumerate(repos, 1):
            name = r.get("full_name", "?")
            desc = r.get("description", "") or ""
            stars = r.get("stargazers_count", 0)
            forks = r.get("forks_count", 0)
            lang = r.get("language", "")
            created = r.get("created_at", "")[:10]
            updated = r.get("updated_at", "")[:10]
            topics = r.get("topics", [])[:5]

            line = f"{i}. **{name}** — {desc[:120]}"
            line += f"\n   Stars: {stars:,} | Forks: {forks:,} | Lang: {lang} | Updated: {updated}"
            if topics:
                line += f"\n   Topics: {', '.join(topics)}"
            lines.append(line)

        return "\n\n".join(lines)
