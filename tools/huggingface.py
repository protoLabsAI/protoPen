"""HuggingFace Hub search tool for protoPen.

Queries the HF Hub REST API for models, datasets, and papers.
No API key required for public data.
"""

import asyncio
from typing import Any

import httpx

from nanobot.agent.tools.base import Tool

_HF_API = "https://huggingface.co/api"
_TIMEOUT = 30
_MAX_RETRIES = 2


class HuggingFaceTool(Tool):
    """Search HuggingFace Hub for models, datasets, and papers."""

    @property
    def name(self) -> str:
        return "huggingface"

    @property
    def description(self) -> str:
        return (
            "Search HuggingFace Hub. Actions:\n"
            "- search_models: Find models by query, sorted by trending/downloads/created\n"
            "- search_datasets: Find datasets by query\n"
            "- model_card: Get the README/model card for a specific model\n"
            "- search_papers: Search HF papers"
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["search_models", "search_datasets", "model_card", "search_papers"],
                    "description": "Action to perform.",
                },
                "query": {
                    "type": "string",
                    "description": "Search query.",
                },
                "model_id": {
                    "type": "string",
                    "description": "Model ID for model_card (e.g. 'Qwen/Qwen3.5-27B').",
                },
                "sort": {
                    "type": "string",
                    "enum": ["trending", "downloads", "likes", "created"],
                    "description": "Sort order (default: trending).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default 10, max 30).",
                },
                "filter_task": {
                    "type": "string",
                    "description": "Filter by pipeline task (e.g. 'text-generation', 'image-classification').",
                },
            },
            "required": ["action"],
        }

    async def _api_get(self, url: str, params: dict | None = None) -> httpx.Response:
        """GET with retry and backoff."""
        last_err = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    resp = await client.get(url, params=params)
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
            if action == "search_models":
                return await self._search_models(kwargs)
            elif action == "search_datasets":
                return await self._search_datasets(kwargs)
            elif action == "model_card":
                return await self._model_card(kwargs)
            elif action == "search_papers":
                return await self._search_papers(kwargs)
            else:
                return f"Error: Unknown action '{action}'."
        except Exception as e:
            return f"HuggingFace {action} failed: {e}. Try rephrasing your query."

    async def _search_models(self, kwargs: dict) -> str:
        query = kwargs.get("query", "")
        sort = kwargs.get("sort", "trending")
        limit = min(kwargs.get("limit", 10), 30)
        filter_task = kwargs.get("filter_task", "")

        params: dict[str, Any] = {"limit": limit, "full": "false"}
        if query:
            params["search"] = query
        if sort == "trending":
            params["sort"] = "trending"
        elif sort == "downloads":
            params["sort"] = "downloads"
            params["direction"] = "-1"
        elif sort == "likes":
            params["sort"] = "likes"
            params["direction"] = "-1"
        elif sort == "created":
            params["sort"] = "createdAt"
            params["direction"] = "-1"
        if filter_task:
            params["pipeline_tag"] = filter_task

        try:
            resp = await self._api_get(f"{_HF_API}/models", params=params)
            models = resp.json()
        except Exception as e:
            return f"Error: HF model search failed after {_MAX_RETRIES + 1} attempts: {e}"

        if not models:
            return "No models found matching your HuggingFace search query."

        lines = []
        for i, m in enumerate(models, 1):
            model_id = m.get("modelId", m.get("id", "?"))
            downloads = m.get("downloads", 0)
            likes = m.get("likes", 0)
            pipeline = m.get("pipeline_tag", "")
            tags = m.get("tags", [])[:5]
            created = m.get("createdAt", "")[:10]

            line = f"{i}. **{model_id}**"
            if pipeline:
                line += f" ({pipeline})"
            line += f"\n   Downloads: {downloads:,} | Likes: {likes} | Created: {created}"
            if tags:
                line += f"\n   Tags: {', '.join(tags)}"
            lines.append(line)

        return "\n\n".join(lines)

    async def _search_datasets(self, kwargs: dict) -> str:
        query = kwargs.get("query", "")
        sort = kwargs.get("sort", "trending")
        limit = min(kwargs.get("limit", 10), 30)

        params: dict[str, Any] = {"limit": limit}
        if query:
            params["search"] = query
        if sort == "trending":
            params["sort"] = "trending"
        elif sort == "downloads":
            params["sort"] = "downloads"
            params["direction"] = "-1"

        try:
            resp = await self._api_get(f"{_HF_API}/datasets", params=params)
            datasets = resp.json()
        except Exception as e:
            return f"Error: HF dataset search failed after {_MAX_RETRIES + 1} attempts: {e}"

        if not datasets:
            return "No datasets found matching your search query."

        lines = []
        for i, d in enumerate(datasets, 1):
            ds_id = d.get("id", "?")
            downloads = d.get("downloads", 0)
            likes = d.get("likes", 0)
            lines.append(f"{i}. **{ds_id}** — Downloads: {downloads:,} | Likes: {likes}")

        return "\n".join(lines)

    async def _model_card(self, kwargs: dict) -> str:
        model_id = kwargs.get("model_id", "") or kwargs.get("query", "")
        if not model_id:
            return "Error: 'model_id' is required."

        try:
            resp = await self._api_get(
                f"https://huggingface.co/{model_id}/raw/main/README.md"
            )
            content = resp.text
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return f"Model card not found for {model_id}."
            return f"Error fetching model card: {e}"
        except Exception as e:
            return f"Error fetching model card after {_MAX_RETRIES + 1} attempts: {e}"

        # Truncate long model cards
        if len(content) > 8000:
            content = content[:8000] + "\n\n[... truncated]"

        return content

    async def _search_papers(self, kwargs: dict) -> str:
        query = kwargs.get("query", "")
        if not query:
            return "Error: 'query' is required for paper search."
        limit = min(kwargs.get("limit", 10), 30)

        try:
            resp = await self._api_get(
                f"{_HF_API}/papers/search",
                params={"query": query, "limit": limit},
            )
            papers = resp.json()
        except Exception as e:
            return f"Error: HF papers search failed after {_MAX_RETRIES + 1} attempts: {e}"

        if not papers:
            return "No papers found matching your search query."

        lines = []
        for i, p in enumerate(papers, 1):
            title = p.get("title", "Untitled")
            paper_id = p.get("id", "?")
            upvotes = p.get("upvotes", 0)
            published = p.get("publishedAt", "")[:10]
            lines.append(
                f"{i}. **{title}**\n"
                f"   ID: {paper_id} | Upvotes: {upvotes} | Published: {published}"
            )

        return "\n\n".join(lines)
