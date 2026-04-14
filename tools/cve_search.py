"""CVE search tool for protoPen.

Queries the NVD REST API v2 for vulnerability data.
Optional NVD_API_KEY env var for higher rate limits (50 req/30s vs 5 req/30s).
"""

import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from tools._tool_base import Tool

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT = 30
_MAX_RETRIES = 2

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


class CVESearchTool(Tool):
    """Search the NVD CVE database for vulnerabilities."""

    @property
    def name(self) -> str:
        return "cve_search"

    @property
    def description(self) -> str:
        return (
            "Search the NVD CVE database for vulnerabilities. Actions:\n"
            "- search: Search CVEs by keyword, product, or CVSS score\n"
            "- get: Get detailed info for a specific CVE ID\n"
            "- recent: Get recently published/modified CVEs"
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["search", "get", "recent"],
                    "description": "Action to perform.",
                },
                "query": {
                    "type": "string",
                    "description": "Search keyword (for 'search').",
                },
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID (for 'get'), e.g. CVE-2024-12345.",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Filter by CVSS severity.",
                },
                "product": {
                    "type": "string",
                    "description": "Filter by product name (CPE match).",
                },
                "days": {
                    "type": "integer",
                    "description": "Look back N days (for 'recent', default 7).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default 10, max 50).",
                },
            },
            "required": ["action"],
        }

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        api_key = os.environ.get("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key
        return headers

    async def _api_get(self, params: dict) -> dict:
        """GET NVD API with retry and backoff."""
        last_err = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    resp = await client.get(
                        _NVD_API, params=params, headers=self._headers()
                    )
                    if resp.status_code == 403:
                        return {"error": "Rate limited. Set NVD_API_KEY for higher limits."}
                    resp.raise_for_status()
                    return resp.json()
            except Exception as e:
                last_err = e
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(2 * (attempt + 1))
        return {"error": f"NVD API failed after {_MAX_RETRIES + 1} attempts: {last_err}"}

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs["action"]
        try:
            if action == "search":
                return await self._search(kwargs)
            elif action == "get":
                return await self._get(kwargs)
            elif action == "recent":
                return await self._recent(kwargs)
            else:
                return f"Error: Unknown action '{action}'."
        except Exception as e:
            return f"CVE {action} failed: {e}"

    async def _search(self, kwargs: dict) -> str:
        query = kwargs.get("query", "")
        if not query:
            return "Error: 'query' is required for search."

        params: dict[str, Any] = {
            "keywordSearch": query,
            "resultsPerPage": min(kwargs.get("limit", 10), 50),
        }

        severity = kwargs.get("severity", "")
        if severity and severity in _SEVERITY_MAP:
            params["cvssV3Severity"] = _SEVERITY_MAP[severity]

        product = kwargs.get("product", "")
        if product:
            params["virtualMatchString"] = f"cpe:2.3:*:*:{product}"

        data = await self._api_get(params)
        if "error" in data:
            return data["error"]

        return self._format_results(data)

    async def _get(self, kwargs: dict) -> str:
        cve_id = kwargs.get("cve_id", "")
        if not cve_id:
            return "Error: 'cve_id' is required for get."

        data = await self._api_get({"cveId": cve_id})
        if "error" in data:
            return data["error"]

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"No results for {cve_id}."

        return self._format_detail(vulns[0])

    async def _recent(self, kwargs: dict) -> str:
        days = kwargs.get("days", 7)
        limit = min(kwargs.get("limit", 10), 50)

        now = datetime.now(timezone.utc)
        start = now - timedelta(days=days)

        params: dict[str, Any] = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": limit,
        }

        severity = kwargs.get("severity", "")
        if severity and severity in _SEVERITY_MAP:
            params["cvssV3Severity"] = _SEVERITY_MAP[severity]

        data = await self._api_get(params)
        if "error" in data:
            return data["error"]

        return self._format_results(data)

    def _format_results(self, data: dict) -> str:
        """Format NVD API response as markdown."""
        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", [])

        if not vulns:
            return "No CVEs found."

        lines = [f"**{total} CVE(s) found** (showing {len(vulns)}):\n"]

        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "?")
            desc = self._get_description(cve)
            score, severity = self._get_cvss(cve)
            published = cve.get("published", "")[:10]

            lines.append(
                f"**{cve_id}** [{severity} {score}] ({published})\n"
                f"  {desc[:200]}{'...' if len(desc) > 200 else ''}"
            )

        return "\n\n".join(lines)

    def _format_detail(self, item: dict) -> str:
        """Format a single CVE with full detail."""
        cve = item.get("cve", {})
        cve_id = cve.get("id", "?")
        desc = self._get_description(cve)
        score, severity = self._get_cvss(cve)
        vector = self._get_cvss_vector(cve)
        published = cve.get("published", "")[:10]
        modified = cve.get("lastModified", "")[:10]

        lines = [
            f"# {cve_id}",
            f"**Severity:** {severity} ({score})",
            f"**Vector:** {vector}",
            f"**Published:** {published} | **Modified:** {modified}",
            f"\n## Description\n{desc}",
        ]

        # References
        refs = cve.get("references", [])
        if refs:
            lines.append("\n## References")
            for ref in refs[:15]:
                url = ref.get("url", "")
                tags = ", ".join(ref.get("tags", []))
                lines.append(f"- {url}" + (f" ({tags})" if tags else ""))

        # Affected configurations (CPEs)
        configs = cve.get("configurations", [])
        if configs:
            lines.append("\n## Affected Products")
            for config in configs[:5]:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", [])[:10]:
                        cpe = match.get("criteria", "")
                        vulnerable = match.get("vulnerable", False)
                        if vulnerable:
                            lines.append(f"- `{cpe}`")

        return "\n".join(lines)

    @staticmethod
    def _get_description(cve: dict) -> str:
        """Extract English description from CVE data."""
        descriptions = cve.get("descriptions", [])
        for d in descriptions:
            if d.get("lang") == "en":
                return d.get("value", "")
        return descriptions[0].get("value", "") if descriptions else ""

    @staticmethod
    def _get_cvss(cve: dict) -> tuple[str, str]:
        """Extract CVSS score and severity."""
        metrics = cve.get("metrics", {})
        # Try v3.1 first, then v3.0, then v2
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss = metric_list[0].get("cvssData", {})
                score = cvss.get("baseScore", 0)
                severity = cvss.get("baseSeverity", "UNKNOWN")
                return str(score), severity
        return "N/A", "UNKNOWN"

    @staticmethod
    def _get_cvss_vector(cve: dict) -> str:
        """Extract CVSS vector string."""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(key, [])
            if metric_list:
                return metric_list[0].get("cvssData", {}).get("vectorString", "N/A")
        return "N/A"
