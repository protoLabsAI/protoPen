"""Lab monitor tool — track experiments and docs from protoLabsAI/lab.

Reads from the GitHub API to check new commits, experiments, docs, and
training data changes since the last digest. Gives the researcher agent
awareness of what the team is building and testing on ava-ai.
"""

import os
from datetime import datetime, timezone
from typing import Any

import httpx

from tools._tool_base import Tool

_GITHUB_API = "https://api.github.com"
_REPO = "protoLabsAI/lab"

# Paths of interest
_WATCH_PATHS = [
    "experiments/",
    "experiments/README.md",
    "experiments/TODO.md",
    "models/",
    "training/",
    "evals/",
    "CLAUDE.md",
]


class LabMonitorTool(Tool):
    """Monitor protoLabs lab and mythxengine repos for new work."""

    def __init__(self):
        self._token = os.environ.get("GITHUB_TOKEN", "")
        self._last_checked: dict[str, str] = {}  # repo -> ISO timestamp

    @property
    def name(self) -> str:
        return "lab_monitor"

    @property
    def description(self) -> str:
        return (
            "Monitor protoLabsAI/lab for new experiments, docs, and changes. Actions:\n"
            "- recent_commits: Get commits since last check (or last N days)\n"
            "- read_file: Read a file from the repo (README, experiment index, etc.)\n"
            "- experiments: List active experiments from the lab index\n"
            "- diff: Show what changed in a specific commit\n"
            "- watch_paths: Show which paths are monitored\n"
            "- changes_since: Get all changes to watched paths since a date"
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "recent_commits", "read_file", "experiments",
                        "diff", "watch_paths", "changes_since",
                    ],
                },
                "path": {
                    "type": "string",
                    "description": "File path for 'read_file', or filter path for commits.",
                },
                "sha": {
                    "type": "string",
                    "description": "Commit SHA for 'diff'.",
                },
                "days": {
                    "type": "integer",
                    "description": "Number of days to look back (default: 7).",
                },
                "since": {
                    "type": "string",
                    "description": "ISO date for 'changes_since' (e.g. 2026-03-20).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default: 20).",
                },
            },
            "required": ["action"],
        }

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self._token:
            headers["Authorization"] = f"token {self._token}"
        return headers

    async def execute(self, **kwargs) -> str:
        action = kwargs.get("action", "")

        try:
            if action == "recent_commits":
                return await self._recent_commits(
                    days=kwargs.get("days", 7),
                    path=kwargs.get("path", ""),
                    limit=kwargs.get("limit", 20),
                )
            elif action == "read_file":
                return await self._read_file(
                    kwargs.get("path", "README.md"),
                )
            elif action == "experiments":
                return await self._read_file("experiments/README.md")
            elif action == "diff":
                return await self._diff(kwargs.get("sha", ""))
            elif action == "watch_paths":
                lines = ["## Watched paths in protoLabsAI/lab:"]
                for p in _WATCH_PATHS:
                    lines.append(f"  - {p}")
                return "\n".join(lines)
            elif action == "changes_since":
                return await self._changes_since(
                    since=kwargs.get("since", ""),
                    limit=kwargs.get("limit", 30),
                )
            else:
                return f"Unknown action: {action}"
        except Exception as e:
            return f"Error: {e}"

    async def _recent_commits(
        self, days: int = 7, path: str = "", limit: int = 20,
    ) -> str:
        since = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0
        )
        from datetime import timedelta
        since = since - timedelta(days=days)

        params: dict[str, Any] = {
            "since": since.isoformat(),
            "per_page": min(limit, 100),
        }
        if path:
            params["path"] = path

        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                f"{_GITHUB_API}/repos/{_REPO}/commits",
                headers=self._headers(), params=params,
            )
            r.raise_for_status()
            commits = r.json()

        if not commits:
            return f"No commits in {_REPO} in the last {days} days."

        lines = [f"## Recent commits in {_REPO} (last {days} days):\n"]
        for c in commits[:limit]:
            sha = c["sha"][:8]
            msg = c["commit"]["message"].split("\n")[0]
            date = c["commit"]["author"]["date"][:10]
            author = c["commit"]["author"]["name"]
            lines.append(f"- `{sha}` {date} ({author}): {msg}")

        self._last_checked["lab"] = datetime.now(timezone.utc).isoformat()

        return "\n".join(lines)

    async def _read_file(self, path: str) -> str:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                f"{_GITHUB_API}/repos/{_REPO}/contents/{path}",
                headers=self._headers(),
            )
            r.raise_for_status()
            data = r.json()

        if data.get("encoding") == "base64":
            import base64
            content = base64.b64decode(data["content"]).decode("utf-8")
            return f"## {path}\n\n{content}"
        elif data.get("type") == "dir":
            entries = [f"- {e['name']} ({e['type']})" for e in data]
            return f"## Directory: {path}\n\n" + "\n".join(entries)
        else:
            return f"Cannot read {path}: unsupported encoding"

    async def _diff(self, sha: str) -> str:
        if not sha:
            return "Error: 'sha' is required for diff action."

        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                f"{_GITHUB_API}/repos/{_REPO}/commits/{sha}",
                headers=self._headers(),
            )
            r.raise_for_status()
            commit = r.json()

        msg = commit["commit"]["message"]
        files = commit.get("files", [])

        lines = [f"## Commit {sha[:8]}: {msg.split(chr(10))[0]}\n"]
        for f in files:
            status = f["status"]
            name = f["filename"]
            adds = f.get("additions", 0)
            dels = f.get("deletions", 0)
            lines.append(f"  {status:>8} {name} (+{adds}/-{dels})")

        return "\n".join(lines)

    async def _changes_since(
        self, since: str = "", limit: int = 30,
    ) -> str:
        if not since:
            return "Error: 'since' date is required (e.g. 2026-03-20)."

        params: dict[str, Any] = {
            "since": f"{since}T00:00:00Z",
            "per_page": 100,
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                f"{_GITHUB_API}/repos/{_REPO}/commits",
                headers=self._headers(), params=params,
            )
            r.raise_for_status()
            all_commits = r.json()

        # Filter to commits touching watched paths
        relevant = []
        for c in all_commits:
            sha = c["sha"]
            async with httpx.AsyncClient(timeout=15.0) as client:
                cr = await client.get(
                    f"{_GITHUB_API}/repos/{_REPO}/commits/{sha}",
                    headers=self._headers(),
                )
                if cr.status_code != 200:
                    continue
                files = cr.json().get("files", [])

            touched = [
                f["filename"] for f in files
                if any(f["filename"].startswith(wp) for wp in _WATCH_PATHS)
            ]
            if touched:
                msg = c["commit"]["message"].split("\n")[0]
                date = c["commit"]["author"]["date"][:10]
                relevant.append((sha[:8], date, msg, touched))

            if len(relevant) >= limit:
                break

        if not relevant:
            return f"No changes to watched paths in {_REPO} since {since}."

        lines = [f"## Changes to watched paths in {_REPO} since {since}:\n"]
        for sha, date, msg, files in relevant:
            lines.append(f"### `{sha}` {date}: {msg}")
            for f in files[:5]:
                lines.append(f"  - {f}")
            if len(files) > 5:
                lines.append(f"  - ...and {len(files) - 5} more")
            lines.append("")

        return "\n".join(lines)
