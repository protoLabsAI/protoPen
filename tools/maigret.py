"""Maigret — OSINT username reconnaissance across thousands of sites.

Maigret pins heavy, version-locked dependencies (aiohttp, requests, lxml,
reportlab, …) that would clash with protoPen's own deps, so it is NOT a
`requirements.txt` import. It runs as an isolated CLI — install it in its own
venv and point `MAIGRET_BIN` at the binary (or have it on PATH). See start.sh
(native) / Dockerfile (container) for the install.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from tools._tool_base import Tool
from tools.parsers import ingest_output

logger = logging.getLogger(__name__)


class MaigretTool(Tool):
    """Maigret — find accounts by username across 3000+ sites (passive OSINT)."""

    def __init__(self, workspace: str = "/tmp/protopen"):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None

    @property
    def name(self) -> str:
        return "maigret"

    @property
    def description(self) -> str:
        return (
            "Maigret OSINT username reconnaissance — search a username (or other "
            "identifier) across 3000+ sites and collect a public-account dossier: "
            "profile URLs plus extracted IDs, names, and bios. Passive — queries "
            "public sites only; no authentication or intrusion."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform (default search)",
                    "enum": ["search"],
                },
                "username": {"type": "string", "description": "Username or identifier to search for"},
                "top_sites": {
                    "type": "integer",
                    "description": "Check the N most popular sites (default 500). Ignored when all_sites is set.",
                },
                "all_sites": {
                    "type": "boolean",
                    "description": "Check all 3000+ sites instead of the top N (much slower)",
                },
                "id_type": {
                    "type": "string",
                    "description": "Identifier type: username (default), steam_id, vk_id, gaia_id, yandex_public_id, etc.",
                },
                "site": {"type": "string", "description": "Restrict the search to a single site by name"},
                "tags": {
                    "type": "string",
                    "description": "Comma-separated site tags to filter by (e.g. 'us,social,photo')",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Follow usernames/IDs extracted from found profiles (deeper, slower)",
                },
                "timeout": {"type": "integer", "description": "Per-request timeout in seconds (default 30)"},
                "max_seconds": {
                    "type": "integer",
                    "description": "Overall wall-clock cap for the whole search (default 300)",
                },
            },
            "required": ["username"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action") or "search"
        if action != "search":
            return f"Unknown action: {action}. Available: ['search']"
        username = (kwargs.get("username") or "").strip()
        if not username:
            return "maigret error: 'username' is required"
        try:
            result = await self.search(
                username,
                top_sites=int(kwargs.get("top_sites", 500)),
                all_sites=bool(kwargs.get("all_sites", False)),
                id_type=kwargs.get("id_type", "username"),
                site=kwargs.get("site", ""),
                tags=kwargs.get("tags", ""),
                recursive=bool(kwargs.get("recursive", False)),
                timeout=int(kwargs.get("timeout", 30)),
                max_seconds=int(kwargs.get("max_seconds", 300)),
            )
            ingest_output("maigret", "search", result, self._target_store)
            return result
        except Exception as exc:
            return f"maigret error (search): {exc}"

    def _resolve_bin(self) -> str | None:
        """Locate the isolated maigret binary; None if not installed."""
        env = os.environ.get("MAIGRET_BIN")
        if env:
            return env if Path(env).exists() else None
        return shutil.which("maigret")

    async def search(
        self,
        username: str,
        top_sites: int = 500,
        all_sites: bool = False,
        id_type: str = "username",
        site: str = "",
        tags: str = "",
        recursive: bool = False,
        timeout: int = 30,
        max_seconds: int = 300,
    ) -> str:
        binpath = self._resolve_bin()
        if not binpath:
            return (
                "maigret is not installed. Install it in an isolated venv (it pins "
                "aiohttp/requests/lxml): `python3 -m venv ~/.maigret-venv && "
                "~/.maigret-venv/bin/pip install maigret`, then set MAIGRET_BIN to "
                "the binary path (start.sh does this automatically on the Deck)."
            )
        args = [
            binpath,
            username,
            "--timeout",
            str(timeout),
            "-n",
            "100",
            "--no-color",
            "--no-progressbar",
            "--no-autoupdate",
        ]
        if not recursive:
            args.append("--no-recursion")
        if all_sites:
            args.append("-a")
        else:
            args += ["--top-sites", str(top_sites)]
        if id_type and id_type != "username":
            args += ["--id-type", id_type]
        if site:
            args += ["--site", site]
        if tags:
            args += ["--tags", tags]

        raw = await self._run(*args, timeout=max_seconds)
        return self._summarize(username, raw)

    async def _run(self, *args: str, timeout: int = 300) -> str:
        """Run maigret from the workspace dir; stdout only (it's self-contained)."""
        logger.info("Running: %s", " ".join(args))
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            cwd=str(self._workspace),
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return f"[timeout] maigret exceeded {timeout}s — narrow the search (lower top_sites or set a site)."
        return stdout.decode(errors="replace").strip()

    @staticmethod
    def _summarize(username: str, raw: str) -> str:
        """Keep found-account lines + their metadata; drop progress chatter."""
        if raw.startswith("[timeout]"):
            return raw
        kept: list[str] = []
        found = 0
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.startswith("[+] Using sites database"):
                continue
            if stripped.startswith(("[-]", "[!]", "[*]")):
                continue
            if stripped.startswith("[+] "):
                found += 1
            kept.append(line.rstrip())
        body = "\n".join(kept).strip()
        header = f"maigret: {found} account(s) found for '{username}'"
        if not body:
            return f"{header} — no accounts found."
        return f"{header}\n\n{body}"
