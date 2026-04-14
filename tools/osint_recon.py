"""OSINT reconnaissance — theHarvester for emails, subdomains, IPs."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from tools.parsers import ingest_output
from tools._tool_base import Tool

logger = logging.getLogger(__name__)


class OsintReconTool(Tool):
    """OSINT reconnaissance — theHarvester and whois lookups."""

    def __init__(self, workspace: str = "/tmp/protopen"):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None

    @property
    def name(self) -> str:
        return "osint_recon"

    @property
    def description(self) -> str:
        return (
            "OSINT reconnaissance tools. theHarvester for email, subdomain, "
            "and IP discovery from public sources. Whois domain lookups."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": ["theharvester", "whois_lookup"],
                },
                "target": {"type": "string", "description": "Domain to investigate"},
                "source": {"type": "string", "description": "theHarvester data source (default all)"},
                "limit": {"type": "integer", "description": "Result limit (default 500)"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 120)"},
            },
            "required": ["action", "target"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        dispatch = {
            "theharvester": lambda: self.theharvester(
                kwargs.get("target", ""),
                kwargs.get("source", "all"),
                kwargs.get("limit", 500),
                kwargs.get("timeout", 120),
            ),
            "whois_lookup": lambda: self.whois_lookup(
                kwargs.get("target", ""),
                kwargs.get("timeout", 30),
            ),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            result = await fn()
            ingest_output("osint_recon", action, result, self._target_store)
            return result
        except Exception as exc:
            return f"osint_recon error ({action}): {exc}"

    async def _run(self, *args: str, timeout: int = 120) -> str:
        logger.info("Running: %s", " ".join(args))
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return f"Command timed out after {timeout}s: {' '.join(args)}"
        output = stdout.decode(errors="replace")
        if stderr:
            output += f"\n[stderr] {stderr.decode(errors='replace')}"
        return output.strip()

    async def theharvester(self, target: str, source: str = "all", limit: int = 500, timeout: int = 120) -> str:
        args = ["theHarvester", "-d", target, "-b", source, "-l", str(limit)]
        return await self._run(*args, timeout=timeout)

    async def whois_lookup(self, target: str, timeout: int = 30) -> str:
        args = ["whois", target]
        return await self._run(*args, timeout=timeout)
