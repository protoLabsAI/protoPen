"""Subdomain enumeration via subfinder and amass passive mode."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from tools.parsers import ingest_output
from tools._subprocess import communicate_or_kill
from tools._tool_base import Tool

logger = logging.getLogger(__name__)


class SubdomainDiscoveryTool(Tool):
    """Subdomain enumeration — subfinder and amass passive mode."""

    def __init__(self, workspace: str = "/tmp/protopen"):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None

    @property
    def name(self) -> str:
        return "subdomain_discovery"

    @property
    def description(self) -> str:
        return "Subdomain enumeration via subfinder and amass passive mode."

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": ["subfinder", "amass_passive"],
                },
                "target": {"type": "string", "description": "Root domain"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 120)"},
            },
            "required": ["action", "target"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        dispatch = {
            "subfinder": lambda: self.subfinder(
                kwargs.get("target", ""),
                kwargs.get("timeout", 120),
            ),
            "amass_passive": lambda: self.amass_passive(
                kwargs.get("target", ""),
                kwargs.get("timeout", 300),
            ),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            result = await fn()
            ingest_output("subdomain_discovery", action, result, self._target_store)
            return result
        except Exception as exc:
            return f"subdomain_discovery error ({action}): {exc}"

    async def _run(self, *args: str, timeout: int = 120) -> str:
        logger.info("Running: %s", " ".join(args))
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        result = await communicate_or_kill(proc, timeout)
        if result is None:
            return f"Command timed out after {timeout}s: {' '.join(args)}"
        stdout, stderr = result
        output = stdout.decode(errors="replace")
        if stderr:
            output += f"\n[stderr] {stderr.decode(errors='replace')}"
        return output.strip()

    async def subfinder(self, target: str, timeout: int = 120) -> str:
        args = ["subfinder", "-d", target, "-silent", "-json"]
        return await self._run(*args, timeout=timeout)

    async def amass_passive(self, target: str, timeout: int = 300) -> str:
        args = ["amass", "enum", "-passive", "-d", target, "-json", "-"]
        return await self._run(*args, timeout=timeout)
