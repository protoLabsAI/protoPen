"""SSL/TLS analysis via testssl.sh."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from tools.parsers import ingest_output
from tools._tool_base import Tool

logger = logging.getLogger(__name__)


class SslAuditTool(Tool):
    """SSL/TLS analysis via testssl.sh."""

    def __init__(self, workspace: str = "/tmp/protopen"):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None

    @property
    def name(self) -> str:
        return "ssl_audit"

    @property
    def description(self) -> str:
        return "SSL/TLS audit via testssl.sh — protocols, ciphers, vulnerabilities, certificates."

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": [
                        "ssl_full_audit", "ssl_protocols", "ssl_ciphers",
                        "ssl_vulnerabilities", "ssl_certificates",
                    ],
                },
                "target": {"type": "string", "description": "host:port or URL"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 180)"},
            },
            "required": ["action", "target"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        target = kwargs.get("target", "")
        timeout = kwargs.get("timeout", 180)

        dispatch = {
            "ssl_full_audit": lambda: self.full_audit(target, timeout),
            "ssl_protocols": lambda: self.protocols(target, timeout),
            "ssl_ciphers": lambda: self.ciphers(target, timeout),
            "ssl_vulnerabilities": lambda: self.vulnerabilities(target, timeout),
            "ssl_certificates": lambda: self.certificates(target, timeout),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            result = await fn()
            ingest_output("ssl_audit", action, result, self._target_store)
            return result
        except Exception as exc:
            return f"ssl_audit error ({action}): {exc}"

    async def _run(self, *args: str, timeout: int = 180) -> str:
        logger.info("Running: %s", " ".join(args))
        import os
        env = os.environ.copy()
        # Use system openssl — testssl.sh's bundled binary crashes on SteamOS (glibc mismatch)
        env.setdefault("OPENSSL", "/usr/bin/openssl")
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
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

    async def full_audit(self, target: str, timeout: int = 180) -> str:
        return await self._run(
            "testssl.sh", "--jsonfile", "-", "--overwrite", target, timeout=timeout,
        )

    async def protocols(self, target: str, timeout: int = 60) -> str:
        return await self._run(
            "testssl.sh", "-p", "--jsonfile", "-", "--overwrite", target, timeout=timeout,
        )

    async def ciphers(self, target: str, timeout: int = 60) -> str:
        return await self._run(
            "testssl.sh", "-E", "--jsonfile", "-", "--overwrite", target, timeout=timeout,
        )

    async def vulnerabilities(self, target: str, timeout: int = 120) -> str:
        return await self._run(
            "testssl.sh", "-U", "--jsonfile", "-", "--overwrite", target, timeout=timeout,
        )

    async def certificates(self, target: str, timeout: int = 60) -> str:
        return await self._run(
            "testssl.sh", "-S", "--jsonfile", "-", "--overwrite", target, timeout=timeout,
        )
