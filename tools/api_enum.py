"""API discovery — OpenAPI/Swagger endpoint detection, REST enumeration."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from tools.parsers import ingest_output
from tools._subprocess import communicate_or_kill
from tools._tool_base import Tool

logger = logging.getLogger(__name__)

_SWAGGER_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/swagger/v1/swagger.json",
    "/v3/api-docs",
    "/.well-known/openapi.json",
]


class ApiEnumTool(Tool):
    """API discovery — Swagger/OpenAPI detection, endpoint brute force, method checking."""

    def __init__(self, workspace: str = "/tmp/protopen"):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None

    @property
    def name(self) -> str:
        return "api_enum"

    @property
    def description(self) -> str:
        return (
            "API enumeration. Swagger/OpenAPI discovery, endpoint brute force "
            "via ffuf, HTTP method enumeration per endpoint."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": ["swagger_scan", "endpoint_brute", "method_check"],
                },
                "url": {"type": "string", "description": "Target URL"},
                "wordlist": {"type": "string", "description": "Wordlist for endpoint_brute"},
                "methods": {"type": "string", "description": "Comma-separated HTTP methods"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 60)"},
            },
            "required": ["action", "url"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        url = kwargs.get("url", "")
        wl = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        methods = kwargs.get("methods", "GET,POST,PUT,DELETE,PATCH")
        timeout = kwargs.get("timeout", 60)

        dispatch = {
            "swagger_scan": lambda: self.swagger_scan(url, timeout),
            "endpoint_brute": lambda: self.endpoint_brute(url, wl, timeout),
            "method_check": lambda: self.method_check(url, methods, timeout),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            result = await fn()
            ingest_output("api_enum", action, result, self._target_store)
            return result
        except Exception as exc:
            return f"api_enum error ({action}): {exc}"

    async def _run(self, *args: str, timeout: int = 60) -> str:
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

    async def swagger_scan(self, url: str, timeout: int = 60) -> str:
        """Check common Swagger/OpenAPI paths via curl."""
        results = []
        base = url.rstrip("/")
        for path in _SWAGGER_PATHS:
            check_url = base + path
            out = await self._run(
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                check_url,
                timeout=10,
            )
            results.append(f"{path}: {out}")
        return "\n".join(results)

    async def endpoint_brute(self, url: str, wordlist: str, timeout: int = 120) -> str:
        fuzz_url = url.rstrip("/") + "/FUZZ"
        args = ["ffuf", "-u", fuzz_url, "-w", wordlist, "-mc", "200,201,301,302,401,403", "-of", "json", "-o", "-"]
        return await self._run(*args, timeout=timeout)

    async def method_check(self, url: str, methods: str = "GET,POST,PUT,DELETE,PATCH", timeout: int = 30) -> str:
        """Test which HTTP methods are allowed on a URL."""
        results = []
        for method in methods.split(","):
            m = method.strip()
            out = await self._run(
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "-X",
                m,
                url,
                timeout=10,
            )
            results.append(f"{m}: {out}")
        return "\n".join(results)
