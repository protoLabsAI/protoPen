"""Web content enumeration — enhanced gobuster/ffuf with recursive mode."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from tools.parsers import ingest_output
from tools._subprocess import communicate_or_kill
from tools._tool_base import Tool

logger = logging.getLogger(__name__)


class WebEnumTool(Tool):
    """Web content enumeration — gobuster dir/vhost, ffuf fuzz/param."""

    def __init__(self, workspace: str = "/tmp/protopen"):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None

    @property
    def name(self) -> str:
        return "web_enum"

    @property
    def description(self) -> str:
        return (
            "Web content enumeration. Directory brute force (gobuster, ffuf), "
            "virtual host discovery, parameter fuzzing, recursive scanning."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": ["gobuster_dir", "gobuster_vhost", "ffuf_fuzz", "ffuf_param"],
                },
                "url": {"type": "string", "description": "Target URL"},
                "wordlist": {"type": "string", "description": "Wordlist path"},
                "extensions": {"type": "string", "description": "File extensions (e.g. php,html,js)"},
                "threads": {"type": "integer", "description": "Thread count (default 10)"},
                "recursive": {"type": "boolean", "description": "Enable recursion (ffuf only)"},
                "depth": {"type": "integer", "description": "Recursion depth (default 2)"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 120)"},
            },
            "required": ["action", "url"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        url = kwargs.get("url", "")
        wl = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        ext = kwargs.get("extensions", "")
        threads = kwargs.get("threads", 10)
        recursive = kwargs.get("recursive", False)
        depth = kwargs.get("depth", 2)
        timeout = kwargs.get("timeout", 120)

        dispatch = {
            "gobuster_dir": lambda: self.gobuster_dir(url, wl, ext, threads, timeout),
            "gobuster_vhost": lambda: self.gobuster_vhost(url, wl, timeout),
            "ffuf_fuzz": lambda: self.ffuf_fuzz(url, wl, ext, threads, recursive, depth, timeout),
            "ffuf_param": lambda: self.ffuf_param(url, wl, timeout),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            result = await fn()
            ingest_output("web_enum", action, result, self._target_store)
            return result
        except Exception as exc:
            return f"web_enum error ({action}): {exc}"

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

    async def gobuster_dir(
        self, url: str, wordlist: str, extensions: str = "", threads: int = 10, timeout: int = 120
    ) -> str:
        args = [
            "gobuster",
            "dir",
            "-u",
            url,
            "-w",
            wordlist,
            "-t",
            str(threads),
            "-q",
            "--follow-redirect",
            "--no-error",
            "-b",
            "301,302,404",
        ]
        if extensions:
            args.extend(["-x", extensions])
        return await self._run(*args, timeout=timeout)

    async def gobuster_vhost(self, url: str, wordlist: str, timeout: int = 120) -> str:
        args = ["gobuster", "vhost", "-u", url, "-w", wordlist, "-q"]
        return await self._run(*args, timeout=timeout)

    async def ffuf_fuzz(
        self,
        url: str,
        wordlist: str,
        extensions: str = "",
        threads: int = 10,
        recursive: bool = False,
        depth: int = 2,
        timeout: int = 120,
    ) -> str:
        fuzz_url = url.rstrip("/") + "/FUZZ"
        args = ["ffuf", "-u", fuzz_url, "-w", wordlist, "-t", str(threads), "-of", "json", "-o", "-"]
        if extensions:
            args.extend(["-e", extensions])
        if recursive:
            args.extend(["-recursion", "-recursion-depth", str(depth)])
        return await self._run(*args, timeout=timeout)

    async def ffuf_param(self, url: str, wordlist: str, timeout: int = 120) -> str:
        args = ["ffuf", "-u", url, "-w", wordlist, "-of", "json", "-o", "-"]
        return await self._run(*args, timeout=timeout)
