"""DNS enumeration tool — dig, nslookup, zone transfers, reverse lookups."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from tools.parsers import ingest_output
from tools._subprocess import communicate_or_kill
from tools._tool_base import Tool

logger = logging.getLogger(__name__)


class DnsEnumTool(Tool):
    """DNS enumeration — dig, nslookup, zone transfers, reverse lookups, subdomain brute force."""

    def __init__(self, workspace: str = "/tmp/protopen"):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None

    @property
    def name(self) -> str:
        return "dns_enum"

    @property
    def description(self) -> str:
        return (
            "DNS enumeration tools. Query DNS records (dig, nslookup), "
            "attempt zone transfers (AXFR), reverse lookups, and subdomain brute force."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": ["dig_query", "nslookup", "zone_transfer", "reverse_lookup", "dns_brute"],
                },
                "target": {"type": "string", "description": "Domain or IP to query"},
                "record_type": {"type": "string", "description": "DNS record type (default A)"},
                "nameserver": {"type": "string", "description": "DNS server to query"},
                "wordlist": {"type": "string", "description": "Wordlist for dns_brute"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 30)"},
            },
            "required": ["action", "target"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        dispatch = {
            "dig_query": lambda: self.dig_query(
                kwargs.get("target", ""),
                kwargs.get("record_type", "A"),
                kwargs.get("nameserver", ""),
                kwargs.get("timeout", 30),
            ),
            "nslookup": lambda: self.nslookup(
                kwargs.get("target", ""),
                kwargs.get("record_type", "A"),
                kwargs.get("timeout", 30),
            ),
            "zone_transfer": lambda: self.zone_transfer(
                kwargs.get("target", ""),
                kwargs.get("nameserver", ""),
                kwargs.get("timeout", 60),
            ),
            "reverse_lookup": lambda: self.reverse_lookup(
                kwargs.get("target", ""),
                kwargs.get("nameserver", ""),
                kwargs.get("timeout", 30),
            ),
            "dns_brute": lambda: self.dns_brute(
                kwargs.get("target", ""),
                kwargs.get("wordlist", "/usr/share/wordlists/dns/subdomains-top1million-5000.txt"),
                kwargs.get("timeout", 300),
            ),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            result = await fn()
            ingest_output("dns_enum", action, result, self._target_store)
            return result
        except Exception as exc:
            return f"dns_enum error ({action}): {exc}"

    async def _run(self, *args: str, timeout: int = 30) -> str:
        logger.info("Running: %s", " ".join(args))
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            binary = args[0] if args else "unknown"
            logger.warning("dns_enum: binary '%s' not found", binary)
            return json.dumps({"error": f"{binary} not found", "tool": "dns_enum"})
        result = await communicate_or_kill(proc, timeout)
        if result is None:
            return f"Command timed out after {timeout}s: {' '.join(args)}"
        stdout, stderr = result
        output = stdout.decode(errors="replace")
        if stderr:
            output += f"\n[stderr] {stderr.decode(errors='replace')}"
        return output.strip()

    async def dig_query(self, target: str, record_type: str = "A", nameserver: str = "", timeout: int = 30) -> str:
        args = ["dig"]
        if nameserver:
            args.append(f"@{nameserver}")
        args.extend([target, record_type, "+noall", "+answer"])
        return await self._run(*args, timeout=timeout)

    async def nslookup(self, target: str, record_type: str = "A", timeout: int = 30) -> str:
        args = ["nslookup", f"-type={record_type}", target]
        return await self._run(*args, timeout=timeout)

    async def zone_transfer(self, target: str, nameserver: str = "", timeout: int = 60) -> str:
        ns = nameserver or target
        args = ["dig", f"@{ns}", target, "AXFR"]
        return await self._run(*args, timeout=timeout)

    async def reverse_lookup(self, target: str, nameserver: str = "", timeout: int = 30) -> str:
        args = ["dig"]
        if nameserver:
            args.append(f"@{nameserver}")
        args.extend(["-x", target, "+short"])
        return await self._run(*args, timeout=timeout)

    async def dns_brute(
        self,
        target: str,
        wordlist: str = "/usr/share/wordlists/dns/subdomains-top1million-5000.txt",
        timeout: int = 300,
    ) -> str:
        args = ["dnsrecon", "-d", target, "-t", "brt", "-D", wordlist]
        return await self._run(*args, timeout=timeout)
