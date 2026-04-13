"""CVE matching tool — cross-reference services with known CVEs."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class CveMatchTool(BasePentestTool):
    """Cross-reference discovered services/versions against CVE databases."""

    name = "cve_match"
    description = (
        "CVE matching — search for known vulnerabilities by product/version, "
        "cross-reference nmap service versions with CVEs."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "cve_search": {
            "cmd": ["searchsploit", "--json", "{query}"],
            "timeout": 30,
            "description": "Search exploitdb for known CVEs/exploits",
        },
        "cve_nmap": {
            "cmd": [
                "nmap", "--script", "vulners",
                "-sV", "-p", "{ports}", "{target}",
                "-oX", "-",
            ],
            "timeout": 120,
            "description": "NSE vulners script against discovered services",
        },
        "cve_nuclei": {
            "cmd": [
                "nuclei", "-u", "{target}",
                "-t", "cves/",
                "-severity", "medium,high,critical",
                "-json", "-silent",
            ],
            "timeout": 300,
            "description": "Nuclei CVE templates against target",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        query: str = "",
        ports: str = "",
        timeout: int = 120,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        if action == "cve_nmap" and not ports and self._target_store:
            stored_ports = self._target_store.get_ports(target)
            if stored_ports:
                ports = ",".join(str(p) for p in stored_ports)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(target=target, query=query, ports=ports)
            for c in spec["cmd"]
        ]
        effective_timeout = min(timeout, spec.get("timeout", 120))

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target or query,
        )
