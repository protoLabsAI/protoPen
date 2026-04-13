"""Vulnerability scanning tool — nikto, nuclei, nmap NSE."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class VulnScanTool(BasePentestTool):
    """Wrapper for general vulnerability scanning tools."""

    name = "vuln_scan"
    description = (
        "Vulnerability scanning — nikto web server scanner, nuclei template "
        "engine, nmap NSE vulnerability scripts."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "nikto_scan": {
            "cmd": [
                "nikto", "-h", "{target}",
                "-Format", "json", "-output", "-",
            ],
            "timeout": 300,
            "description": "Nikto web server vulnerability scan",
        },
        "nuclei_scan": {
            "cmd": [
                "nuclei", "-u", "{target}",
                "-severity", "medium,high,critical",
                "-json", "-silent",
            ],
            "timeout": 300,
            "description": "Nuclei vulnerability scan with default templates",
        },
        "nuclei_tagged": {
            "cmd": [
                "nuclei", "-u", "{target}",
                "-tags", "{tags}",
                "-json", "-silent",
            ],
            "timeout": 300,
            "description": "Nuclei scan with specific template tags",
        },
        "nse_vuln": {
            "cmd": [
                "nmap", "--script", "vuln",
                "-p", "{ports}", "{target}",
                "-oX", "-",
            ],
            "timeout": 180,
            "description": "Nmap NSE vuln category scripts",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        ports: str = "",
        tags: str = "",
        timeout: int = 300,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        if action == "nse_vuln" and not ports and self._target_store:
            stored_ports = self._target_store.get_ports(target)
            if stored_ports:
                ports = ",".join(str(p) for p in stored_ports)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(target=target, ports=ports, tags=tags)
            for c in spec["cmd"]
        ]
        effective_timeout = min(timeout, spec.get("timeout", 300))

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target,
        )
