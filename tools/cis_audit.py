"""Defensive scanning — CIS benchmarks, config audits, patch assessment, port baselines."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)

_SCRIPTS_DIR = Path(__file__).parent / "scripts"


class CisAuditTool(BasePentestTool):
    """Blue team defensive scanning and configuration auditing."""

    name = "cis_audit"
    description = (
        "Defensive scanning — CIS benchmark checks, SSH/TLS/firewall config audits, "
        "patch level assessment, open port baseline comparison."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "ssh_audit": {
            "cmd": ["python3", str(_SCRIPTS_DIR / "ssh_audit.py"), "{target}"],
            "timeout": 15,
            "description": "Audit SSH server configuration against CIS benchmarks",
        },
        "tls_audit": {
            "cmd": ["python3", str(_SCRIPTS_DIR / "tls_audit.py"), "{target}", "{port}"],
            "timeout": 15,
            "description": "Audit TLS/SSL configuration (protocol version, cipher strength, cert expiry)",
        },
        "firewall_audit": {
            "cmd": ["python3", str(_SCRIPTS_DIR / "firewall_audit.py")],
            "timeout": 15,
            "description": "Audit firewall rules and default policies",
        },
        "patch_check": {
            "cmd": ["python3", str(_SCRIPTS_DIR / "patch_check.py")],
            "timeout": 60,
            "description": "Check for pending security patches and updates",
        },
        "port_baseline": {
            "cmd": [
                "python3", str(_SCRIPTS_DIR / "port_baseline.py"),
                "{target}", "{expected_ports}", "{timeout}",
            ],
            "timeout": 300,
            "description": "Compare open ports against expected baseline",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "localhost",
        port: int = 443,
        expected_ports: str = "[22,80,443]",
        timeout: int = 60,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target, port=port,
                expected_ports=expected_ports, timeout=timeout,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = min(timeout, spec.get("timeout", 60))

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target,
        )
