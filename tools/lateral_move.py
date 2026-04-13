"""Lateral movement tool — psexec, wmi, evil-winrm, ssh pivoting."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class LateralMoveTool(BasePentestTool):
    """Wrapper for lateral movement tools."""

    name = "lateral_move"
    description = (
        "Lateral movement — psexec, evil-winrm, SSH pivoting, "
        "pass-the-hash attacks."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "psexec": {
            "cmd": [
                "impacket-psexec",
                "{domain}/{username}:{password}@{target}",
            ],
            "timeout": 60,
            "description": "PsExec via impacket",
        },
        "wmiexec": {
            "cmd": [
                "impacket-wmiexec",
                "{domain}/{username}:{password}@{target}",
            ],
            "timeout": 60,
            "description": "WMI execution via impacket",
        },
        "evil_winrm": {
            "cmd": [
                "evil-winrm",
                "-i", "{target}",
                "-u", "{username}",
                "-p", "{password}",
            ],
            "timeout": 60,
            "description": "Evil-WinRM shell",
        },
        "pth_winrm": {
            "cmd": [
                "evil-winrm",
                "-i", "{target}",
                "-u", "{username}",
                "-H", "{hash}",
            ],
            "timeout": 60,
            "description": "Pass-the-hash via evil-winrm",
        },
        "ssh_pivot": {
            "cmd": [
                "ssh", "-D", "{socks_port}",
                "-N", "-f",
                "{username}@{target}",
            ],
            "timeout": 30,
            "description": "SSH SOCKS proxy for pivoting",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        username: str = "",
        password: str = "",
        domain: str = ".",
        hash: str = "",
        socks_port: str = "1080",
        timeout: int = 60,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target, username=username, password=password,
                domain=domain, hash=hash, socks_port=socks_port,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", 60)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target,
        )
