"""Cleanup tool — remove artifacts, persistence, and evidence from target."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class CleanupTool(BasePentestTool):
    """Wrapper for post-engagement cleanup of artifacts and persistence."""

    name = "cleanup"
    description = (
        "Cleanup — remove engagement artifacts, persistence mechanisms, "
        "and other traces from target systems."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "remove_ssh_key": {
            "cmd": [
                "bash", "-c",
                "sed -i '/{key_fingerprint}/d' ~/.ssh/authorized_keys && echo 'Key removed'",
            ],
            "timeout": 10,
            "description": "Remove a planted SSH key",
        },
        "remove_cron": {
            "cmd": [
                "bash", "-c",
                "crontab -l 2>/dev/null | grep -v '{pattern}' | crontab - && echo 'Cron removed'",
            ],
            "timeout": 10,
            "description": "Remove a planted cron job",
        },
        "remove_files": {
            "cmd": [
                "bash", "-c",
                "rm -f {file_paths} && echo 'Files removed'",
            ],
            "timeout": 10,
            "description": "Remove specified files",
        },
        "cleanup_report": {
            "cmd": [
                "bash", "-c",
                "echo '=== Cleanup Report ===' && "
                "echo 'Cron entries:' && crontab -l 2>/dev/null | wc -l && "
                "echo 'SSH keys:' && wc -l < ~/.ssh/authorized_keys 2>/dev/null && "
                "echo 'Temp files:' && ls /tmp/exfil* 2>/dev/null | wc -l",
            ],
            "timeout": 10,
            "description": "Generate cleanup status report",
        },
    }

    async def execute(
        self,
        action: str,
        key_fingerprint: str = "",
        pattern: str = "",
        file_paths: str = "",
        timeout: int = 30,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                key_fingerprint=key_fingerprint,
                pattern=pattern,
                file_paths=file_paths,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = min(timeout, spec.get("timeout", 30))

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint="localhost",
        )
