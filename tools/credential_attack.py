"""Credential attack tool — hydra brute force, password spraying."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class CredentialAttackTool(BasePentestTool):
    """Wrapper for credential attack tools — hydra, medusa."""

    name = "credential_attack"
    description = (
        "Credential attacks — hydra brute force, password spraying, "
        "SSH/FTP/HTTP/SMB login testing."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "hydra_brute": {
            "cmd": [
                "hydra",
                "-l", "{username}",
                "-P", "{wordlist}",
                "{target}",
                "{service}",
                "-t", "{threads}",
                "-f",
            ],
            "timeout": 600,
            "description": "Brute force a single user with a password list",
        },
        "hydra_spray": {
            "cmd": [
                "hydra",
                "-L", "{userlist}",
                "-p", "{password}",
                "{target}",
                "{service}",
                "-t", "{threads}",
                "-f",
            ],
            "timeout": 600,
            "description": "Password spray a single password across user list",
        },
        "hydra_combo": {
            "cmd": [
                "hydra",
                "-C", "{combolist}",
                "{target}",
                "{service}",
                "-t", "{threads}",
                "-f",
            ],
            "timeout": 600,
            "description": "Combo list attack (user:pass format)",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        service: str = "ssh",
        username: str = "",
        password: str = "",
        wordlist: str = "",
        userlist: str = "",
        combolist: str = "",
        threads: int = 4,
        timeout: int = 600,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target, service=service, username=username,
                password=password, wordlist=wordlist, userlist=userlist,
                combolist=combolist, threads=str(threads),
            )
            for c in spec["cmd"]
        ]
        effective_timeout = min(timeout, spec.get("timeout", 600))

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target,
        )
