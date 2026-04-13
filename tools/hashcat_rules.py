"""Hash cracking tool — hashcat and john the ripper."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class HashcatRulesTool(BasePentestTool):
    """Wrapper for hash cracking — hashcat, john the ripper."""

    name = "hashcat_rules"
    description = (
        "Hash cracking — hashcat rule-based attacks, john the ripper, "
        "hash identification."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "hash_identify": {
            "cmd": ["hashid", "-j", "{hash}"],
            "timeout": 10,
            "description": "Identify hash type",
        },
        "hashcat_dict": {
            "cmd": [
                "hashcat",
                "-m", "{mode}",
                "{hashfile}",
                "{wordlist}",
                "--force", "--quiet",
            ],
            "timeout": 600,
            "description": "Dictionary attack with hashcat",
        },
        "hashcat_rules": {
            "cmd": [
                "hashcat",
                "-m", "{mode}",
                "{hashfile}",
                "{wordlist}",
                "-r", "{rulefile}",
                "--force", "--quiet",
            ],
            "timeout": 600,
            "description": "Rule-based attack with hashcat",
        },
        "john_crack": {
            "cmd": [
                "john",
                "--wordlist={wordlist}",
                "--format={format}",
                "{hashfile}",
            ],
            "timeout": 600,
            "description": "Crack hashes with john the ripper",
        },
        "john_show": {
            "cmd": ["john", "--show", "{hashfile}"],
            "timeout": 10,
            "description": "Show cracked passwords from john pot",
        },
    }

    async def execute(
        self,
        action: str,
        hash: str = "",
        hashfile: str = "",
        wordlist: str = "",
        rulefile: str = "/usr/share/hashcat/rules/best64.rule",
        mode: str = "0",
        format: str = "",
        timeout: int = 600,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                hash=hash, hashfile=hashfile, wordlist=wordlist,
                rulefile=rulefile, mode=mode, format=format,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", 600)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=hashfile or hash,
        )
