"""SQL injection testing tool — sqlmap wrapper."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class SqlTestTool(BasePentestTool):
    """Wrapper for SQL injection testing via sqlmap."""

    name = "sql_test"
    description = (
        "SQL injection testing — sqlmap automated detection and exploitation "
        "of SQL injection flaws."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "sqli_detect": {
            "cmd": [
                "sqlmap", "-u", "{url}",
                "--batch", "--level", "3", "--risk", "2",
                "--output-dir=/tmp/sqlmap",
            ],
            "timeout": 300,
            "description": "SQL injection detection scan",
        },
        "sqli_forms": {
            "cmd": [
                "sqlmap", "-u", "{url}",
                "--forms", "--batch", "--level", "3",
                "--output-dir=/tmp/sqlmap",
            ],
            "timeout": 300,
            "description": "SQL injection scan on form parameters",
        },
        "sqli_dbs": {
            "cmd": [
                "sqlmap", "-u", "{url}",
                "--batch", "--dbs",
                "--output-dir=/tmp/sqlmap",
            ],
            "timeout": 300,
            "description": "Enumerate databases via confirmed SQLi",
        },
        "sqli_tables": {
            "cmd": [
                "sqlmap", "-u", "{url}",
                "--batch", "-D", "{database}", "--tables",
                "--output-dir=/tmp/sqlmap",
            ],
            "timeout": 300,
            "description": "Enumerate tables in a database",
        },
    }

    async def execute(
        self,
        action: str,
        url: str = "",
        database: str = "",
        timeout: int = 300,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(url=url, database=database)
            for c in spec["cmd"]
        ]
        effective_timeout = min(timeout, spec.get("timeout", 300))

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=url,
        )
