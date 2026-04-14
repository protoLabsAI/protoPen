"""WebSocket security testing — auth bypass, CSWSH, message injection."""
from __future__ import annotations

import logging
import os
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)

_SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "scripts")


class WebSocketTestTool(BasePentestTool):
    """WebSocket security testing — authentication bypass, CSWSH, injection."""

    name = "websocket_test"
    description = (
        "WebSocket security testing — authentication bypass detection, "
        "Cross-Site WebSocket Hijacking (CSWSH), and message injection "
        "(SQLi, XSS, command injection, path traversal)."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "auth_bypass": {
            "cmd": [
                "python3",
                os.path.join(_SCRIPTS_DIR, "ws_auth_bypass.py"),
                "{url}", "{origin}", "{auth_token}",
            ],
            "timeout": 30,
            "description": "Test WebSocket endpoint for authentication bypass",
        },
        "cswsh": {
            "cmd": [
                "python3",
                os.path.join(_SCRIPTS_DIR, "ws_cswsh.py"),
                "{url}", "{origin}",
            ],
            "timeout": 60,
            "description": "Test for Cross-Site WebSocket Hijacking via Origin validation",
        },
        "injection": {
            "cmd": [
                "python3",
                os.path.join(_SCRIPTS_DIR, "ws_injection.py"),
                "{url}", "{origin}", "{categories}",
            ],
            "timeout": 120,
            "description": "Test WebSocket messages for injection vulnerabilities",
        },
    }

    async def execute(
        self,
        action: str,
        url: str = "ws://localhost:8080",
        origin: str = "",
        auth_token: str = "",
        categories: str = "",
        timeout: int = 60,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                url=url,
                origin=origin,
                auth_token=auth_token,
                categories=categories,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", timeout)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=url,
        )
