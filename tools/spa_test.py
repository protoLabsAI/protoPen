"""SPA security testing — route bypass, state inspection, postMessage, DOM XSS, source maps."""

from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class SPATestTool(BasePentestTool):
    """SPA security testing — route bypass, state inspection, postMessage, DOM XSS, source maps."""

    name = "spa_test"
    description = (
        "Single-page application security testing — client-side route bypass, "
        "state store inspection, postMessage scanning, token leakage auditing, "
        "DOM XSS detection, and JavaScript source map checks."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "route_bypass": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.spa_route_bypass",
                "--url",
                "{target}",
                "--routes-file",
                "{routes_file}",
                "--output-json",
            ],
            "timeout": 60,
            "description": "Test SPA client-side route guard bypass",
        },
        "state_inspect": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.spa_state",
                "--url",
                "{target}",
                "--store-type",
                "{store_type}",
                "--output-json",
            ],
            "timeout": 60,
            "description": "Inspect client-side state stores for sensitive data",
        },
        "postmessage_scan": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.postmessage_scan",
                "--url",
                "{target}",
                "--output-json",
            ],
            "timeout": 60,
            "description": "Scan for insecure postMessage handlers",
        },
        "token_leakage_audit": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.token_leakage",
                "--url",
                "{target}",
                "--check-localstorage",
                "--check-url-fragments",
                "--output-json",
            ],
            "timeout": 60,
            "description": "Audit for token leakage in localStorage and URL fragments",
        },
        "dom_xss_scan": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.dom_xss",
                "--url",
                "{target}",
                "--output-json",
            ],
            "timeout": 60,
            "description": "Scan for DOM-based cross-site scripting vulnerabilities",
        },
        "js_source_map_check": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.sourcemap_check",
                "--url",
                "{target}",
                "--output-json",
            ],
            "timeout": 60,
            "description": "Check for exposed JavaScript source maps",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        routes_file: str = "",
        store_type: str = "redux",
        timeout: int = 60,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target,
                routes_file=routes_file,
                store_type=store_type,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", timeout)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target,
        )
