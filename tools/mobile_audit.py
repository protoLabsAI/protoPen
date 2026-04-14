"""Mobile application security testing — APK/IPA analysis, Frida hooking, IPC auditing."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class MobileAuditTool(BasePentestTool):
    """Mobile application security testing — APK/IPA analysis, Frida hooking, IPC auditing."""

    name = "mobile_audit"
    description = (
        "Mobile application security testing — APK/IPA decompilation, static "
        "analysis, dynamic instrumentation with Frida, SSL pinning bypass, "
        "IPC auditing, and keychain extraction."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "apk_decompile": {
            "cmd": ["apktool", "d", "{target}", "-o", "{output_dir}/decompiled", "-f"],
            "timeout": 120,
            "description": "Decompile APK with apktool for static review",
        },
        "static_analysis": {
            "cmd": ["mobsf-cli", "scan", "--file", "{target}", "--type", "apk", "--output-json"],
            "timeout": 120,
            "description": "Run MobSF static analysis on mobile application",
        },
        "jadx_decompile": {
            "cmd": ["jadx", "--deobf", "--output-dir", "{output_dir}/jadx", "{target}"],
            "timeout": 120,
            "description": "Decompile APK to Java source with jadx",
        },
        "drozer_scan": {
            "cmd": [
                "drozer", "console", "connect",
                "--command", "run scanner.provider.finduris -a {package_name}",
                "--server", "{target}",
            ],
            "timeout": 120,
            "description": "Scan content providers for exposed URIs with drozer",
        },
        "frida_hook": {
            "cmd": ["frida", "-U", "-l", "{script_path}", "-f", "{package_name}", "--no-pause"],
            "timeout": 120,
            "description": "Attach Frida hook script to running mobile application",
        },
        "ssl_pinning_bypass": {
            "cmd": [
                "objection", "-g", "{package_name}", "explore",
                "--startup-command", "android sslpinning disable",
            ],
            "timeout": 120,
            "description": "Bypass SSL certificate pinning via objection",
        },
        "ipc_audit": {
            "cmd": [
                "drozer", "console", "connect",
                "--command", "run app.activity.info -a {package_name}",
                "--server", "{target}",
            ],
            "timeout": 120,
            "description": "Audit IPC components (activities, services, receivers)",
        },
        "keychain_dump": {
            "cmd": [
                "objection", "-g", "{package_name}", "explore",
                "--startup-command", "android keystore list",
            ],
            "timeout": 120,
            "description": "Dump Android keystore entries via objection",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        package_name: str = "",
        script_path: str = "",
        output_dir: str = "/tmp/mobile_audit",
        timeout: int = 120,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target,
                package_name=package_name,
                script_path=script_path,
                output_dir=output_dir,
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
