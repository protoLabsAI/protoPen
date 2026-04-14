"""Data exfiltration tool — controlled extraction for evidence collection."""

from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class DataExfilTool(BasePentestTool):
    """Wrapper for controlled data exfiltration / evidence gathering."""

    name = "data_exfil"
    description = (
        "Data exfiltration — controlled extraction of files and data for evidence collection during engagements."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "scp_download": {
            "cmd": [
                "scp",
                "{username}@{target}:{remote_path}",
                "{local_path}",
            ],
            "timeout": 120,
            "description": "Download file via SCP",
        },
        "smb_download": {
            "cmd": [
                "smbclient",
                "//{target}/{share}",
                "-U",
                "{username}%{password}",
                "-c",
                "get {remote_path} {local_path}",
            ],
            "timeout": 120,
            "description": "Download file from SMB share",
        },
        "http_exfil": {
            "cmd": [
                "curl",
                "-s",
                "-o",
                "{local_path}",
                "{url}",
            ],
            "timeout": 60,
            "description": "Download file via HTTP/HTTPS",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        username: str = "",
        password: str = "",
        share: str = "",
        remote_path: str = "",
        local_path: str = "/tmp/exfil",
        url: str = "",
        timeout: int = 120,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target,
                username=username,
                password=password,
                share=share,
                remote_path=remote_path,
                local_path=local_path,
                url=url,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", 120)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target or url,
        )
