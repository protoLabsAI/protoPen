"""Telecom security testing — SIP (SIPVicious) + IMSI / GSM detection (gr-gsm).

Scoped to the actions backed by real tools. Earlier GTP / SS7 / Diameter /
STIR-SHAKEN actions were removed (they called binaries that don't exist; see
protopen-3k1).
"""

from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class TelecomAttackTool(BasePentestTool):
    """Telecom protocol security testing — SIP enum/cracking + IMSI detection."""

    name = "telecom_attack"
    description = (
        "Telecom security — SIP enumeration/cracking (SIPVicious svmap/svcrack/"
        "svwar) and IMSI catcher / GSM base-station detection (gr-gsm)."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "sip_enum": {
            "cmd": ["sipvicious_svmap", "{target}"],
            "timeout": 60,
            "description": "SIP device enumeration (SIPVicious svmap)",
        },
        "sip_crack": {
            "cmd": ["sipvicious_svcrack", "-u", "{username}", "-r", "{crack_range}", "{target}"],
            "timeout": 120,
            "description": "SIP credential cracking (SIPVicious svcrack; numeric range)",
        },
        "sip_flood_test": {
            "cmd": ["sipvicious_svwar", "-e", "{extension_range}", "{target}"],
            "timeout": 60,
            "description": "SIP extension enumeration via REGISTER flood (SIPVicious svwar)",
        },
        "imsi_detect": {
            "cmd": ["grgsm_scanner", "--args", "{device_args}"],
            "timeout": 30,
            "description": "Scan for GSM base stations / IMSI catcher detection",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        username: str = "admin",
        crack_range: str = "1000-9999",
        extension_range: str = "100-999",
        device_args: str = "rtl=0",
        timeout: int = 60,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            str(c).format(
                target=target,
                username=username,
                crack_range=crack_range,
                extension_range=extension_range,
                device_args=device_args,
                timeout=timeout,
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
