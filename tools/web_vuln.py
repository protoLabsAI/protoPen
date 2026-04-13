"""Web vulnerability testing tool — XSS, SSRF, open redirect, CORS."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class WebVulnTool(BasePentestTool):
    """Wrapper for web application vulnerability testing tools."""

    name = "web_vuln"
    description = (
        "Web vulnerability testing — XSS detection (dalfox), SSRF testing, "
        "open redirect checking, CORS misconfiguration testing."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "xss_scan": {
            "cmd": ["dalfox", "url", "{url}", "--silence", "--format", "json"],
            "timeout": 180,
            "description": "XSS vulnerability scan with dalfox",
        },
        "cors_check": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "r=requests.get('{url}',headers={{'Origin':'https://evil.com'}}); "
                "print(json.dumps({{'url':'{url}',"
                "'acao':r.headers.get('Access-Control-Allow-Origin',''),"
                "'vulnerable':r.headers.get('Access-Control-Allow-Origin','')in"
                "('https://evil.com','*')}}))",
            ],
            "timeout": 30,
            "description": "Check CORS misconfiguration",
        },
        "redirect_check": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "r=requests.get('{url}',allow_redirects=False); "
                "print(json.dumps({{'url':'{url}','status':r.status_code,"
                "'location':r.headers.get('Location','')}}))",
            ],
            "timeout": 30,
            "description": "Check for open redirect",
        },
    }

    async def execute(
        self,
        action: str,
        url: str = "",
        timeout: int = 180,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [c.format(url=url) for c in spec["cmd"]]
        effective_timeout = spec.get("timeout", 180)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=url,
        )
