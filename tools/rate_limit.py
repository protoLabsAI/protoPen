"""Rate limit testing tool — detect and test bypass for rate limiting."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class RateLimitTool(BasePentestTool):
    """Wrapper for rate limit detection and bypass testing."""

    name = "rate_limit"
    description = (
        "Rate limit testing — detect rate limits, test bypass techniques "
        "(header rotation, IP spoofing headers, path manipulation)."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "rate_detect": {
            "cmd": [
                "python3", "-c",
                "import requests,json,time; "
                "results=[]; "
                "for i in range({count}): "
                "  r=requests.get('{url}',headers={headers},timeout=5); "
                "  results.append({{'request':i+1,'status':r.status_code,"
                "'retry_after':r.headers.get('Retry-After',''),"
                "'rate_limit_remaining':r.headers.get('X-RateLimit-Remaining','')}}); "
                "  time.sleep({interval}); "
                "limited=[r for r in results if r['status']==429]; "
                "print(json.dumps({{'total_requests':{count},'rate_limited':len(limited),"
                "'first_limited':limited[0]['request'] if limited else None,"
                "'results':results}}))",
            ],
            "timeout": 120,
            "description": "Detect rate limiting by sending sequential requests",
        },
        "rate_bypass_headers": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "bypass_headers=['X-Forwarded-For','X-Real-IP','X-Originating-IP',"
                "'X-Client-IP','X-Remote-IP','X-Remote-Addr','True-Client-IP',"
                "'CF-Connecting-IP','X-Forwarded-Host']; "
                "results=[]; "
                "for h in bypass_headers: "
                "  hdrs={{**{headers},h:'{spoof_ip}'}}; "
                "  r=requests.get('{url}',headers=hdrs,timeout=5); "
                "  results.append({{'header':h,'status':r.status_code,"
                "'bypassed':r.status_code!=429}}); "
                "print(json.dumps({{'url':'{url}','spoof_ip':'{spoof_ip}',"
                "'results':results,"
                "'bypassed_with':[r['header'] for r in results if r['bypassed']]}}))",
            ],
            "timeout": 60,
            "description": "Test rate limit bypass via IP spoofing headers",
        },
        "rate_bypass_path": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "variants=['{url}','{url}/','{url}/.','{url}/./','%2f'.join('{url}'.rsplit('/',1)),"
                "'{url}?_=1','{url}#x']; "
                "results=[]; "
                "[results.append({{'url':v,'status':r.status_code,'bypassed':r.status_code!=429}}) "
                "for v in variants if (r:=requests.get(v,headers={headers},timeout=5)) or True]; "
                "print(json.dumps({{'results':results,"
                "'bypassed_with':[r['url'] for r in results if r['bypassed']]}}))",
            ],
            "timeout": 30,
            "description": "Test rate limit bypass via URL path manipulation",
        },
    }

    async def execute(
        self,
        action: str,
        url: str = "",
        headers: str = "{}",
        count: int = 50,
        interval: float = 0.1,
        spoof_ip: str = "1.2.3.4",
        timeout: int = 120,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                url=url, headers=headers, count=count,
                interval=interval, spoof_ip=spoof_ip,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", 120)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=url,
        )
