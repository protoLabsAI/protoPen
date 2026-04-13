"""Authentication & authorization testing — BOLA/IDOR, privilege escalation, session management."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class AuthTestTool(BasePentestTool):
    """Wrapper for authentication and authorization testing."""

    name = "auth_test"
    description = (
        "Authentication & authorization testing — BOLA/IDOR detection, "
        "privilege escalation checks, token manipulation, session testing."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "idor_check": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "results=[]; ids={test_ids}; "
                "[results.append({{'id':i,'status':r.status_code,'length':len(r.text),'accessible':r.status_code==200}}) "
                "for i in ids if (r:=requests.get('{url}'.replace('{id_param}',str(i)),"
                "headers={headers},timeout=5)) or True]; "
                "print(json.dumps({{'url':'{url}','results':results,"
                "'vulnerable':any(r['accessible'] for r in results)}}))",
            ],
            "timeout": 60,
            "description": "Test for IDOR/BOLA by iterating object IDs",
        },
        "privesc_horizontal": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "r1=requests.get('{url}',headers={user_a_headers},timeout=5); "
                "r2=requests.get('{url}',headers={user_b_headers},timeout=5); "
                "print(json.dumps({{'url':'{url}',"
                "'user_a_status':r1.status_code,'user_a_length':len(r1.text),"
                "'user_b_status':r2.status_code,'user_b_length':len(r2.text),"
                "'same_response':r1.text==r2.text,"
                "'potential_vuln':r2.status_code==200}}))",
            ],
            "timeout": 30,
            "description": "Test horizontal privilege escalation (user A accessing user B's resources)",
        },
        "privesc_vertical": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "r=requests.get('{admin_url}',headers={low_priv_headers},timeout=5); "
                "print(json.dumps({{'admin_url':'{admin_url}',"
                "'status':r.status_code,'length':len(r.text),"
                "'accessible':r.status_code==200,"
                "'vulnerability':'Vertical privilege escalation' if r.status_code==200 else 'Properly restricted'}}))",
            ],
            "timeout": 30,
            "description": "Test vertical privilege escalation (low-priv user accessing admin endpoints)",
        },
        "session_fixation": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "s=requests.Session(); "
                "r1=s.get('{url}',timeout=5); "
                "pre_cookies=dict(s.cookies); "
                "r2=s.post('{login_url}',data={login_data},timeout=5,allow_redirects=False); "
                "post_cookies=dict(s.cookies); "
                "fixed=[k for k in pre_cookies if k in post_cookies and pre_cookies[k]==post_cookies[k]]; "
                "print(json.dumps({{'pre_login_cookies':pre_cookies,'post_login_cookies':post_cookies,"
                "'fixed_cookies':fixed,'vulnerable':len(fixed)>0}}))",
            ],
            "timeout": 30,
            "description": "Test for session fixation (cookies unchanged after login)",
        },
        "token_replay": {
            "cmd": [
                "python3", "-c",
                "import requests,json,time; "
                "r1=requests.get('{url}',headers={headers},timeout=5); "
                "time.sleep({delay}); "
                "r2=requests.get('{url}',headers={headers},timeout=5); "
                "print(json.dumps({{'first_status':r1.status_code,'second_status':r2.status_code,"
                "'both_succeeded':r1.status_code==200 and r2.status_code==200,"
                "'note':'If both succeed, token replay is possible'}}))",
            ],
            "timeout": 60,
            "description": "Test token replay — send same auth token after delay",
        },
    }

    async def execute(
        self,
        action: str,
        url: str = "",
        admin_url: str = "",
        login_url: str = "",
        headers: str = "{}",
        user_a_headers: str = "{}",
        user_b_headers: str = "{}",
        low_priv_headers: str = "{}",
        login_data: str = "{}",
        test_ids: str = "[1,2,3,100,999]",
        id_param: str = "FUZZ",
        delay: int = 5,
        timeout: int = 60,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                url=url, admin_url=admin_url, login_url=login_url,
                headers=headers, user_a_headers=user_a_headers,
                user_b_headers=user_b_headers, low_priv_headers=low_priv_headers,
                login_data=login_data, test_ids=test_ids, id_param=id_param,
                delay=delay,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = min(timeout, spec.get("timeout", 60))

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=url or admin_url,
        )
