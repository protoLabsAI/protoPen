"""WebSocket message injection / manipulation tester.

Sends crafted payloads through a WebSocket connection to test for
injection vulnerabilities (SQLi, XSS, command injection, path traversal).
"""
from __future__ import annotations

import asyncio
import json
import sys
import ssl


PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "' UNION SELECT null,null,null--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ],
    "command_injection": [
        "; ls -la /",
        "| cat /etc/passwd",
        "$(whoami)",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
}


async def main(url: str, origin: str, categories: str) -> None:
    try:
        import websockets
    except ImportError:
        print(json.dumps({"error": "websockets library not installed"}))
        return

    cats = [c.strip() for c in categories.split(",")] if categories else list(PAYLOADS.keys())

    results: dict = {
        "url": url,
        "tests": [],
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ssl_ctx = ctx if url.startswith("wss://") else None

    headers = {"Origin": origin} if origin else {}

    for cat in cats:
        payloads = PAYLOADS.get(cat, [])
        for payload in payloads:
            try:
                async with websockets.connect(
                    url, additional_headers=headers, ssl=ssl_ctx, open_timeout=10,
                ) as ws:
                    await ws.send(payload)
                    try:
                        resp = await asyncio.wait_for(ws.recv(), timeout=5)
                        # Check if payload is reflected back
                        reflected = payload.lower() in resp.lower()
                        # Check for error messages that leak info
                        error_leak = any(
                            kw in resp.lower()
                            for kw in ["sql", "syntax", "error", "exception", "stack", "traceback"]
                        )
                        severity = "info"
                        if reflected:
                            severity = "high"
                        elif error_leak:
                            severity = "medium"

                        results["tests"].append({
                            "test": "injection",
                            "category": cat,
                            "payload": payload,
                            "reflected": reflected,
                            "error_leak": error_leak,
                            "severity": severity,
                            "response_preview": resp[:300],
                        })
                    except asyncio.TimeoutError:
                        results["tests"].append({
                            "test": "injection",
                            "category": cat,
                            "payload": payload,
                            "severity": "info",
                            "detail": "No response (timeout)",
                        })
            except Exception as e:
                results["tests"].append({
                    "test": "injection",
                    "category": cat,
                    "payload": payload,
                    "severity": "info",
                    "detail": f"Connection error: {type(e).__name__}: {e}",
                })

    print(json.dumps(results))


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "ws://localhost:8080"
    origin = sys.argv[2] if len(sys.argv) > 2 else ""
    categories = sys.argv[3] if len(sys.argv) > 3 else ""
    asyncio.run(main(url, origin, categories))
