"""Cross-Site WebSocket Hijacking (CSWSH) tester.

Tests whether a WebSocket endpoint validates the Origin header,
which is the primary defense against CSWSH attacks.
"""

from __future__ import annotations

import asyncio
import json
import sys
import ssl


EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
]


async def main(url: str, legitimate_origin: str) -> None:
    try:
        import websockets
    except ImportError:
        print(json.dumps({"error": "websockets library not installed"}))
        return

    results: dict = {
        "url": url,
        "legitimate_origin": legitimate_origin,
        "tests": [],
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ssl_ctx = ctx if url.startswith("wss://") else None

    # Test 1: Connect with legitimate origin (baseline)
    try:
        headers = {"Origin": legitimate_origin} if legitimate_origin else {}
        async with websockets.connect(
            url,
            additional_headers=headers,
            ssl=ssl_ctx,
            open_timeout=10,
        ) as ws:
            await ws.send('{"type":"ping"}')
            try:
                await asyncio.wait_for(ws.recv(), timeout=5)
            except asyncio.TimeoutError:
                pass
        results["tests"].append(
            {
                "test": "legitimate_origin",
                "origin": legitimate_origin or "(none)",
                "accepted": True,
            }
        )
    except Exception as e:
        results["tests"].append(
            {
                "test": "legitimate_origin",
                "origin": legitimate_origin or "(none)",
                "accepted": False,
                "detail": str(e),
            }
        )

    # Test 2: Connect with each evil origin
    for origin in EVIL_ORIGINS:
        try:
            async with websockets.connect(
                url,
                additional_headers={"Origin": origin},
                ssl=ssl_ctx,
                open_timeout=10,
            ) as ws:
                await ws.send('{"type":"ping"}')
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=5)
                    results["tests"].append(
                        {
                            "test": "cswsh",
                            "origin": origin,
                            "vulnerable": True,
                            "severity": "high",
                            "detail": f"Evil origin accepted, server responded: {resp[:200]}",
                        }
                    )
                except asyncio.TimeoutError:
                    results["tests"].append(
                        {
                            "test": "cswsh",
                            "origin": origin,
                            "vulnerable": True,
                            "severity": "medium",
                            "detail": "Evil origin accepted (connection opened) but no response",
                        }
                    )
        except Exception as e:
            results["tests"].append(
                {
                    "test": "cswsh",
                    "origin": origin,
                    "vulnerable": False,
                    "severity": "info",
                    "detail": f"Rejected: {type(e).__name__}: {e}",
                }
            )

    # Test 3: No Origin header at all
    try:
        async with websockets.connect(
            url,
            ssl=ssl_ctx,
            open_timeout=10,
        ) as ws:
            await ws.send('{"type":"ping"}')
            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=5)
                results["tests"].append(
                    {
                        "test": "no_origin",
                        "vulnerable": True,
                        "severity": "medium",
                        "detail": f"No Origin header accepted, server responded: {resp[:200]}",
                    }
                )
            except asyncio.TimeoutError:
                results["tests"].append(
                    {
                        "test": "no_origin",
                        "vulnerable": True,
                        "severity": "low",
                        "detail": "No Origin header accepted but no response",
                    }
                )
    except Exception as e:
        results["tests"].append(
            {
                "test": "no_origin",
                "vulnerable": False,
                "severity": "info",
                "detail": f"Rejected: {type(e).__name__}: {e}",
            }
        )

    print(json.dumps(results))


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "ws://localhost:8080"
    legitimate_origin = sys.argv[2] if len(sys.argv) > 2 else ""
    asyncio.run(main(url, legitimate_origin))
