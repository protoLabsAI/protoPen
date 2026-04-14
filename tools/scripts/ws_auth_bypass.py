"""WebSocket authentication bypass tester.

Connects to a WebSocket endpoint without credentials or with manipulated
auth tokens and checks whether the server accepts the connection and
responds to messages.
"""

from __future__ import annotations

import asyncio
import json
import sys
import ssl


async def main(url: str, origin: str, auth_token: str) -> None:
    try:
        import websockets
    except ImportError:
        print(json.dumps({"error": "websockets library not installed"}))
        return

    results: dict = {
        "url": url,
        "tests": [],
    }

    # Test 1: Connect with no auth
    try:
        extra_headers = {"Origin": origin} if origin else {}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        async with websockets.connect(
            url,
            additional_headers=extra_headers,
            ssl=ctx if url.startswith("wss://") else None,
            open_timeout=10,
        ) as ws:
            await ws.send('{"type":"ping"}')
            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=5)
                results["tests"].append(
                    {
                        "test": "no_auth_connect",
                        "vulnerable": True,
                        "severity": "high",
                        "detail": f"Server accepted unauthenticated connection and responded: {resp[:200]}",
                    }
                )
            except asyncio.TimeoutError:
                results["tests"].append(
                    {
                        "test": "no_auth_connect",
                        "vulnerable": True,
                        "severity": "medium",
                        "detail": "Server accepted unauthenticated connection but no response to message",
                    }
                )
    except Exception as e:
        results["tests"].append(
            {
                "test": "no_auth_connect",
                "vulnerable": False,
                "severity": "info",
                "detail": f"Connection rejected: {type(e).__name__}: {e}",
            }
        )

    # Test 2: Connect with manipulated token (if provided)
    if auth_token:
        try:
            mangled = auth_token[::-1]  # reversed token
            extra_headers = {"Authorization": f"Bearer {mangled}"}
            if origin:
                extra_headers["Origin"] = origin
            async with websockets.connect(
                url,
                additional_headers=extra_headers,
                ssl=ctx if url.startswith("wss://") else None,
                open_timeout=10,
            ) as ws:
                await ws.send('{"type":"ping"}')
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=5)
                    results["tests"].append(
                        {
                            "test": "mangled_token",
                            "vulnerable": True,
                            "severity": "high",
                            "detail": f"Server accepted mangled auth token: {resp[:200]}",
                        }
                    )
                except asyncio.TimeoutError:
                    results["tests"].append(
                        {
                            "test": "mangled_token",
                            "vulnerable": True,
                            "severity": "medium",
                            "detail": "Server accepted mangled token but no response",
                        }
                    )
        except Exception as e:
            results["tests"].append(
                {
                    "test": "mangled_token",
                    "vulnerable": False,
                    "severity": "info",
                    "detail": f"Mangled token rejected: {type(e).__name__}: {e}",
                }
            )

    print(json.dumps(results))


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "ws://localhost:8080"
    origin = sys.argv[2] if len(sys.argv) > 2 else ""
    auth_token = sys.argv[3] if len(sys.argv) > 3 else ""
    asyncio.run(main(url, origin, auth_token))
