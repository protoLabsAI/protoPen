#!/usr/bin/env python3
"""Cold-start race condition tester.

Sends N concurrent requests to a serverless function URL using asyncio
and aiohttp (falls back to threaded requests). Measures cold-start time
variance and checks for race conditions in response content.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import logging
import time
from typing import Any

import requests
from protopen_scripts._common import make_headers, make_session
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


async def _async_fetch(url: str, payload: dict, session_headers: dict) -> dict[str, Any]:
    """Async HTTP POST using asyncio + aiohttp if available, else httpx."""
    import aiohttp  # type: ignore
    start = time.monotonic()
    try:
        async with aiohttp.ClientSession(headers=session_headers) as client:
            async with client.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                body = await resp.text()
                elapsed_ms = (time.monotonic() - start) * 1000
                return {
                    "status": resp.status,
                    "elapsed_ms": round(elapsed_ms, 2),
                    "body_preview": body[:200],
                    "error": None,
                }
    except Exception as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        return {"status": -1, "elapsed_ms": round(elapsed_ms, 2), "body_preview": "", "error": str(exc)}


def _threaded_fetch(url: str, payload: dict, headers: dict) -> dict[str, Any]:
    """Synchronous HTTP POST for fallback."""
    start = time.monotonic()
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        elapsed_ms = (time.monotonic() - start) * 1000
        return {
            "status": resp.status_code,
            "elapsed_ms": round(elapsed_ms, 2),
            "body_preview": resp.text[:200],
            "error": None,
        }
    except Exception as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        return {"status": -1, "elapsed_ms": round(elapsed_ms, 2), "body_preview": "", "error": str(exc)}


def analyze_responses(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Analyze concurrent responses for race condition indicators."""
    findings: list[dict[str, Any]] = []

    successful = [r for r in responses if r["status"] == 200]
    elapsed_values = [r["elapsed_ms"] for r in successful if r["elapsed_ms"] > 0]

    if not elapsed_values:
        return findings

    min_ms = min(elapsed_values)
    max_ms = max(elapsed_values)
    avg_ms = sum(elapsed_values) / len(elapsed_values)
    variance = max_ms - min_ms

    # High variance suggests some requests hit cold starts
    if variance > 2000:
        findings.append({
            "type": "cold_start_detected",
            "severity": "low",
            "description": f"High response time variance ({variance:.0f}ms) suggests cold starts — min={min_ms:.0f}ms, max={max_ms:.0f}ms, avg={avg_ms:.0f}ms",
        })

    # Check for unique/different response bodies (race condition signal)
    bodies = [r["body_preview"] for r in successful if r["body_preview"]]
    unique_bodies = set(bodies)
    if len(unique_bodies) > 1 and len(bodies) > 2:
        findings.append({
            "type": "inconsistent_responses",
            "severity": "high",
            "description": f"Concurrent requests returned {len(unique_bodies)} distinct response bodies — possible race condition in state initialization",
        })

    # Check for error responses that indicate initialization failure
    errors = [r for r in responses if r["status"] not in (200, 201, 202, 204, -1)]
    if errors:
        findings.append({
            "type": "cold_start_errors",
            "severity": "medium",
            "description": f"{len(errors)}/{len(responses)} requests failed during concurrent load — {set(r['status'] for r in errors)} status codes",
        })

    # Check for duplicate IDs or counters in responses (shared state leak)
    id_pattern_found = False
    seen_ids: set[str] = set()
    import re
    id_re = re.compile(r'"(?:id|request_id|trace_id|nonce)"\s*:\s*"?([a-f0-9\-]{8,})"?', re.IGNORECASE)
    for body in bodies:
        for m in id_re.finditer(body):
            val = m.group(1)
            if val in seen_ids:
                id_pattern_found = True
                break
            seen_ids.add(val)
        if id_pattern_found:
            break

    if id_pattern_found:
        findings.append({
            "type": "duplicate_id_detected",
            "severity": "high",
            "description": "Duplicate request ID/nonce returned by concurrent requests — possible shared state vulnerability",
        })

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Cold-start race condition tester")
    parser.add_argument("--function-url", required=True, help="Serverless function URL")
    parser.add_argument("--concurrency", type=int, default=20, help="Number of concurrent requests")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"results": []}
    concurrency = min(args.concurrency, 100)

    try:
        headers = {
            "User-Agent": make_headers()["User-Agent"],
            "Content-Type": "application/json",
        }
        payload = {"test": True, "timestamp": time.time()}

        # Try async (aiohttp) first, fall back to threaded
        responses: list[dict[str, Any]] = []

        async def _run_async():
            tasks = [_async_fetch(args.function_url, payload, headers) for _ in range(concurrency)]
            return await asyncio.gather(*tasks, return_exceptions=False)

        try:
            import aiohttp  # noqa: F401
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                responses = loop.run_until_complete(_run_async())
            finally:
                loop.close()
        except ImportError:
            # Fall back to ThreadPoolExecutor
            logger.debug("aiohttp not available, using threaded fallback")
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = [executor.submit(_threaded_fetch, args.function_url, payload, headers)
                           for _ in range(concurrency)]
                responses = [f.result() for f in as_completed(futures)]

        # Analyze results
        race_findings = analyze_responses(responses)

        # Summary finding
        successful = sum(1 for r in responses if r.get("status", -1) == 200)
        elapsed_vals = [r["elapsed_ms"] for r in responses if r.get("elapsed_ms", 0) > 0]
        avg_ms = sum(elapsed_vals) / len(elapsed_vals) if elapsed_vals else 0

        result["results"].append({
            "function_url": args.function_url,
            "severity": "info",
            "description": f"Sent {concurrency} concurrent requests — {successful} succeeded, avg={avg_ms:.0f}ms",
            "concurrency": concurrency,
            "successful_requests": successful,
            "avg_response_ms": round(avg_ms, 2),
        })

        for finding in race_findings:
            result["results"].append({
                "function_url": args.function_url,
                "severity": finding["severity"],
                "description": finding["description"],
                "vulnerability_type": finding["type"],
            })

    except Exception as exc:
        result["error"] = str(exc)
        result["results"].append({
            "function_url": args.function_url,
            "severity": "error",
            "description": f"Cold-start race test failed: {exc}",
        })
        logger.error("cold_start_race error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
