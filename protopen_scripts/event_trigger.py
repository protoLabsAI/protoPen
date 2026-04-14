#!/usr/bin/env python3
"""Event trigger abuse tester.

Checks for unauthenticated event trigger endpoints on serverless functions
(S3, SQS, SNS, EventBridge, webhook-style HTTP triggers).
"""
from __future__ import annotations

import argparse
import json
import sys
import logging
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from protopen_scripts._common import make_session

logger = logging.getLogger(__name__)

# Common webhook/event trigger URL patterns
WEBHOOK_PATHS = [
    "/webhook",
    "/webhooks",
    "/hook",
    "/hooks",
    "/trigger",
    "/triggers",
    "/event",
    "/events",
    "/callback",
    "/notify",
    "/notification",
    "/api/webhook",
    "/api/trigger",
    "/api/event",
    "/api/hooks",
    "/_hooks",
    "/_events",
    "/sns",
    "/sqs",
    "/eventbridge",
    "/s3-event",
    "/github-webhook",
    "/gitlab-webhook",
    "/stripe-webhook",
    "/twilio-webhook",
]

# Fake SNS notification payload (common attack surface)
SNS_PAYLOAD = {
    "Type": "Notification",
    "MessageId": "test-message-id",
    "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
    "Subject": "Test notification",
    "Message": "{\"test\": true}",
    "Timestamp": "2024-01-01T00:00:00.000Z",
    "SignatureVersion": "1",
    "Signature": "INVALID",
    "SigningCertURL": "https://evil.com/cert.pem",
}

# S3 event payload
S3_PAYLOAD = {
    "Records": [{
        "eventVersion": "2.1",
        "eventSource": "aws:s3",
        "awsRegion": "us-east-1",
        "eventTime": "2024-01-01T00:00:00.000Z",
        "eventName": "ObjectCreated:Put",
        "s3": {
            "bucket": {"name": "test-bucket", "arn": "arn:aws:s3:::test-bucket"},
            "object": {"key": "../../../../etc/passwd", "size": 100},
        },
    }]
}

# Generic webhook test payload
GENERIC_PAYLOAD = {
    "event": "test",
    "data": {"test": True, "source": "aws-lambda"},
}


def _probe_trigger(session: requests.Session, url: str, payload: dict) -> dict[str, Any]:
    """POST a trigger payload and return response info."""
    try:
        resp = session.post(url, json=payload, timeout=10, allow_redirects=False)
        return {
            "status_code": resp.status_code,
            "body_preview": resp.text[:200],
            "content_type": resp.headers.get("Content-Type", ""),
        }
    except requests.RequestException as exc:
        return {"status_code": -1, "error": str(exc)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Event trigger abuse tester")
    parser.add_argument("--function-url", required=True, help="Serverless function URL")
    parser.add_argument("--trigger-type", default="http", help="Trigger type (s3, sns, sqs, http, webhook)")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"triggers": []}

    try:
        session = make_session()

        parsed = urlparse(args.function_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Check if primary URL is accessible
        try:
            probe = session.get(args.function_url, timeout=10, allow_redirects=False)
            primary_accessible = probe.status_code not in (000,)
        except requests.RequestException:
            primary_accessible = False

        # Select payload based on trigger type
        payloads_to_test = [
            ("generic", GENERIC_PAYLOAD),
            ("sns_notification", SNS_PAYLOAD),
            ("s3_event", S3_PAYLOAD),
        ]

        if primary_accessible:
            for payload_type, payload in payloads_to_test:
                resp_info = _probe_trigger(session, args.function_url, payload)
                status = resp_info.get("status_code", -1)

                if status in (200, 202, 204):
                    result["triggers"].append({
                        "function_url": args.function_url,
                        "severity": "high",
                        "description": f"Unauthenticated event trigger accepted {payload_type} payload (HTTP {status})",
                        "vulnerability_type": "unauthenticated_trigger",
                        "trigger_type": payload_type,
                        "response_preview": resp_info.get("body_preview", ""),
                    })
                elif status in (401, 403):
                    result["triggers"].append({
                        "function_url": args.function_url,
                        "severity": "info",
                        "description": f"Trigger endpoint requires authentication for {payload_type} payload (HTTP {status})",
                        "vulnerability_type": "authenticated_trigger",
                        "trigger_type": payload_type,
                    })

        # Probe common webhook paths at the origin
        for path in WEBHOOK_PATHS[:15]:
            url = urljoin(origin, path)
            try:
                resp = session.post(url, json=GENERIC_PAYLOAD, timeout=8, allow_redirects=False)
                if resp.status_code in (200, 202, 204):
                    result["triggers"].append({
                        "function_url": url,
                        "severity": "medium",
                        "description": f"Webhook/trigger endpoint found at {url} accepting unauthenticated POST (HTTP {resp.status_code})",
                        "vulnerability_type": "unauthenticated_webhook",
                        "trigger_type": "webhook",
                    })
                elif resp.status_code not in (404, 410, 501):
                    result["triggers"].append({
                        "function_url": url,
                        "severity": "info",
                        "description": f"Potential trigger endpoint at {url} (HTTP {resp.status_code})",
                        "vulnerability_type": "trigger_endpoint_found",
                        "trigger_type": "webhook",
                    })
            except requests.RequestException:
                pass

        if not result["triggers"]:
            result["triggers"].append({
                "function_url": args.function_url,
                "severity": "info",
                "description": "No unauthenticated event trigger endpoints found",
                "vulnerability_type": "none_found",
            })

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("event_trigger error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
