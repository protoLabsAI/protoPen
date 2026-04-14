#!/usr/bin/env python3
"""Edge function auditor.

Checks response headers for edge function indicators and tests
for enumerability and path traversal on edge routes.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import logging
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger(__name__)

EDGE_HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    ("X-Vercel-Id", "vercel", "Vercel edge function detected"),
    ("X-Vercel-Cache", "vercel", "Vercel edge caching detected"),
    ("X-Vercel-Execution-Region", "vercel", "Vercel edge region header exposed"),
    ("x-nf-request-id", "netlify", "Netlify edge function detected"),
    ("X-Nf-Account-Id", "netlify", "Netlify account ID exposed in headers"),
    ("CF-Cache-Status", "cloudflare", "Cloudflare CDN/edge detected"),
    ("CF-RAY", "cloudflare", "Cloudflare Ray ID — edge processing confirmed"),
    ("cf-edge-cache", "cloudflare", "Cloudflare edge cache header"),
    ("X-Amzn-Trace-Id", "aws", "AWS Lambda/ALB trace ID exposed"),
    ("X-Amzn-RequestId", "aws", "AWS request ID — Lambda or API Gateway"),
    ("x-amz-cf-id", "cloudfront", "AWS CloudFront edge detected"),
    ("x-amz-cf-pop", "cloudfront", "AWS CloudFront PoP exposed"),
    ("Fly-Request-Id", "fly.io", "Fly.io edge runtime detected"),
    ("X-EdgeConnect-MidMile-RTT", "akamai", "Akamai edge detected"),
    ("X-Check-Cacheable", "fastly", "Fastly edge detected"),
    ("Fastly-Debug-Digest", "fastly", "Fastly debug header exposed"),
    ("X-Powered-By-Deno", "deno_deploy", "Deno Deploy edge runtime"),
    ("Via", "proxy", "Proxy/CDN intermediary detected"),
]

# Edge runtime route patterns
EDGE_ROUTE_PATTERNS = [
    "/api/edge",
    "/_edge",
    "/_vercel",
    "/_function",
    "/api/_middleware",
    "/.netlify/edge-handlers",
    "/.netlify/functions",
    "/api/__middleware",
    "/_worker.js",
    "/cdn-cgi/",
    "/cdn-cgi/l/email-protection",
]

# Path traversal payloads for edge routes
PATH_TRAVERSAL_PAYLOADS = [
    "/../../../etc/passwd",
    "/..%2F..%2F..%2Fetc%2Fpasswd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/.env",
    "/../.env",
    "/..%2F.env",
]


def check_edge_headers(resp: requests.Response, url: str) -> list[dict[str, Any]]:
    """Detect edge runtime from response headers."""
    findings: list[dict[str, Any]] = []
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for header_name, provider, description in EDGE_HEADER_SIGNATURES:
        if header_name.lower() in headers_lower:
            value = headers_lower[header_name.lower()]
            findings.append({
                "url": url,
                "severity": "info",
                "description": f"{description} — header '{header_name}: {value[:50]}'",
                "provider": provider,
                "header": header_name,
            })

    return findings


def probe_edge_routes(session: requests.Session, base_url: str) -> list[dict[str, Any]]:
    """Probe known edge route paths."""
    findings: list[dict[str, Any]] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in EDGE_ROUTE_PATTERNS:
        url = urljoin(origin, path)
        try:
            resp = session.get(url, timeout=8, allow_redirects=False)
            if resp.status_code not in (404, 410, 501):
                findings.append({
                    "url": url,
                    "severity": "info" if resp.status_code in (200, 301, 302) else "low",
                    "description": f"Edge route accessible: {url} (HTTP {resp.status_code})",
                    "provider": "unknown",
                    "http_status": resp.status_code,
                })
        except requests.RequestException:
            pass

    return findings


def test_path_traversal(session: requests.Session, base_url: str) -> list[dict[str, Any]]:
    """Test path traversal on edge routes."""
    findings: list[dict[str, Any]] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Find accessible edge routes first
    accessible_routes: list[str] = []
    for path in EDGE_ROUTE_PATTERNS[:5]:
        url = urljoin(origin, path)
        try:
            resp = session.get(url, timeout=8, allow_redirects=False)
            if resp.status_code in (200, 405):
                accessible_routes.append(path)
        except requests.RequestException:
            pass

    # Apply traversal to accessible routes
    for route in accessible_routes:
        for traversal in PATH_TRAVERSAL_PAYLOADS:
            url = urljoin(origin, route + traversal)
            try:
                resp = session.get(url, timeout=8, allow_redirects=False)
                body = resp.text[:500]
                if (resp.status_code == 200 and
                    ('root:' in body or 'AWS_SECRET' in body or 'DB_PASSWORD' in body)):
                    findings.append({
                        "url": url,
                        "severity": "critical",
                        "description": f"Path traversal successful at {url} — sensitive content in response",
                        "provider": "unknown",
                    })
                elif resp.status_code == 200:
                    findings.append({
                        "url": url,
                        "severity": "medium",
                        "description": f"Path traversal returned 200 at {url} — verify response content",
                        "provider": "unknown",
                    })
            except requests.RequestException:
                pass

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Edge function auditor")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--provider", default="", help="Edge provider hint (vercel, netlify, cloudflare, etc.)")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"findings": []}

    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "protopen-edge-audit/1.0"})

        # Initial request to check headers
        resp = session.get(args.url, timeout=15, allow_redirects=True)
        header_findings = check_edge_headers(resp, args.url)
        result["findings"].extend(header_findings)

        # Probe edge routes
        route_findings = probe_edge_routes(session, args.url)
        result["findings"].extend(route_findings)

        # Test path traversal on discovered routes
        traversal_findings = test_path_traversal(session, args.url)
        result["findings"].extend(traversal_findings)

        if not result["findings"]:
            result["findings"].append({
                "url": args.url,
                "severity": "info",
                "description": "No edge function indicators detected",
                "provider": "none",
            })

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("edge_audit error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
