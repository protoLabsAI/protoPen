#!/usr/bin/env python3
"""OIDC provider discovery.

Fetches the OpenID Connect discovery document from /.well-known/openid-configuration
and returns the full configuration JSON. Empty findings if not found.
"""
from __future__ import annotations

import argparse
import json
import sys
import logging
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="OIDC discovery document fetcher")
    parser.add_argument("--url", required=True, help="Target OIDC provider URL")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    wk_url = urljoin(origin, "/.well-known/openid-configuration")

    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "protopen-oidc-discover/1.0"})
        resp = session.get(wk_url, timeout=15)

        if resp.status_code == 200:
            try:
                config = resp.json()
                # Return the raw OIDC config — parser handles it
                print(json.dumps(config))
                return
            except Exception as exc:
                print(json.dumps({
                    "findings": [{
                        "severity": "info",
                        "vulnerability_type": "oidc_parse_error",
                        "message": f"OIDC endpoint returned 200 but invalid JSON: {exc}",
                    }]
                }))
                return
        else:
            print(json.dumps({
                "findings": [{
                    "severity": "info",
                    "vulnerability_type": "oidc_not_found",
                    "message": f"No OIDC discovery document found at {wk_url} (HTTP {resp.status_code})",
                }]
            }))

    except Exception as exc:
        print(json.dumps({
            "error": str(exc),
            "findings": [{
                "severity": "error",
                "vulnerability_type": "scan_error",
                "message": f"OIDC discovery failed: {exc}",
            }]
        }))
        logger.error("oidc_discover error: %s", exc)


if __name__ == "__main__":
    main()
