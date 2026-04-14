#!/usr/bin/env python3
"""Recon pipeline orchestrator.

Performs DNS lookup, probes common subdomains, HTTP probes each
discovered subdomain, and returns technology detection results.
Uses only standard library + requests — no external tools required.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlparse

import requests
from protopen_scripts._common import make_headers, make_session

logger = logging.getLogger(__name__)

COMMON_SUBDOMAINS = [
    "www",
    "api",
    "dev",
    "staging",
    "app",
    "admin",
    "portal",
    "mail",
    "webmail",
    "smtp",
    "ftp",
    "vpn",
    "remote",
    "git",
    "gitlab",
    "github",
    "jira",
    "confluence",
    "jenkins",
    "ci",
    "cd",
    "cdn",
    "static",
    "assets",
    "media",
    "uploads",
    "img",
    "images",
    "beta",
    "test",
    "qa",
    "uat",
    "prod",
    "preview",
    "dashboard",
    "auth",
    "sso",
    "login",
    "oauth",
    "shop",
    "store",
    "blog",
    "docs",
    "help",
    "support",
    "status",
    "monitor",
    "metrics",
    "grafana",
    "kibana",
    "elastic",
    "db",
    "database",
    "mysql",
    "postgres",
    "redis",
    "mongo",
    "s3",
    "backup",
    "files",
]

# Tech fingerprints from response headers/body
TECH_FINGERPRINTS = {
    "nginx": re.compile(r"nginx", re.IGNORECASE),
    "apache": re.compile(r"Apache", re.IGNORECASE),
    "iis": re.compile(r"Microsoft-IIS", re.IGNORECASE),
    "cloudflare": re.compile(r"cloudflare", re.IGNORECASE),
    "vercel": re.compile(r"vercel|x-vercel", re.IGNORECASE),
    "netlify": re.compile(r"netlify", re.IGNORECASE),
    "aws_alb": re.compile(r"awselb|amazon", re.IGNORECASE),
    "fastly": re.compile(r"fastly", re.IGNORECASE),
    "akamai": re.compile(r"akamai", re.IGNORECASE),
    "wordpress": re.compile(r"wp-content|wp-includes|WordPress", re.IGNORECASE),
    "react": re.compile(r"__REACT|_reactFiber|react\.", re.IGNORECASE),
    "next_js": re.compile(r"__NEXT_DATA__|_next/static", re.IGNORECASE),
    "django": re.compile(r"csrfmiddlewaretoken|django", re.IGNORECASE),
    "rails": re.compile(r"rails|X-Request-Id.*x-runtime", re.IGNORECASE),
    "express": re.compile(r"X-Powered-By.*Express", re.IGNORECASE),
    "php": re.compile(r"X-Powered-By.*PHP|\.php", re.IGNORECASE),
    "laravel": re.compile(r"laravel_session|XSRF-TOKEN.*laravel", re.IGNORECASE),
    "kubernetes": re.compile(r"kubernetes|k8s", re.IGNORECASE),
    "traefik": re.compile(r"traefik", re.IGNORECASE),
    "istio": re.compile(r"x-envoy|istio", re.IGNORECASE),
    "shopify": re.compile(r"shopify|myshopify\.com", re.IGNORECASE),
}


def dns_lookup(domain: str) -> dict[str, Any]:
    """Resolve domain to IPs."""
    result: dict[str, Any] = {"domain": domain, "ips": [], "cname": None}
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = list({info[4][0] for info in infos})
        result["ips"] = ips
    except socket.gaierror as exc:
        result["error"] = str(exc)
    try:
        cname = socket.gethostbyname_ex(domain)
        if cname[0] != domain:
            result["cname"] = cname[0]
    except Exception:
        pass
    return result


def probe_subdomain(subdomain: str, domain: str, timeout: int = 8) -> dict[str, Any] | None:
    """Probe a subdomain for HTTP(S) access. Return info or None if unreachable."""
    fqdn = f"{subdomain}.{domain}"
    # Quick DNS check first
    try:
        socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return None  # Does not resolve

    info: dict[str, Any] = {"subdomain": fqdn, "ips": [], "status": None, "technologies": [], "https": False}

    try:
        addrs = socket.getaddrinfo(fqdn, None)
        info["ips"] = list({a[4][0] for a in addrs})
    except Exception:
        pass

    # Try HTTPS first, then HTTP
    for scheme in ("https", "http"):
        url = f"{scheme}://{fqdn}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers=make_headers(),
            )
            info["status"] = resp.status_code
            info["https"] = scheme == "https"
            info["url"] = url

            # Tech detection from headers + body
            header_str = str(resp.headers)
            body_preview = resp.text[:5000]
            combined = header_str + body_preview
            techs = [name for name, pat in TECH_FINGERPRINTS.items() if pat.search(combined)]
            info["technologies"] = techs

            # Title
            title_m = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.IGNORECASE)
            if title_m:
                info["title"] = title_m.group(1).strip()[:100]

            return info
        except requests.RequestException:
            continue

    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Recon pipeline")
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument("--output-dir", default="/tmp/recon", help="Output directory for results")
    parser.add_argument("--threads", type=int, default=20, help="Concurrent threads")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "domain": args.domain,
        "subdomains": [],
        "technologies": {},
        "open_ports": [],
    }

    try:
        os.makedirs(args.output_dir, exist_ok=True)

        # DNS lookup for main domain
        dns_info = dns_lookup(args.domain)
        result["dns"] = dns_info

        # Probe subdomains concurrently
        found_subdomains: list[dict[str, Any]] = []
        max_threads = min(args.threads, len(COMMON_SUBDOMAINS))

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(probe_subdomain, sub, args.domain): sub for sub in COMMON_SUBDOMAINS}
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    info = future.result()
                    if info is not None:
                        found_subdomains.append(info)
                        # Aggregate technologies
                        for tech in info.get("technologies", []):
                            result["technologies"][tech] = result["technologies"].get(tech, 0) + 1
                except Exception as exc:
                    logger.debug("Subdomain probe error for %s: %s", sub, exc)

        result["subdomains"] = sorted(found_subdomains, key=lambda x: x["subdomain"])

        # Save results to output dir
        out_file = os.path.join(args.output_dir, f"{args.domain}_recon.json")
        with open(out_file, "w") as fh:
            json.dump(result, fh, indent=2)

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("recon_pipeline error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
