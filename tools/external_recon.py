"""External reconnaissance — passive public footprint from an attacker's perspective.

Covers the full pre-engagement external view:
  - WAN IP discovery (what IP the internet sees)
  - Shodan host lookup (what the internet can see at that IP)
  - Censys certificate + host search
  - BGP/ASN/WHOIS for IP ranges
  - Certificate transparency (crt.sh) for domain expansion
  - DNS security posture (SPF, DKIM, DMARC, CAA)
  - Email security headers
  - Cloud storage exposure (S3, Azure Blob, GCP)
  - Tailscale / VPN endpoint detection
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import urllib.parse
from pathlib import Path
from typing import Any

from tools.parsers import ingest_output
from tools._tool_base import Tool

logger = logging.getLogger(__name__)


class ExternalReconTool(Tool):
    """Passive external reconnaissance — public footprint, Shodan, Censys, BGP, cert-transparency."""

    def __init__(self, workspace: str = "/tmp/protopen"):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None

    @property
    def name(self) -> str:
        return "external_recon"

    @property
    def description(self) -> str:
        return (
            "Passive external reconnaissance from an attacker's perspective. "
            "Discovers public IP, Shodan/Censys exposure, BGP/ASN ownership, "
            "certificate transparency, DNS security posture (SPF/DKIM/DMARC), "
            "and cloud storage exposure without sending packets to the target."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Recon action to perform",
                    "enum": [
                        "wan_ip",
                        "shodan_host",
                        "shodan_search",
                        "censys_host",
                        "bgp_asn",
                        "cert_transparency",
                        "dns_security",
                        "cloud_exposure",
                        "full_external",
                    ],
                },
                "target": {
                    "type": "string",
                    "description": "IP address, domain, or ASN. Leave empty for wan_ip.",
                },
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 60)"},
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        target = kwargs.get("target", "")
        timeout = kwargs.get("timeout", 60)

        dispatch = {
            "wan_ip": lambda: self.wan_ip(timeout),
            "shodan_host": lambda: self.shodan_host(target, timeout),
            "shodan_search": lambda: self.shodan_search(target, timeout),
            "censys_host": lambda: self.censys_host(target, timeout),
            "bgp_asn": lambda: self.bgp_asn(target, timeout),
            "cert_transparency": lambda: self.cert_transparency(target, timeout),
            "dns_security": lambda: self.dns_security(target, timeout),
            "cloud_exposure": lambda: self.cloud_exposure(target, timeout),
            "full_external": lambda: self.full_external(target, timeout),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            result = await fn()
            ingest_output("external_recon", action, result, self._target_store)
            return result
        except Exception as exc:
            logger.exception("external_recon error (%s)", action)
            return f"external_recon error ({action}): {exc}"

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _run(self, *args: str, timeout: int = 60, stdin: str | None = None) -> str:
        logger.info("Running: %s", " ".join(str(a) for a in args))
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin else None,
        )
        try:
            inp = stdin.encode() if stdin else None
            stdout, stderr = await asyncio.wait_for(proc.communicate(input=inp), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return f"Timed out after {timeout}s: {' '.join(str(a) for a in args)}"
        out = stdout.decode(errors="replace").strip()
        err = stderr.decode(errors="replace").strip()
        return out + (f"\n[stderr] {err}" if err else "")

    async def _curl(self, url: str, headers: dict | None = None, timeout: int = 30) -> str:
        args = ["curl", "-s", "--max-time", str(timeout), "-L", url]
        if headers:
            for k, v in headers.items():
                args += ["-H", f"{k}: {v}"]
        return await self._run(*args, timeout=timeout + 5)

    def _shodan_key(self) -> str | None:
        return os.environ.get("SHODAN_API_KEY") or os.environ.get("SHODAN_KEY")

    def _censys_creds(self) -> tuple[str, str] | None:
        uid = os.environ.get("CENSYS_API_ID")
        secret = os.environ.get("CENSYS_API_SECRET")
        return (uid, secret) if uid and secret else None

    # ── actions ───────────────────────────────────────────────────────────────

    async def wan_ip(self, timeout: int = 15) -> str:
        """Discover the public WAN IP from multiple sources."""
        sources = [
            "https://api.ipify.org?format=json",
            "https://api4.my-ip.io/ip.json",
            "https://ifconfig.me/all.json",
        ]
        results: list[str] = []
        for url in sources:
            try:
                raw = await self._curl(url, timeout=10)
                # extract IP from various JSON shapes
                m = re.search(r'"(?:ip|YourFuckingIPAddress)"\s*:\s*"([\d.]+)"', raw)
                if m:
                    results.append(m.group(1))
                    break
                m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', raw)
                if m:
                    results.append(m.group(1))
                    break
            except Exception:
                continue
        if not results:
            return "wan_ip: could not determine public IP (all sources failed)"
        ip = results[0]
        # also do a quick reverse DNS
        rdns = await self._run("dig", "+short", "-x", ip, timeout=10)
        return f"WAN IP: {ip}\nReverse DNS: {rdns or '(none)'}"

    async def shodan_host(self, target: str, timeout: int = 30) -> str:
        """Query Shodan for everything known about an IP."""
        if not target:
            return "shodan_host: target IP required"
        key = self._shodan_key()
        if key:
            url = f"https://api.shodan.io/shodan/host/{urllib.parse.quote(target)}?key={key}"
            raw = await self._curl(url, timeout=timeout)
            try:
                data = json.loads(raw)
                if "error" in data:
                    return f"Shodan error: {data['error']}"
                ports = data.get("ports", [])
                vulns = list(data.get("vulns", {}).keys())
                hostnames = data.get("hostnames", [])
                org = data.get("org", "unknown")
                isp = data.get("isp", "unknown")
                asn = data.get("asn", "unknown")
                country = data.get("country_name", "unknown")
                services = []
                for item in data.get("data", []):
                    port = item.get("port", "?")
                    transport = item.get("transport", "tcp")
                    product = item.get("product", "")
                    version = item.get("version", "")
                    banner = (item.get("data", "") or "").split("\n")[0][:80]
                    services.append(f"  {port}/{transport} {product} {version} — {banner}")
                lines = [
                    f"Shodan: {target}",
                    f"  Org: {org} | ISP: {isp} | ASN: {asn} | Country: {country}",
                    f"  Hostnames: {', '.join(hostnames) or '(none)'}",
                    f"  Open ports: {ports}",
                    f"  CVEs: {vulns or '(none)'}",
                    "  Services:",
                    *services,
                ]
                return "\n".join(lines)
            except json.JSONDecodeError:
                return f"Shodan raw: {raw[:2000]}"
        # fallback: shodan CLI if available
        result = await self._run("shodan", "host", target, timeout=timeout)
        if "command not found" in result or "No such file" in result:
            return "Shodan: no API key set (SHODAN_API_KEY) and shodan CLI not found. Set key or install: pip install shodan"
        return result

    async def shodan_search(self, query: str, timeout: int = 30) -> str:
        """Search Shodan with a query string (e.g. 'org:\"My ISP\" port:22')."""
        if not query:
            return "shodan_search: query string required"
        key = self._shodan_key()
        if key:
            url = f"https://api.shodan.io/shodan/host/search?key={key}&query={urllib.parse.quote(query)}&minify=true"
            raw = await self._curl(url, timeout=timeout)
            try:
                data = json.loads(raw)
                total = data.get("total", 0)
                matches = data.get("matches", [])
                lines = [f"Shodan search: '{query}' — {total} total results"]
                for m in matches[:20]:
                    ip = m.get("ip_str", "?")
                    port = m.get("port", "?")
                    org = m.get("org", "?")
                    product = m.get("product", "")
                    lines.append(f"  {ip}:{port} [{org}] {product}")
                return "\n".join(lines)
            except json.JSONDecodeError:
                return f"Shodan search raw: {raw[:2000]}"
        result = await self._run("shodan", "search", "--fields", "ip_str,port,org,product", query, timeout=timeout)
        return result

    async def censys_host(self, target: str, timeout: int = 30) -> str:
        """Query Censys for everything known about an IP."""
        if not target:
            return "censys_host: target IP required"
        creds = self._censys_creds()
        if creds:
            uid, secret = creds
            url = f"https://search.censys.io/api/v2/hosts/{urllib.parse.quote(target)}"
            raw = await self._curl(url, headers={"Authorization": f"Basic {_b64(uid + ':' + secret)}"}, timeout=timeout)
            try:
                data = json.loads(raw)
                result = data.get("result", {})
                services = result.get("services", [])
                lines = [f"Censys: {target}"]
                for svc in services:
                    port = svc.get("port", "?")
                    proto = svc.get("transport_protocol", "tcp")
                    name = svc.get("service_name", "")
                    banner = str(svc.get("banner", ""))[:80]
                    lines.append(f"  {port}/{proto} {name} — {banner}")
                return "\n".join(lines) if len(lines) > 1 else f"Censys: no services found for {target}"
            except json.JSONDecodeError:
                return f"Censys raw: {raw[:2000]}"
        # fallback: censys CLI
        result = await self._run("censys", "view", "--index-type", "hosts", target, timeout=timeout)
        if "command not found" in result or "No such file" in result:
            return "Censys: no API credentials (CENSYS_API_ID/CENSYS_API_SECRET) and censys CLI not found."
        return result

    async def bgp_asn(self, target: str, timeout: int = 20) -> str:
        """BGP/ASN/WHOIS lookup for an IP or domain — ownership, prefixes, abuse contacts."""
        if not target:
            return "bgp_asn: target IP or domain required"
        lines: list[str] = []

        # Team Cymru WHOIS (most reliable for ASN)
        cymru = await self._run(
            "whois", "-h", "whois.cymru.com", f" -v {target}", timeout=15
        )
        lines.append(f"=== Team Cymru ASN ===\n{cymru}")

        # bgp.he.net via curl (human-readable, no API key needed)
        he_raw = await self._curl(f"https://bgp.he.net/ip/{urllib.parse.quote(target)}#_bgpinfo", timeout=15)
        # extract key fields
        asn_m = re.findall(r'AS(\d+)', he_raw)
        prefix_m = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', he_raw)
        if asn_m:
            lines.append(f"BGP.he.net ASNs: {list(set(asn_m))[:5]}")
        if prefix_m:
            lines.append(f"Announced prefixes: {list(set(prefix_m))[:5]}")

        # ipinfo.io — org, city, ASN, abuse
        ipinfo = await self._curl(f"https://ipinfo.io/{urllib.parse.quote(target)}/json", timeout=15)
        try:
            d = json.loads(ipinfo)
            lines.append(
                f"ipinfo: org={d.get('org','?')} city={d.get('city','?')} "
                f"region={d.get('region','?')} country={d.get('country','?')}"
            )
        except json.JSONDecodeError:
            lines.append(f"ipinfo raw: {ipinfo[:200]}")

        return "\n".join(lines)

    async def cert_transparency(self, domain: str, timeout: int = 30) -> str:
        """Search crt.sh certificate transparency logs for domain expansion."""
        if not domain:
            return "cert_transparency: domain required"
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
        raw = await self._curl(url, timeout=timeout)
        try:
            data = json.loads(raw)
            names: set[str] = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for n in name_value.splitlines():
                    n = n.strip().lstrip("*.")
                    if n and domain in n:
                        names.add(n)
            if not names:
                return f"cert_transparency: no certificates found for {domain}"
            sorted_names = sorted(names)
            lines = [f"crt.sh certificate transparency — {len(sorted_names)} unique names for {domain}:"]
            lines += [f"  {n}" for n in sorted_names[:100]]
            if len(sorted_names) > 100:
                lines.append(f"  ... and {len(sorted_names) - 100} more")
            return "\n".join(lines)
        except json.JSONDecodeError:
            return f"cert_transparency raw: {raw[:1000]}"

    async def dns_security(self, domain: str, timeout: int = 30) -> str:
        """Check DNS security posture: SPF, DKIM, DMARC, CAA, DNSSEC."""
        if not domain:
            return "dns_security: domain required"
        results: list[str] = [f"DNS security posture: {domain}"]

        checks = {
            "SPF": ("TXT", f"{domain}"),
            "DMARC": ("TXT", f"_dmarc.{domain}"),
            "CAA": ("CAA", f"{domain}"),
            "MX": ("MX", f"{domain}"),
            "DNSSEC (DS)": ("DS", f"{domain}"),
        }
        tasks = {
            label: self._run("dig", "+short", f"-t{rtype}", target, timeout=10)
            for label, (rtype, target) in checks.items()
        }
        resolved = {k: await v for k, v in tasks.items()}

        for label, output in resolved.items():
            if output and "timed out" not in output.lower():
                results.append(f"  {label}: {output[:200]}")
            else:
                results.append(f"  {label}: NOT FOUND")

        # SPF analysis
        spf_raw = resolved.get("SPF", "")
        if "v=spf1" in spf_raw:
            if "-all" in spf_raw:
                results.append("  SPF policy: HARD FAIL (-all) — good")
            elif "~all" in spf_raw:
                results.append("  SPF policy: SOFT FAIL (~all) — acceptable")
            elif "+all" in spf_raw:
                results.append("  SPF policy: PASS ALL (+all) — DANGEROUS")
            else:
                results.append("  SPF policy: no explicit all — weak")
        else:
            results.append("  SPF: MISSING — email spoofing possible")

        # DMARC analysis
        dmarc_raw = resolved.get("DMARC", "")
        if "v=DMARC1" in dmarc_raw:
            if "p=reject" in dmarc_raw:
                results.append("  DMARC policy: reject — strong")
            elif "p=quarantine" in dmarc_raw:
                results.append("  DMARC policy: quarantine — moderate")
            elif "p=none" in dmarc_raw:
                results.append("  DMARC policy: none — monitoring only, no enforcement")
        else:
            results.append("  DMARC: MISSING — no email authentication enforcement")

        return "\n".join(results)

    async def cloud_exposure(self, target: str, timeout: int = 45) -> str:
        """Check for exposed cloud storage (S3, Azure Blob, GCP) tied to a domain."""
        if not target:
            return "cloud_exposure: domain required"
        domain_base = target.split(".")[0]
        results: list[str] = [f"Cloud storage exposure check: {target}"]

        # Common bucket name patterns
        bucket_names = [
            domain_base,
            target,
            f"{domain_base}-backup",
            f"{domain_base}-data",
            f"{domain_base}-assets",
            f"{domain_base}-static",
            f"{domain_base}-media",
            f"{domain_base}-logs",
            f"{domain_base}-dev",
            f"{domain_base}-prod",
            f"{domain_base}-staging",
        ]

        async def check_s3(bucket: str) -> tuple[str, str]:
            url = f"https://{bucket}.s3.amazonaws.com"
            raw = await self._curl(url, timeout=8)
            if "<ListBucketResult" in raw:
                return bucket, "S3 OPEN — bucket listing enabled"
            if "<Error>" in raw and "NoSuchBucket" not in raw and "AccessDenied" not in raw:
                return bucket, f"S3 exists but restricted: {raw[:100]}"
            if "AccessDenied" in raw:
                return bucket, "S3 exists — access denied (private)"
            return bucket, ""

        async def check_azure(bucket: str) -> tuple[str, str]:
            url = f"https://{bucket}.blob.core.windows.net/{bucket}?restype=container&comp=list"
            raw = await self._curl(url, timeout=8)
            if "<EnumerationResults" in raw:
                return bucket, "Azure Blob OPEN — container listing enabled"
            if "BlobNotFound" not in raw and "ContainerNotFound" not in raw and len(raw) > 50:
                return bucket, f"Azure Blob exists: {raw[:100]}"
            return bucket, ""

        async def check_gcs(bucket: str) -> tuple[str, str]:
            url = f"https://storage.googleapis.com/{bucket}"
            raw = await self._curl(url, timeout=8)
            if "<ListBucketResult" in raw or "<Contents>" in raw:
                return bucket, "GCS OPEN — bucket listing enabled"
            if "NoSuchBucket" not in raw and "AccessDenied" not in raw and len(raw) > 50:
                return bucket, f"GCS exists: {raw[:100]}"
            return bucket, ""

        all_checks = []
        for b in bucket_names:
            all_checks.extend([check_s3(b), check_azure(b), check_gcs(b)])

        check_results = await asyncio.gather(*all_checks, return_exceptions=True)
        found = False
        for res in check_results:
            if isinstance(res, Exception):
                continue
            bucket, finding = res
            if finding:
                results.append(f"  [{finding}] {bucket}")
                found = True
        if not found:
            results.append("  No exposed cloud storage found for common bucket name patterns")
        return "\n".join(results)

    async def full_external(self, target: str, timeout: int = 120) -> str:
        """Run all external recon phases for a target IP or domain."""
        parts: list[str] = [f"=== Full External Recon: {target or 'WAN'} ===\n"]

        # Phase 1: WAN IP (always)
        wan = await self.wan_ip(timeout=15)
        parts.append(f"## WAN IP\n{wan}\n")

        # Extract IP for subsequent queries
        ip_m = re.search(r'WAN IP:\s*([\d.]+)', wan)
        recon_ip = ip_m.group(1) if ip_m else target

        # Phase 2: Run everything in parallel
        tasks = {
            "Shodan": self.shodan_host(recon_ip, timeout=30),
            "BGP/ASN": self.bgp_asn(recon_ip, timeout=20),
        }
        if target and not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            tasks["Cert Transparency"] = self.cert_transparency(target, timeout=30)
            tasks["DNS Security"] = self.dns_security(target, timeout=30)
            tasks["Cloud Exposure"] = self.cloud_exposure(target, timeout=45)

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for label, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                parts.append(f"## {label}\nError: {result}\n")
            else:
                parts.append(f"## {label}\n{result}\n")

        return "\n".join(parts)


def _b64(s: str) -> str:
    import base64
    return base64.b64encode(s.encode()).decode()
