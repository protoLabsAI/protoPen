"""Parser for external_recon tool output."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")
_PORT_RE = re.compile(r"(\d+)/(tcp|udp)\s+(\w+)")
_DOMAIN_RE = re.compile(r"\b([\w.-]+\.[\w]{2,})\b")


def parse_wan_ip(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    m = re.search(r"WAN IP:\s*([\d.]+)", raw)
    if m:
        ip = m.group(1)
        store.upsert_host(ip=ip, tags=["wan", "public"])
        entities.append({"type": "host", "ip": ip, "role": "wan_ip"})
    rdns_m = re.search(r"Reverse DNS:\s*(\S+)", raw)
    if rdns_m and rdns_m.group(1) != "(none)":
        store.upsert_host(ip=m.group(1) if m else "", hostname=rdns_m.group(1), tags=["wan"])
    return entities


def parse_shodan_host(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    for ip in _IP_RE.findall(raw):
        store.upsert_host(ip=ip, tags=["shodan"])
        entities.append({"type": "host", "ip": ip})
    for cve in _CVE_RE.findall(raw):
        entities.append({"type": "vulnerability", "cve": cve, "source": "shodan"})
    for port, proto, service in _PORT_RE.findall(raw):
        entities.append({"type": "service", "port": int(port), "protocol": proto, "service": service})
    return entities


def parse_bgp_asn(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    asn_m = re.findall(r"\bAS(\d+)\b", raw)
    for asn in set(asn_m):
        entities.append({"type": "asn", "asn": f"AS{asn}"})
    prefix_m = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", raw)
    for prefix in set(prefix_m):
        entities.append({"type": "network_prefix", "prefix": prefix})
    org_m = re.search(r"org=([^\s,]+)", raw)
    if org_m:
        entities.append({"type": "org", "name": org_m.group(1)})
    return entities


def parse_cert_transparency(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("  ") and "." in line:
            hostname = line.strip()
            if _DOMAIN_RE.match(hostname):
                store.upsert_host(hostname=hostname, tags=["cert_transparency"])
                entities.append({"type": "host", "hostname": hostname})
    return entities


def parse_dns_security(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    if "SPF: MISSING" in raw:
        entities.append({"type": "finding", "severity": "medium", "title": "Missing SPF record", "detail": raw[:200]})
    if "DMARC: MISSING" in raw:
        entities.append({"type": "finding", "severity": "medium", "title": "Missing DMARC record", "detail": raw[:200]})
    if "p=none" in raw:
        entities.append(
            {"type": "finding", "severity": "low", "title": "DMARC policy=none (no enforcement)", "detail": raw[:200]}
        )
    if "+all" in raw:
        entities.append(
            {"type": "finding", "severity": "high", "title": "SPF +all — email spoofing trivial", "detail": raw[:200]}
        )
    return entities


def parse_cloud_exposure(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    if "OPEN" in raw:
        for line in raw.splitlines():
            if "OPEN" in line:
                entities.append(
                    {
                        "type": "finding",
                        "severity": "critical",
                        "title": "Open cloud storage bucket",
                        "detail": line.strip(),
                    }
                )
    if "exists" in raw.lower():
        for line in raw.splitlines():
            if "exists" in line.lower():
                entities.append(
                    {
                        "type": "finding",
                        "severity": "medium",
                        "title": "Cloud storage bucket exists",
                        "detail": line.strip(),
                    }
                )
    return entities


def parse_full_external(raw: str, store: "TargetStore") -> list[dict]:
    entities: list[dict] = []
    entities.extend(parse_wan_ip(raw, store))
    entities.extend(parse_shodan_host(raw, store))
    entities.extend(parse_bgp_asn(raw, store))
    entities.extend(parse_cert_transparency(raw, store))
    entities.extend(parse_dns_security(raw, store))
    entities.extend(parse_cloud_exposure(raw, store))
    return entities


PARSER_MAP[("external_recon", "wan_ip")] = parse_wan_ip
PARSER_MAP[("external_recon", "shodan_host")] = parse_shodan_host
PARSER_MAP[("external_recon", "shodan_search")] = parse_shodan_host
PARSER_MAP[("external_recon", "censys_host")] = parse_shodan_host
PARSER_MAP[("external_recon", "bgp_asn")] = parse_bgp_asn
PARSER_MAP[("external_recon", "cert_transparency")] = parse_cert_transparency
PARSER_MAP[("external_recon", "dns_security")] = parse_dns_security
PARSER_MAP[("external_recon", "cloud_exposure")] = parse_cloud_exposure
PARSER_MAP[("external_recon", "full_external")] = parse_full_external
