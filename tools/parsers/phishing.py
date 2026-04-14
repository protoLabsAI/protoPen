"""Parser for phishing framework output — GoPhish, Evilginx, email, DNS, SMTP."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_gophish_json(raw: str, store: "TargetStore") -> list[dict]:
    """Parse GoPhish JSON output (campaign create/results)."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    # Campaign results
    if "results" in data:
        for r in data["results"]:
            entities.append(
                {
                    "type": "phishing_finding",
                    "check": "gophish_results",
                    "severity": "info",
                    "details": f"{r.get('email', '')} — status: {r.get('status', 'unknown')}",
                }
            )
    elif "id" in data:
        entities.append(
            {
                "type": "phishing_finding",
                "check": "gophish_create_campaign",
                "severity": "info",
                "details": f"Campaign created: {data.get('name', '')} (id={data.get('id', '')})",
            }
        )
    else:
        entities.append(
            {
                "type": "phishing_finding",
                "check": "gophish",
                "severity": "info",
                "details": str(data)[:300],
            }
        )
    return entities


def parse_evilginx_text(raw: str, store: "TargetStore") -> list[dict]:
    """Parse Evilginx text output for phishlet/lure info."""
    entities: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if "http" in line.lower() or "lure" in line.lower() or "phishlet" in line.lower():
            entities.append(
                {
                    "type": "phishing_finding",
                    "check": "evilginx",
                    "severity": "info",
                    "details": line,
                }
            )
    return entities


def parse_email_header(raw: str, store: "TargetStore") -> list[dict]:
    """Parse email header analysis JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities
    for finding in data if isinstance(data, list) else data.get("findings", [data]):
        entities.append(
            {
                "type": "phishing_finding",
                "check": "email_header_analyze",
                "severity": finding.get("severity", "medium"),
                "details": finding.get("message", str(finding)[:200]),
            }
        )
    return entities


def parse_dns_txt(raw: str, store: "TargetStore") -> list[dict]:
    """Parse dig TXT output for SPF/DKIM/DMARC records."""
    entities: list[dict] = []
    raw_s = raw.strip()
    if not raw_s:
        entities.append(
            {
                "type": "phishing_finding",
                "check": "dns_txt",
                "severity": "high",
                "details": "No TXT record found — missing email authentication",
            }
        )
        return entities

    for line in raw_s.splitlines():
        line = line.strip().strip('"')
        if not line:
            continue
        severity = "info"
        if "v=spf1" in line:
            if "+all" in line:
                severity = "critical"
            elif "~all" in line:
                severity = "medium"
        elif "p=none" in line:
            severity = "medium"
        elif "p=reject" in line:
            severity = "info"
        entities.append(
            {
                "type": "phishing_finding",
                "check": "dns_txt",
                "severity": severity,
                "details": line,
            }
        )
    return entities


def parse_smtp_relay(raw: str, store: "TargetStore") -> list[dict]:
    """Parse swaks SMTP relay test output."""
    entities: list[dict] = []
    raw_s = raw.strip()
    if not raw_s:
        return entities
    relay_open = "250" in raw_s and ("Ok" in raw_s or "Queued" in raw_s or "ok" in raw_s)
    entities.append(
        {
            "type": "phishing_finding",
            "check": "smtp_relay_test",
            "severity": "critical" if relay_open else "info",
            "details": "SMTP relay OPEN — server accepted message" if relay_open else raw_s[:300],
        }
    )
    return entities


PARSER_MAP[("phishing", "gophish_create_campaign")] = parse_gophish_json
PARSER_MAP[("phishing", "gophish_results")] = parse_gophish_json
PARSER_MAP[("phishing", "evilginx_phishlet")] = parse_evilginx_text
PARSER_MAP[("phishing", "evilginx_lures")] = parse_evilginx_text
PARSER_MAP[("phishing", "email_header_analyze")] = parse_email_header
PARSER_MAP[("phishing", "spf_check")] = parse_dns_txt
PARSER_MAP[("phishing", "dkim_check")] = parse_dns_txt
PARSER_MAP[("phishing", "dmarc_check")] = parse_dns_txt
PARSER_MAP[("phishing", "smtp_relay_test")] = parse_smtp_relay
