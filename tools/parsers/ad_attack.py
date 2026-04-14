"""Parser for Active Directory attack output — BloodHound, Certipy, enum4linux-ng, Impacket."""
from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_bloodhound_collect(raw: str, store: "TargetStore") -> list[dict]:
    """Parse bloodhound-python collection output."""
    entities: list[dict] = []
    # bloodhound-python prints progress and creates a zip — extract summary
    zip_match = re.search(r"(\S+\.zip)", raw)
    zip_file = zip_match.group(1) if zip_match else "unknown"

    counts: dict[str, int] = {}
    for obj_type in ("users", "groups", "computers", "domains", "ous", "gpos", "containers"):
        match = re.search(rf"(\d+)\s+{obj_type}", raw, re.IGNORECASE)
        if match:
            counts[obj_type] = int(match.group(1))

    entities.append({
        "type": "ad_finding",
        "target": "domain",
        "check": "bloodhound_collection",
        "severity": "info",
        "value": f"BloodHound data collected: {zip_file}",
        "counts": counts,
        "zip_file": zip_file,
    })
    return entities


def parse_certipy_find(raw: str, store: "TargetStore") -> list[dict]:
    """Parse certipy find JSON output for certificate templates."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    # Certipy outputs under "Certificate Templates" or "Certificate Authorities"
    templates = data.get("Certificate Templates", {})
    if isinstance(templates, dict):
        templates = templates.values()

    for tmpl in templates:
        name = tmpl.get("Template Name", tmpl.get("name", ""))
        vuln_to = tmpl.get("Vulnerabilities", tmpl.get("[!] Vulnerabilities", []))
        severity = "high" if vuln_to else "info"
        entities.append({
            "type": "ad_finding",
            "target": name,
            "check": "adcs_template",
            "severity": severity,
            "value": tmpl.get("Display Name", name),
            "vulnerabilities": vuln_to if isinstance(vuln_to, list) else [vuln_to] if vuln_to else [],
            "enabled": tmpl.get("Enabled", True),
            "client_authentication": tmpl.get("Client Authentication", False),
            "enrollee_supplies_subject": tmpl.get("Enrollee Supplies Subject", False),
        })
    return entities


def parse_certipy_vuln(raw: str, store: "TargetStore") -> list[dict]:
    """Parse certipy find -vulnerable JSON output."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    templates = data.get("Certificate Templates", {})
    if isinstance(templates, dict):
        templates = templates.values()

    for tmpl in templates:
        name = tmpl.get("Template Name", tmpl.get("name", ""))
        vuln_to = tmpl.get("Vulnerabilities", tmpl.get("[!] Vulnerabilities", []))
        if not vuln_to:
            continue
        entities.append({
            "type": "ad_finding",
            "target": name,
            "check": "adcs_vulnerable_template",
            "severity": "critical",
            "value": f"Vulnerable template: {name}",
            "vulnerabilities": vuln_to if isinstance(vuln_to, list) else [vuln_to],
            "enabled": tmpl.get("Enabled", True),
            "client_authentication": tmpl.get("Client Authentication", False),
            "enrollee_supplies_subject": tmpl.get("Enrollee Supplies Subject", False),
        })
    return entities


def parse_enum4linux_ng(raw: str, store: "TargetStore") -> list[dict]:
    """Parse enum4linux-ng JSON output for shares, users, groups."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    # Shares
    for share in data.get("shares", []):
        entities.append({
            "type": "ad_finding",
            "target": share.get("name", ""),
            "check": "smb_share",
            "severity": "info",
            "value": share.get("comment", ""),
            "access": share.get("access", ""),
        })

    # Users
    for user in data.get("users", []):
        entities.append({
            "type": "ad_finding",
            "target": user.get("username", ""),
            "check": "smb_user",
            "severity": "info",
            "value": user.get("name", user.get("username", "")),
        })

    # Groups
    for group in data.get("groups", []):
        entities.append({
            "type": "ad_finding",
            "target": group.get("groupname", ""),
            "check": "smb_group",
            "severity": "info",
            "value": group.get("groupname", ""),
            "members": group.get("members", []),
        })

    return entities


def parse_ldapsearch(raw: str, store: "TargetStore") -> list[dict]:
    """Parse ldapsearch LDIF output into entry dicts."""
    entities: list[dict] = []
    current_dn = ""
    current_attrs: dict[str, list[str]] = {}

    for line in raw.splitlines():
        line = line.rstrip()
        if not line or line.startswith("#"):
            if current_dn:
                entities.append({
                    "type": "ad_finding",
                    "target": current_dn,
                    "check": "ldap_entry",
                    "severity": "info",
                    "value": current_dn,
                    "attributes": dict(current_attrs),
                })
                current_dn = ""
                current_attrs = {}
            continue
        if line.startswith("dn: "):
            current_dn = line[4:]
            current_attrs = {}
        elif ": " in line:
            key, _, val = line.partition(": ")
            current_attrs.setdefault(key, []).append(val)

    # Flush last entry
    if current_dn:
        entities.append({
            "type": "ad_finding",
            "target": current_dn,
            "check": "ldap_entry",
            "severity": "info",
            "value": current_dn,
            "attributes": dict(current_attrs),
        })

    return entities


def parse_kerberoast(raw: str, store: "TargetStore") -> list[dict]:
    """Parse Impacket GetUserSPNs output for Kerberoast hashes."""
    entities: list[dict] = []
    hashes = [line for line in raw.splitlines() if line.startswith("$krb5tgs$")]
    entities.append({
        "type": "ad_finding",
        "target": "domain",
        "check": "kerberoast",
        "severity": "high" if hashes else "info",
        "value": f"Kerberoastable hashes found: {len(hashes)}",
        "hash_count": len(hashes),
    })
    return entities


def parse_asreproast(raw: str, store: "TargetStore") -> list[dict]:
    """Parse Impacket GetNPUsers output for AS-REP roast hashes."""
    entities: list[dict] = []
    hashes = [line for line in raw.splitlines() if line.startswith("$krb5asrep$")]
    entities.append({
        "type": "ad_finding",
        "target": "domain",
        "check": "asreproast",
        "severity": "high" if hashes else "info",
        "value": f"AS-REP roastable hashes found: {len(hashes)}",
        "hash_count": len(hashes),
    })
    return entities


def parse_secretsdump(raw: str, store: "TargetStore") -> list[dict]:
    """Parse Impacket secretsdump output for credential types."""
    entities: list[dict] = []
    sam_hashes = [l for l in raw.splitlines() if ":::" in l and "SAM" not in l and l.strip()]
    ntds_section = "NTDS.DIT secrets" in raw
    lsa_section = "LSA Secrets" in raw

    # Count NTLM hashes (lines with :::)
    ntlm_lines = [l for l in raw.splitlines() if re.match(r"^\S+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::", l)]

    types_found: list[str] = []
    if ntlm_lines:
        types_found.append("NTLM")
    if ntds_section:
        types_found.append("NTDS.DIT")
    if lsa_section:
        types_found.append("LSA")

    entities.append({
        "type": "ad_finding",
        "target": "domain_controller",
        "check": "secretsdump",
        "severity": "critical" if ntlm_lines else "info",
        "value": f"Secrets dumped — types: {', '.join(types_found) or 'none'}, NTLM hashes: {len(ntlm_lines)}",
        "hash_count": len(ntlm_lines),
        "types_found": types_found,
    })
    return entities


# ── Register all parsers ─────────────────────────────────────────────────────

PARSER_MAP[("ad_attack", "bloodhound_collect")] = parse_bloodhound_collect
PARSER_MAP[("ad_attack", "bloodhound_edges")] = parse_bloodhound_collect
PARSER_MAP[("ad_attack", "certipy_find")] = parse_certipy_find
PARSER_MAP[("ad_attack", "certipy_vuln")] = parse_certipy_vuln
PARSER_MAP[("ad_attack", "enum4linux_ng")] = parse_enum4linux_ng
PARSER_MAP[("ad_attack", "ldapsearch")] = parse_ldapsearch
PARSER_MAP[("ad_attack", "kerberoast")] = parse_kerberoast
PARSER_MAP[("ad_attack", "asreproast")] = parse_asreproast
PARSER_MAP[("ad_attack", "secretsdump")] = parse_secretsdump
