"""Finding scorer, deduplicator, and attack suggester.

Used by the orchestrator to prioritize findings after automated scans and
generate targeted follow-up suggestions the agent can act on.

Typical flow:
    scored = score_all(engagement.findings, mode="active")
    for finding in scored[:5]:          # top 5 priorities
        for suggestion in finding.suggestions:
            await dispatch(suggestion.tool, suggestion.action, suggestion.params)
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any


# ── Severity weights ───────────────────────────────────────────────────────────

_SEVERITY_SCORE = {"critical": 80, "high": 55, "medium": 25, "low": 8, "info": 1}
_SEVERITY_RANK  = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ── High-impact title keywords (bonus score) ──────────────────────────────────

_HIGH_IMPACT_KW = (
    "rce", "remote code", "command injection", "credential", "password",
    "admin", "root", "privilege", "authentication bypass",
)
_MEDIUM_IMPACT_KW = (
    "sql", "sqli", "ssrf", "xxe", "deserialization", "path traversal",
    "file inclusion", "idor", "bola", "exposed secret", "api key",
)
_LOW_IMPACT_KW = (
    "open port", "service", "exposed", "public", "default",
    "misconfiguration", "weak cipher",
)

# ── Attack suggestion rule table ──────────────────────────────────────────────
# (category_contains, title_contains, tool, action, params_template, min_mode, description)
# Both category_contains and title_contains are substring matches (empty = always match).

_RULES: list[tuple[str, str, str, str, dict[str, str], str, str]] = [
    # ─ SSH / Remote Access ──────────────────────────────────────────────────
    ("ssh",        "",        "credential_attack", "ssh_brute",    {"target": "{target}", "port": "22"},       "active",  "Brute-force SSH credentials"),
    ("ssh",        "",        "priv_esc",          "run",          {"target": "{target}"},                     "active",  "Check for post-auth privilege escalation"),
    ("ssh",        "open",    "lateral_move",      "ssh_pivot",    {"target": "{target}"},                     "redteam", "SSH pivot into internal network"),

    # ─ Web Application ──────────────────────────────────────────────────────
    ("web",        "",        "web_vuln",          "scan",         {"target": "https://{target}"},             "active",  "Full web vulnerability scan"),
    ("web",        "",        "auth_test",         "run",          {"target": "https://{target}"},             "active",  "Authentication bypass and BOLA testing"),
    ("web",        "api",     "api_enum",          "run",          {"target": "https://{target}"},             "active",  "Enumerate and fuzz API endpoints"),
    ("web",        "jwt",     "jwt_tool",          "attack",       {"target": "https://{target}"},             "active",  "JWT algorithm confusion and claim manipulation"),
    ("web",        "graphql", "graphql_test",      "introspect",   {"target": "https://{target}/graphql"},     "active",  "GraphQL schema extraction and fuzzing"),
    ("web",        "sql",     "sql_test",          "scan",         {"target": "https://{target}"},             "active",  "SQL injection detection and exploitation"),
    ("web",        "ssrf",    "web_vuln",          "ssrf_probe",   {"target": "https://{target}"},             "active",  "SSRF probe against internal endpoints"),

    # ─ API / Auth ───────────────────────────────────────────────────────────
    ("api",        "",        "web_vuln",          "scan",         {"target": "https://{target}"},             "active",  "Web vulnerability scan on API surface"),
    ("api",        "openapi", "api_enum",          "openapi_fuzz", {"target": "https://{target}"},             "active",  "Fuzz OpenAPI spec endpoints"),
    ("api",        "graphql", "graphql_test",      "fuzz",         {"target": "https://{target}/graphql"},     "active",  "GraphQL field and query fuzzing"),
    ("auth",       "oauth",   "auth_audit",        "oauth_test",   {"target": "https://{target}"},             "active",  "OAuth/OIDC flow and token testing"),
    ("auth",       "jwt",     "jwt_tool",          "attack",       {"target": "https://{target}"},             "active",  "JWT key confusion and brute-force"),
    ("auth",       "bypass",  "auth_test",         "bola_idor",    {"target": "https://{target}"},             "active",  "Broken object-level auth (BOLA/IDOR) testing"),
    ("auth",       "saml",    "auth_audit",        "saml_test",    {"target": "https://{target}"},             "active",  "SAML assertion forge and redirect tests"),

    # ─ SSL / TLS ─────────────────────────────────────────────────────────────
    ("ssl",        "",        "ssl_audit",         "ssl_full_audit", {"target": "{target}"},                   "passive", "Full TLS configuration audit"),

    # ─ Network Services ──────────────────────────────────────────────────────
    ("network",    "smb",     "service_enum",      "enum4linux",   {"target": "{target}"},                     "active",  "Enumerate SMB shares, users, policies"),
    ("network",    "rdp",     "credential_attack", "rdp_brute",    {"target": "{target}"},                     "active",  "Brute-force RDP credentials"),
    ("network",    "ftp",     "credential_attack", "ftp_brute",    {"target": "{target}"},                     "active",  "Brute-force FTP credentials"),
    ("network",    "snmp",    "service_enum",      "snmp_enum",    {"target": "{target}"},                     "active",  "SNMP community string enumeration"),
    ("service",    "",        "cve_match",         "lookup",       {"target": "{target}"},                     "passive", "Match discovered services against known CVEs"),
    ("service",    "",        "vuln_scan",         "nuclei_scan",  {"target": "{target}", "severity": "medium,high,critical"}, "passive", "Nuclei vulnerability scan"),

    # ─ Database ──────────────────────────────────────────────────────────────
    ("database",   "mysql",   "sql_test",          "scan",         {"target": "{target}", "dbms": "mysql"},    "active",  "MySQL injection and credential testing"),
    ("database",   "mssql",   "credential_attack", "mssql_brute",  {"target": "{target}"},                     "active",  "MSSQL brute-force and xp_cmdshell"),
    ("database",   "redis",   "credential_attack", "run",          {"target": "{target}", "service": "redis"}, "active",  "Redis unauthenticated access check"),

    # ─ WiFi / RF ─────────────────────────────────────────────────────────────
    ("wifi",       "open",    "marauder",          "evil_portal",  {"ssid": "{target}"},                       "redteam", "Evil portal credential harvesting"),
    ("wifi",       "weak",    "marauder",          "sniff",        {"type": "pmkid"},                          "active",  "Capture PMKID handshake for offline cracking"),
    ("wifi",       "pmkid",   "hashcat_rules",     "generate",     {"hash_type": "22000"},                     "active",  "Generate hashcat rules for PMKID cracking"),
    ("wifi",       "pmkid",   "credential_attack", "wifi_crack",   {"target": "{target}"},                     "active",  "Offline WPA2 handshake crack"),

    # ─ Container / Cloud ─────────────────────────────────────────────────────
    ("container",  "",        "container_audit",   "deepce",       {"target": "{target}"},                     "active",  "Container escape and privilege escalation"),
    ("container",  "k8s",     "container_audit",   "kube_hunter",  {"target": "{target}"},                     "active",  "Kubernetes cluster security scanning"),
    ("container",  "image",   "container_audit",   "trivy_image",  {"target": "{target}"},                     "passive", "Container image CVE scanning"),
    ("cicd",       "",        "cicd_audit",        "run",          {"target": "{target}"},                     "passive", "CI/CD pipeline secret scanning"),
    ("supply_chain","",       "supply_chain",      "run",          {"target": "{target}"},                     "passive", "Dependency confusion and typosquatting"),

    # ─ Credentials / Hashes ──────────────────────────────────────────────────
    ("credential", "hash",    "hashcat_rules",     "generate",     {"hash_type": "NT"},                        "active",  "Generate hashcat rules for captured hashes"),
    ("credential", "",        "credential_attack", "run",          {"target": "{target}"},                     "active",  "Credential spray against discovered services"),

    # ─ CVE ───────────────────────────────────────────────────────────────────
    ("cve",        "",        "cve_search",        "get",          {"cve_id": "{cve_id}"},                     "passive", "Deep-read CVE advisory and PoC"),

    # ─ IoT ───────────────────────────────────────────────────────────────────
    ("iot",        "mqtt",    "iot_protocol",      "mqtt_subscribe", {"target": "{target}"},                   "active",  "Subscribe to MQTT broker, extract topics/payloads"),
    ("iot",        "",        "iot_protocol",      "mqtt_discover",  {"target": "{target}"},                   "active",  "Discover IoT protocols on target segment"),

    # ─ Active Directory ──────────────────────────────────────────────────────
    ("ad",         "",        "ad_attack",         "bloodhound",   {"target": "{target}"},                     "active",  "BloodHound AD attack path enumeration"),
    ("ad",         "kerberos","ad_attack",         "kerberoast",   {"target": "{target}"},                     "active",  "Kerberoasting — extract service tickets for cracking"),
]

_IP_RE  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
_MODE_RANK = {"passive": 0, "active": 1, "redteam": 2}


# ── Public data classes ────────────────────────────────────────────────────────

@dataclass
class AttackSuggestion:
    tool: str
    action: str
    params: dict[str, Any]
    description: str
    requires_mode: str = "active"

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "action": self.action,
            "params": self.params,
            "description": self.description,
            "requires_mode": self.requires_mode,
        }


@dataclass
class ScoredFinding:
    id: str
    severity: str
    category: str
    title: str
    detail: str
    target: str = ""
    cve_id: str = ""
    score: int = 0
    occurrences: int = 1
    suggestions: list[AttackSuggestion] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "score": self.score,
            "occurrences": self.occurrences,
            "target": self.target,
            "cve_id": self.cve_id,
            "suggestions": [s.to_dict() for s in self.suggestions],
        }


# ── Core functions ─────────────────────────────────────────────────────────────

def finding_id(finding: dict) -> str:
    """Stable hash key for deduplication — category + title prefix."""
    raw = f"{finding.get('category','').lower()}:{finding.get('title','').lower()[:80]}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def deduplicate(findings: list[dict]) -> list[dict]:
    """Merge findings with the same (category, title) — keep highest severity."""
    seen: dict[str, dict] = {}
    order: list[str] = []

    for f in findings:
        fid = finding_id(f)
        if fid not in seen:
            seen[fid] = {**f, "_id": fid, "_count": 1}
            order.append(fid)
        else:
            seen[fid]["_count"] += 1
            # Promote severity if this occurrence is worse
            if _SEVERITY_RANK.get(f.get("severity", "info"), 0) > \
               _SEVERITY_RANK.get(seen[fid].get("severity", "info"), 0):
                seen[fid]["severity"] = f["severity"]
                seen[fid]["detail"]   = f["detail"]

    return [seen[fid] for fid in order]


def score(finding: dict) -> int:
    """Priority score 0–100 for a single finding."""
    base = _SEVERITY_SCORE.get(finding.get("severity", "info"), 1)

    count_bonus = min(finding.get("_count", 1) - 1, 10)

    title = finding.get("title", "").lower()
    detail = finding.get("detail", "").lower()
    text = title + " " + detail

    if any(kw in text for kw in _HIGH_IMPACT_KW):
        impact_bonus = 15
    elif any(kw in text for kw in _MEDIUM_IMPACT_KW):
        impact_bonus = 10
    elif any(kw in text for kw in _LOW_IMPACT_KW):
        impact_bonus = 3
    else:
        impact_bonus = 0

    return min(base + count_bonus + impact_bonus, 100)


def suggest_followup(finding: dict, mode: str = "active") -> list[AttackSuggestion]:
    """Generate up to 5 attack suggestions for a finding, filtered by mode."""
    current_rank = _MODE_RANK.get(mode.lower(), 1)

    category = finding.get("category", "").lower()
    title    = finding.get("title", "").lower()
    detail   = finding.get("detail", "")

    target = (_extract_first_ip(detail) or "target")
    cve_id = _extract_cve_id(title + " " + detail)

    suggestions: list[AttackSuggestion] = []
    seen_keys: set[str] = set()

    for (cat_kw, title_kw, tool, action, tmpl, min_mode, desc) in _RULES:
        if cat_kw and cat_kw not in category:
            continue
        if title_kw and title_kw not in title:
            continue
        if _MODE_RANK.get(min_mode, 1) > current_rank:
            continue

        key = f"{tool}:{action}"
        if key in seen_keys:
            continue
        seen_keys.add(key)

        resolved = {
            k: v.replace("{target}", target).replace("{cve_id}", cve_id or "")
            for k, v in tmpl.items()
        }
        suggestions.append(AttackSuggestion(
            tool=tool, action=action, params=resolved,
            description=desc, requires_mode=min_mode,
        ))
        if len(suggestions) >= 5:
            break

    return suggestions


def score_all(findings: list[dict], mode: str = "active") -> list[ScoredFinding]:
    """Deduplicate, score, and attach attack suggestions to all findings.

    Returns findings sorted highest-priority first.
    """
    deduped = deduplicate(findings)
    result: list[ScoredFinding] = []

    for f in deduped:
        s = score(f)
        detail = f.get("detail", "")
        result.append(ScoredFinding(
            id          = f["_id"],
            severity    = f.get("severity", "info"),
            category    = f.get("category", ""),
            title       = f.get("title", ""),
            detail      = detail,
            target      = _extract_first_ip(detail),
            cve_id      = _extract_cve_id(f.get("title", "") + " " + detail),
            score       = s,
            occurrences = f.get("_count", 1),
            suggestions = suggest_followup(f, mode),
        ))

    result.sort(key=lambda x: x.score, reverse=True)
    return result


def format_findings_summary(scored: list[ScoredFinding]) -> str:
    """Return a compact human-readable summary for the agent prompt."""
    counts = Counter(f.severity for f in scored)
    lines = [
        f"**{len(scored)} unique findings** "
        f"(critical={counts.get('critical',0)} "
        f"high={counts.get('high',0)} "
        f"medium={counts.get('medium',0)} "
        f"low={counts.get('low',0)})",
    ]
    priority = [f for f in scored if f.severity in ("critical", "high")]
    if priority:
        lines.append("")
        lines.append("### Priority Targets for Agent Follow-up")
        for f in priority[:8]:
            lines.append(f"")
            lines.append(f"**[{f.severity.upper()} score={f.score}]** {f.title} (id=`{f.id}`)")
            if f.target:
                lines.append(f"  Target: `{f.target}`")
            if f.suggestions:
                lines.append("  Suggestions:")
                for s in f.suggestions:
                    p = " ".join(f"{k}={v}" for k, v in s.params.items())
                    lines.append(f"    • `{s.tool} {s.action} {p}` [{s.requires_mode}] — {s.description}")
    return "\n".join(lines)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_first_ip(text: str) -> str:
    m = _IP_RE.search(text)
    return m.group(0) if m else ""


def _extract_cve_id(text: str) -> str:
    m = _CVE_RE.search(text)
    return m.group(0).upper() if m else ""
