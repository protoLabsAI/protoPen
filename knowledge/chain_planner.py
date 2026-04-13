"""Chain planner — recommend next tool actions based on target profile."""
from __future__ import annotations

import logging
from typing import Any

from knowledge.target_profile import TargetProfile

logger = logging.getLogger(__name__)


# Rule-based recommendation engine — maps conditions to suggested next steps
_RULES: list[dict[str, Any]] = [
    # Recon → Enumeration transitions
    {
        "name": "web_discovered",
        "condition": lambda p: p.has_service("http") or p.has_service("https"),
        "suggestions": [
            {"tool": "web_enum", "action": "gobuster_dir", "reason": "Web server found — enumerate directories"},
            {"tool": "ssl_audit", "action": "ssl_full_audit", "reason": "Check SSL/TLS configuration"},
            {"tool": "vuln_scan", "action": "nikto_scan", "reason": "Run Nikto web vulnerability scan"},
        ],
    },
    {
        "name": "smb_discovered",
        "condition": lambda p: p.has_service("smb") or p.has_service("microsoft-ds") or any(port.port in (139, 445) for port in p.ports),
        "suggestions": [
            {"tool": "service_enum", "action": "enum4linux_full", "reason": "SMB found — run enum4linux"},
            {"tool": "service_enum", "action": "smb_shares", "reason": "List SMB shares"},
        ],
    },
    {
        "name": "ssh_discovered",
        "condition": lambda p: p.has_service("ssh"),
        "suggestions": [
            {"tool": "credential_attack", "action": "hydra_brute", "reason": "SSH found — test credentials"},
        ],
    },
    {
        "name": "dns_service",
        "condition": lambda p: p.has_service("dns") or p.has_service("domain"),
        "suggestions": [
            {"tool": "dns_enum", "action": "zone_transfer", "reason": "DNS found — attempt zone transfer"},
            {"tool": "dns_enum", "action": "dns_brute", "reason": "Brute-force DNS subdomains"},
        ],
    },
    # Vuln Assessment transitions
    {
        "name": "web_paths_found",
        "condition": lambda p: len(p.web_paths) > 0,
        "suggestions": [
            {"tool": "web_vuln", "action": "xss_scan", "reason": "Web paths found — test for XSS"},
            {"tool": "sql_test", "action": "sqli_detect", "reason": "Test web endpoints for SQL injection"},
            {"tool": "api_enum", "action": "swagger_scan", "reason": "Check for exposed API documentation"},
        ],
    },
    {
        "name": "users_found",
        "condition": lambda p: len(p.users) > 0,
        "suggestions": [
            {"tool": "credential_attack", "action": "hydra_spray", "reason": "Users discovered — try password spray"},
        ],
    },
    # Exploitation transitions
    {
        "name": "vulns_found",
        "condition": lambda p: len(p.vulnerabilities) > 0,
        "suggestions": [
            {"tool": "msf_exploit", "action": "msf_search", "reason": "Vulnerabilities found — search for exploits"},
            {"tool": "cve_match", "action": "cve_search", "reason": "Cross-reference CVEs with exploit-db"},
        ],
    },
    {
        "name": "creds_found",
        "condition": lambda p: len(p.credentials) > 0,
        "suggestions": [
            {"tool": "lateral_move", "action": "psexec", "reason": "Credentials found — attempt lateral movement"},
            {"tool": "lateral_move", "action": "evil_winrm", "reason": "Try WinRM with discovered creds"},
        ],
    },
]


def suggest_next_steps(profile: TargetProfile, max_suggestions: int = 10) -> list[dict]:
    """Given a target profile, return ordered list of suggested next actions.

    Returns:
        List of dicts with keys: tool, action, reason, rule_name
    """
    suggestions: list[dict] = []
    for rule in _RULES:
        try:
            if rule["condition"](profile):
                for suggestion in rule["suggestions"]:
                    suggestions.append({
                        **suggestion,
                        "rule_name": rule["name"],
                    })
        except Exception as e:
            logger.warning("Rule '%s' evaluation failed: %s", rule["name"], e)

    return suggestions[:max_suggestions]


def format_suggestions(suggestions: list[dict]) -> str:
    """Format suggestions for display."""
    if not suggestions:
        return "No specific recommendations — consider running a full port scan first."
    lines = ["Recommended next steps:"]
    for i, s in enumerate(suggestions, 1):
        lines.append(f"  {i}. [{s['tool']}.{s['action']}] {s['reason']}")
    return "\n".join(lines)
