"""Normalize raw tool outputs to ATT&CK-aligned purple team format.

Converts prose / structured tool outputs into:
  red:  [{"technique_id": "T1046", "technique_name": "...", "success": bool}]
  blue: [{"technique_id": "T1046", "technique_name": "...", "detected": bool}]

Used by the playbook runner's ``normalize`` step directive to bridge
raw tool output → ``purple_team.coverage_matrix`` / ``exercise_report`` input.
"""
from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

# ── Technique mappings per (tool, action) ─────────────────────────────

_RED_RULES: dict[tuple[str, str], list[dict]] = {
    ("blackarch", "nmap_scan"): [
        {"technique_id": "T1046", "technique_name": "Network Service Discovery"},
    ],
    ("blackarch", "nmap_vuln_scan"): [
        {"technique_id": "T1046", "technique_name": "Network Service Discovery"},
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
    ],
    ("dns_enum", "dig_query"): [
        {"technique_id": "T1018", "technique_name": "Remote System Discovery"},
    ],
    ("vuln_scan", "nikto_scan"): [
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
    ],
    ("credential_attack", "hydra_ssh"): [
        {"technique_id": "T1110", "technique_name": "Brute Force"},
    ],
    ("credential_attack", "hydra_http"): [
        {"technique_id": "T1110", "technique_name": "Brute Force"},
    ],
    ("msf_exploit", "exploit_run"): [
        {"technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation"},
    ],
    ("lateral_move", "psexec"): [
        {"technique_id": "T1021", "technique_name": "Remote Services"},
    ],
    ("lateral_move", "wmiexec"): [
        {"technique_id": "T1021", "technique_name": "Remote Services"},
    ],
    # Tier 2 — CI/CD audit
    ("cicd_audit", "trufflehog_scan"): [
        {"technique_id": "T1552", "technique_name": "Unsecured Credentials"},
    ],
    ("cicd_audit", "gitleaks_detect"): [
        {"technique_id": "T1552", "technique_name": "Unsecured Credentials"},
    ],
    ("cicd_audit", "semgrep_ci"): [
        {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"},
    ],
    # Tier 2 — IPv6
    ("ipv6_attack", "alive6"): [
        {"technique_id": "T1018", "technique_name": "Remote System Discovery"},
    ],
    ("ipv6_attack", "nmap_ipv6"): [
        {"technique_id": "T1046", "technique_name": "Network Service Discovery"},
    ],
    ("ipv6_attack", "fake_router6"): [
        {"technique_id": "T1557", "technique_name": "Adversary-in-the-Middle"},
    ],
    ("ipv6_attack", "parasite6"): [
        {"technique_id": "T1557", "technique_name": "Adversary-in-the-Middle"},
    ],
    # Tier 2 — IoT
    ("iot_protocol", "mqtt_bruteforce"): [
        {"technique_id": "T1110", "technique_name": "Brute Force"},
    ],
    ("iot_protocol", "modbus_scan"): [
        {"technique_id": "T1046", "technique_name": "Network Service Discovery"},
    ],
    # Tier 2 — AD
    ("ad_attack", "bloodhound_collect"): [
        {"technique_id": "T1087", "technique_name": "Account Discovery"},
    ],
    ("ad_attack", "certipy_vuln"): [
        {"technique_id": "T1649", "technique_name": "Steal or Forge Authentication Certificates"},
    ],
    ("ad_attack", "kerberoast"): [
        {"technique_id": "T1558", "technique_name": "Steal or Forge Kerberos Tickets"},
    ],
    ("ad_attack", "asreproast"): [
        {"technique_id": "T1558", "technique_name": "Steal or Forge Kerberos Tickets"},
    ],
    ("ad_attack", "secretsdump"): [
        {"technique_id": "T1003", "technique_name": "OS Credential Dumping"},
    ],
    # Tier 3 — LLM
    ("llm_audit", "prompt_inject_test"): [
        {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"},
    ],
    ("llm_audit", "jailbreak_test"): [
        {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"},
    ],
    # Tier 3 — Telecom
    ("telecom_attack", "gtp_scan"): [
        {"technique_id": "T1046", "technique_name": "Network Service Discovery"},
    ],
    ("telecom_attack", "sip_crack"): [
        {"technique_id": "T1110", "technique_name": "Brute Force"},
    ],
    ("telecom_attack", "imsi_detect"): [
        {"technique_id": "T1040", "technique_name": "Network Sniffing"},
    ],
    # Tier 3 — Evasion
    ("evasion", "msfvenom_generate"): [
        {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information"},
    ],
    ("evasion", "scarecrow_generate"): [
        {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information"},
    ],
    # Tier 3 — Phishing
    ("phishing", "gophish_create_campaign"): [
        {"technique_id": "T1566", "technique_name": "Phishing"},
    ],
    ("phishing", "smtp_relay_test"): [
        {"technique_id": "T1566", "technique_name": "Phishing"},
    ],
    # Tier 3 — gRPC
    ("grpc_audit", "grpc_reflection"): [
        {"technique_id": "T1046", "technique_name": "Network Service Discovery"},
    ],
    ("grpc_audit", "grpc_auth_test"): [
        {"technique_id": "T1550", "technique_name": "Use Alternate Authentication Material"},
    ],
    # Tier 3 — Auth
    ("auth_audit", "jwt_scan"): [
        {"technique_id": "T1550", "technique_name": "Use Alternate Authentication Material"},
    ],
    ("auth_audit", "oauth_redirect_test"): [
        {"technique_id": "T1078", "technique_name": "Valid Accounts"},
    ],
    ("auth_audit", "session_fixation"): [
        {"technique_id": "T1550", "technique_name": "Use Alternate Authentication Material"},
    ],
}

_BLUE_RULES: dict[tuple[str, str], list[dict]] = {
    ("cis_audit", "ssh_audit"): [
        {"technique_id": "T1021", "technique_name": "Remote Services"},
        {"technique_id": "T1110", "technique_name": "Brute Force"},
    ],
    ("cis_audit", "tls_audit"): [
        {"technique_id": "T1557", "technique_name": "Adversary-in-the-Middle"},
    ],
    ("cis_audit", "port_baseline"): [
        {"technique_id": "T1046", "technique_name": "Network Service Discovery"},
    ],
    ("cis_audit", "firewall_audit"): [
        {"technique_id": "T1046", "technique_name": "Network Service Discovery"},
    ],
    ("hardening_check", "ssh_harden"): [
        {"technique_id": "T1098", "technique_name": "Account Manipulation"},
        {"technique_id": "T1021", "technique_name": "Remote Services"},
    ],
    ("hardening_check", "nginx_harden"): [
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
    ],
    ("hardening_check", "apache_harden"): [
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
    ],
    ("net_monitor", "traffic_baseline"): [
        {"technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol"},
    ],
    ("ir_toolkit", "ioc_scan"): [
        {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"},
    ],
    ("ir_toolkit", "auth_log_analyze"): [
        {"technique_id": "T1110", "technique_name": "Brute Force"},
        {"technique_id": "T1078", "technique_name": "Valid Accounts"},
    ],
}


# ── Success / detection heuristics ────────────────────────────────────

def _nmap_has_results(raw: str) -> bool:
    """Check if nmap XML contains at least one open port."""
    try:
        root = ET.fromstring(raw)
        return any(
            port.find("state") is not None
            and port.find("state").get("state") == "open"  # type: ignore[union-attr]
            for host in root.findall("host")
            for port in (host.find("ports") or [])
        )
    except ET.ParseError:
        # Might be prose from LLM dispatch — check for port-like patterns
        return _prose_has_results(raw)


def _json_has_issues(raw: str) -> bool:
    """Check if JSON output contains issues or findings."""
    # Strip stderr prefix lines to find embedded JSON
    lines = raw.strip().splitlines()
    json_str = raw
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("{") or (stripped.startswith("[") and not stripped.startswith("[stderr")):
            json_str = "\n".join(lines[i:])
            break

    try:
        data = json.loads(json_str)
        if isinstance(data, dict):
            # If tool itself reported an error, treat as no detection
            if data.get("error"):
                return False
            return bool(data.get("issues") or data.get("findings")
                        or data.get("fail_count", 0) > 0
                        or data.get("failed", 0) > 0)
        if isinstance(data, list):
            return len(data) > 0
    except (json.JSONDecodeError, TypeError):
        pass
    return _prose_has_results(raw)


def _prose_has_results(raw: str) -> bool:
    """Heuristic: check if prose output indicates positive findings."""
    if not raw or not raw.strip():
        return False
    lower = raw.lower()
    # If output is mostly stderr, treat as failure
    if lower.startswith("[stderr]") or lower.startswith("traceback"):
        return False
    # Positive indicators
    positive = any(kw in lower for kw in [
        "open", "found", "detected", "vulnerable", "issue",
        "warning", "critical", "high", "fail",
        "port", "service", "record",
    ])
    # Negative indicators (empty / no-results)
    negative = any(kw in lower for kw in [
        "no results", "no hosts", "no open", "timed out",
        "unreachable", "0 hosts up",
        "command not found", "no such file", "not found",
        "filenotfounderror", "errno 2",
    ])
    return positive and not negative


# Map (tool, action) -> heuristic function
_HEURISTIC: dict[tuple[str, str], callable] = {
    ("blackarch", "nmap_scan"): _nmap_has_results,
    ("blackarch", "nmap_vuln_scan"): _nmap_has_results,
    ("dns_enum", "dig_query"): _prose_has_results,
    ("vuln_scan", "nikto_scan"): _prose_has_results,
    ("credential_attack", "hydra_ssh"): _prose_has_results,
    ("credential_attack", "hydra_http"): _prose_has_results,
    ("msf_exploit", "exploit_run"): _prose_has_results,
    ("lateral_move", "psexec"): _prose_has_results,
    ("lateral_move", "wmiexec"): _prose_has_results,
    ("cis_audit", "ssh_audit"): _json_has_issues,
    ("cis_audit", "tls_audit"): _json_has_issues,
    ("cis_audit", "port_baseline"): _json_has_issues,
    ("cis_audit", "firewall_audit"): _json_has_issues,
    ("hardening_check", "ssh_harden"): _json_has_issues,
    ("hardening_check", "nginx_harden"): _json_has_issues,
    ("hardening_check", "apache_harden"): _json_has_issues,
    ("net_monitor", "traffic_baseline"): _json_has_issues,
    ("ir_toolkit", "ioc_scan"): _json_has_issues,
    ("ir_toolkit", "auth_log_analyze"): _json_has_issues,
    # Tier 2 — CI/CD
    ("cicd_audit", "trufflehog_scan"): _prose_has_results,
    ("cicd_audit", "gitleaks_detect"): _json_has_issues,
    ("cicd_audit", "semgrep_ci"): _json_has_issues,
    # Tier 2 — IPv6
    ("ipv6_attack", "alive6"): _prose_has_results,
    ("ipv6_attack", "nmap_ipv6"): _nmap_has_results,
    ("ipv6_attack", "fake_router6"): _prose_has_results,
    ("ipv6_attack", "parasite6"): _prose_has_results,
    # Tier 2 — IoT
    ("iot_protocol", "mqtt_bruteforce"): _prose_has_results,
    ("iot_protocol", "modbus_scan"): _nmap_has_results,
    # Tier 2 — AD
    ("ad_attack", "bloodhound_collect"): _prose_has_results,
    ("ad_attack", "certipy_vuln"): _json_has_issues,
    ("ad_attack", "kerberoast"): _prose_has_results,
    ("ad_attack", "asreproast"): _prose_has_results,
    ("ad_attack", "secretsdump"): _prose_has_results,
    # Tier 3 — LLM
    ("llm_audit", "prompt_inject_test"): _json_has_issues,
    ("llm_audit", "jailbreak_test"): _json_has_issues,
    # Tier 3 — Telecom
    ("telecom_attack", "gtp_scan"): _json_has_issues,
    ("telecom_attack", "sip_crack"): _json_has_issues,
    ("telecom_attack", "imsi_detect"): _prose_has_results,
    # Tier 3 — Evasion
    ("evasion", "msfvenom_generate"): _prose_has_results,
    ("evasion", "scarecrow_generate"): _prose_has_results,
    # Tier 3 — Phishing
    ("phishing", "gophish_create_campaign"): _json_has_issues,
    ("phishing", "smtp_relay_test"): _prose_has_results,
    # Tier 3 — gRPC
    ("grpc_audit", "grpc_reflection"): _prose_has_results,
    ("grpc_audit", "grpc_auth_test"): _prose_has_results,
    # Tier 3 — Auth
    ("auth_audit", "jwt_scan"): _json_has_issues,
    ("auth_audit", "oauth_redirect_test"): _json_has_issues,
    ("auth_audit", "session_fixation"): _json_has_issues,
}


# ── Public API ────────────────────────────────────────────────────────

def normalize_red(tool: str, action: str, raw: str) -> list[dict]:
    """Convert a red-team tool output to ATT&CK-aligned result dicts."""
    rules = _RED_RULES.get((tool, action))
    if not rules:
        logger.debug("No red normalization rule for %s/%s", tool, action)
        return []

    heuristic = _HEURISTIC.get((tool, action), _prose_has_results)
    success = heuristic(raw)

    return [
        {**rule, "success": success}
        for rule in rules
    ]


def normalize_blue(tool: str, action: str, raw: str) -> list[dict]:
    """Convert a blue-team tool output to ATT&CK-aligned result dicts."""
    rules = _BLUE_RULES.get((tool, action))
    if not rules:
        logger.debug("No blue normalization rule for %s/%s", tool, action)
        return []

    heuristic = _HEURISTIC.get((tool, action), _json_has_issues)
    detected = heuristic(raw)

    return [
        {**rule, "detected": detected}
        for rule in rules
    ]


def normalize_step(tool: str, action: str, raw: str, phase: str) -> list[dict]:
    """Normalize a step output based on its phase (red or blue).

    Args:
        tool: Tool name (e.g. "blackarch").
        action: Action name (e.g. "nmap_scan").
        raw: Raw output string from the step.
        phase: "red" or "blue".

    Returns:
        List of ATT&CK-aligned result dicts.
    """
    if phase == "red":
        return normalize_red(tool, action, raw)
    elif phase == "blue":
        return normalize_blue(tool, action, raw)
    else:
        logger.warning("Unknown phase '%s' for normalization", phase)
        return []
