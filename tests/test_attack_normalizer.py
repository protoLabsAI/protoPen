"""Tests for tools.parsers.attack_normalizer."""

from __future__ import annotations

import json

import pytest

from tools.parsers.attack_normalizer import (
    normalize_red,
    normalize_blue,
    normalize_step,
    _nmap_has_results,
    _json_has_issues,
    _prose_has_results,
)


# ── Heuristic tests ──────────────────────────────────────────────────

NMAP_XML_WITH_PORTS = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.4.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NMAP_XML_NO_PORTS = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.4.1" addrtype="ipv4"/>
    <ports/>
  </host>
</nmaprun>
"""


class TestNmapHeuristic:
    def test_xml_with_open_ports(self):
        assert _nmap_has_results(NMAP_XML_WITH_PORTS) is True

    def test_xml_no_open_ports(self):
        assert _nmap_has_results(NMAP_XML_NO_PORTS) is False

    def test_prose_with_results(self):
        assert _nmap_has_results("Found 3 open ports on host") is True

    def test_prose_no_results(self):
        assert _nmap_has_results("No hosts up, timed out") is False


class TestJsonHeuristic:
    def test_dict_with_issues(self):
        data = json.dumps({"issues": [{"check": "SSH"}], "fail_count": 1})
        assert _json_has_issues(data) is True

    def test_dict_no_issues(self):
        data = json.dumps({"issues": [], "fail_count": 0})
        assert _json_has_issues(data) is False

    def test_list_with_items(self):
        assert _json_has_issues('[{"finding": "weak"}]') is True

    def test_empty_list(self):
        assert _json_has_issues("[]") is False

    def test_dict_with_error_field(self):
        """JSON with 'error' key indicates tool failure — treat as no detection."""
        data = json.dumps({"target": "x", "error": "Connection refused", "issues": [{"severity": "info"}]})
        assert _json_has_issues(data) is False

    def test_dict_with_failed_count(self):
        """Hardening tools use 'failed' key instead of 'fail_count'."""
        data = json.dumps({"service": "ssh", "failed": 3, "passed": 5})
        assert _json_has_issues(data) is True

    def test_json_embedded_in_stderr(self):
        """JSON preceded by stderr lines should still be found."""
        raw = '[stderr] some warning\n{"issues": [{"check": "SSH"}], "fail_count": 1}'
        assert _json_has_issues(raw) is True

    def test_invalid_json_falls_to_prose(self):
        # Contains "found" keyword
        assert _json_has_issues("Found some issues in config") is True


class TestProseHeuristic:
    def test_positive_keywords(self):
        assert _prose_has_results("Port 22 open on target") is True

    def test_negative_keywords(self):
        assert _prose_has_results("No results found") is False

    def test_empty(self):
        assert _prose_has_results("") is False

    def test_whitespace_only(self):
        assert _prose_has_results("   \n  ") is False

    def test_stderr_prefix_is_failure(self):
        assert _prose_has_results('[stderr] File "<string>", line 1') is False

    def test_traceback_is_failure(self):
        assert _prose_has_results("Traceback (most recent call last):\n  File ...") is False

    def test_command_not_found(self):
        assert _prose_has_results("bash: dig: command not found") is False

    def test_no_such_file(self):
        assert _prose_has_results("dns_enum error (dig_query): [Errno 2] No such file or directory: 'dig'") is False

    def test_filenotfounderror(self):
        assert _prose_has_results("FileNotFoundError: [Errno 2] No such file or directory") is False


# ── normalize_red tests ──────────────────────────────────────────────


class TestNormalizeRed:
    def test_nmap_scan_with_results(self):
        results = normalize_red("blackarch", "nmap_scan", NMAP_XML_WITH_PORTS)
        assert len(results) == 1
        assert results[0]["technique_id"] == "T1046"
        assert results[0]["success"] is True

    def test_nmap_scan_no_results(self):
        results = normalize_red("blackarch", "nmap_scan", NMAP_XML_NO_PORTS)
        assert len(results) == 1
        assert results[0]["technique_id"] == "T1046"
        assert results[0]["success"] is False

    def test_unknown_tool(self):
        assert normalize_red("unknown", "unknown", "anything") == []

    def test_vuln_scan(self):
        results = normalize_red("vuln_scan", "nikto_scan", "Found vulnerable endpoint /admin")
        assert len(results) == 1
        assert results[0]["technique_id"] == "T1190"
        assert results[0]["success"] is True


# ── normalize_blue tests ─────────────────────────────────────────────


class TestNormalizeBlue:
    def test_ssh_audit_with_issues(self):
        data = json.dumps(
            {
                "target": "192.168.4.1",
                "checks_run": 5,
                "issues": [{"severity": "high", "check": "PasswordAuthentication"}],
                "fail_count": 1,
            }
        )
        results = normalize_blue("cis_audit", "ssh_audit", data)
        assert len(results) == 2
        assert results[0]["technique_id"] == "T1021"
        assert results[0]["detected"] is True
        assert results[1]["technique_id"] == "T1110"
        assert results[1]["detected"] is True

    def test_ssh_audit_clean(self):
        data = json.dumps(
            {
                "target": "192.168.4.1",
                "checks_run": 5,
                "issues": [],
                "fail_count": 0,
            }
        )
        results = normalize_blue("cis_audit", "ssh_audit", data)
        assert len(results) == 2
        assert results[0]["detected"] is False

    def test_unknown_tool(self):
        assert normalize_blue("unknown", "unknown", "anything") == []

    def test_tls_audit_connection_error(self):
        """TLS audit that returns JSON with 'error' → detected: false."""
        data = json.dumps(
            {
                "target": "192.168.4.1",
                "port": 443,
                "error": "[Errno 61] Connection refused",
                "issues": [{"severity": "info", "check": "TLS Connection"}],
            }
        )
        results = normalize_blue("cis_audit", "tls_audit", data)
        assert len(results) == 1
        assert results[0]["technique_id"] == "T1557"
        assert results[0]["detected"] is False

    def test_hardening_with_failures_detected(self):
        """Hardening tool that finds misconfigurations → detected: true."""
        data = json.dumps(
            {
                "service": "ssh",
                "target": "x",
                "total_checks": 8,
                "passed": 2,
                "failed": 6,
                "checks": [{"check": "PermitRootLogin", "passed": False}],
            }
        )
        results = normalize_blue("hardening_check", "ssh_harden", data)
        assert all(r["detected"] is True for r in results)

    def test_port_baseline_empty(self):
        """Port baseline with no output → detected: false."""
        results = normalize_blue("cis_audit", "port_baseline", "")
        assert all(r["detected"] is False for r in results)


# ── normalize_red error handling ─────────────────────────────────────


class TestNormalizeRedErrors:
    def test_dig_not_found(self):
        """dns_enum when dig is missing → success: false."""
        results = normalize_red(
            "dns_enum",
            "dig_query",
            "dns_enum error (dig_query): [Errno 2] No such file or directory: 'dig'",
        )
        assert len(results) == 1
        assert results[0]["technique_id"] == "T1018"
        assert results[0]["success"] is False

    def test_nikto_broken_json(self):
        """nikto returning broken JSON → success: false."""
        results = normalize_red("vuln_scan", "nikto_scan", "]}")
        assert len(results) == 1
        assert results[0]["success"] is False

    def test_nikto_not_installed(self):
        results = normalize_red(
            "vuln_scan",
            "nikto_scan",
            "[stderr] bash: nikto: command not found",
        )
        assert len(results) == 1
        assert results[0]["success"] is False

    def test_base_tool_not_found_json(self):
        """BasePentestTool returns JSON error when binary missing."""
        results = normalize_red(
            "vuln_scan",
            "nikto_scan",
            json.dumps({"error": "nikto not found", "tool": "vuln_scan", "action": "nikto_scan"}),
        )
        assert len(results) == 1
        assert results[0]["success"] is False


# ── normalize_step dispatch ──────────────────────────────────────────


class TestNormalizeStep:
    def test_red_dispatch(self):
        results = normalize_step("blackarch", "nmap_scan", NMAP_XML_WITH_PORTS, "red")
        assert results[0]["technique_id"] == "T1046"
        assert "success" in results[0]

    def test_blue_dispatch(self):
        data = json.dumps({"issues": [{"check": "X"}], "fail_count": 1})
        results = normalize_step("cis_audit", "ssh_audit", data, "blue")
        assert results[0]["technique_id"] == "T1021"
        assert "detected" in results[0]

    def test_unknown_phase(self):
        assert normalize_step("blackarch", "nmap_scan", "data", "unknown") == []


# ── Tier 4 ATT&CK coverage ───────────────────────────────────────────


class TestTier4Coverage:
    """Every Tier 4 tool action must map to at least one ATT&CK technique."""

    TIER4_ACTIONS = {
        "supply_chain": [
            "dependency_confusion_test",
            "typosquat_scan",
            "package_provenance_audit",
            "postinstall_audit",
            "trufflehog_scan",
            "gitleaks_scan",
            "depscan",
        ],
        "serverless_audit": [
            "lambda_inject_test",
            "edge_function_audit",
            "event_trigger_abuse",
            "tfstate_scan",
            "iac_security_scan",
            "serverless_misconfig",
            "cold_start_race",
        ],
        "spa_test": [
            "route_bypass",
            "state_inspect",
            "postmessage_scan",
            "token_leakage_audit",
            "dom_xss_scan",
            "js_source_map_check",
        ],
        "sdn_attack": [
            "sdn_controller_enum",
            "netconf_exploit",
            "network_policy_audit",
            "yang_model_enum",
            "restconf_test",
            "openflow_audit",
        ],
        "mobile_audit": [
            "apk_decompile",
            "static_analysis",
            "jadx_decompile",
            "drozer_scan",
            "frida_hook",
            "ssl_pinning_bypass",
            "ipc_audit",
            "keychain_dump",
        ],
        "recon_pipeline": [
            "full_pipeline",
            "subdomain_httpx",
            "nuclei_scan",
            "screenshot_capture",
            "asset_correlate",
            "attack_graph_build",
            "tech_detect",
        ],
    }

    def test_every_tier4_action_has_a_rule(self):
        from tools.parsers.attack_normalizer import _RED_RULES

        missing = [
            (tool, action)
            for tool, actions in self.TIER4_ACTIONS.items()
            for action in actions
            if (tool, action) not in _RED_RULES
        ]
        assert missing == [], f"Tier 4 actions without ATT&CK rules: {missing}"

    def test_rules_carry_valid_technique_ids(self):
        import re

        from tools.parsers.attack_normalizer import _RED_RULES

        tid = re.compile(r"^T\d{4}(\.\d{3})?$")
        for tool, actions in self.TIER4_ACTIONS.items():
            for action in actions:
                for rule in _RED_RULES[(tool, action)]:
                    assert tid.match(rule["technique_id"]), f"bad id {rule} for {tool}/{action}"
                    assert rule["technique_name"]

    def test_normalize_red_marks_success_on_findings(self):
        raw = json.dumps({"confused_packages": [{"name": "@acme/x", "severity": "critical"}]})
        results = normalize_red("supply_chain", "dependency_confusion_test", raw)
        assert results[0]["technique_id"] == "T1195.002"
        assert results[0]["success"] is True
