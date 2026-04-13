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

    def test_mixed_leans_negative(self):
        # "error" is a negative indicator
        assert _prose_has_results("error") is False


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
        data = json.dumps({
            "target": "192.168.4.1",
            "checks_run": 5,
            "issues": [{"severity": "high", "check": "PasswordAuthentication"}],
            "fail_count": 1,
        })
        results = normalize_blue("cis_audit", "ssh_audit", data)
        assert len(results) == 2
        assert results[0]["technique_id"] == "T1021"
        assert results[0]["detected"] is True
        assert results[1]["technique_id"] == "T1110"
        assert results[1]["detected"] is True

    def test_ssh_audit_clean(self):
        data = json.dumps({
            "target": "192.168.4.1",
            "checks_run": 5,
            "issues": [],
            "fail_count": 0,
        })
        results = normalize_blue("cis_audit", "ssh_audit", data)
        assert len(results) == 2
        assert results[0]["detected"] is False

    def test_unknown_tool(self):
        assert normalize_blue("unknown", "unknown", "anything") == []


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
