"""Tests for blue-team output parsers — cis_audit, net_monitor, hardening_check, ir_toolkit."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def store():
    """Mock TargetStore with upsert_host for net_monitor parser."""
    s = MagicMock()
    return s


# ── PARSER_MAP Registration ─────────────────────────────────────────────────


class TestBlueTeamParserRegistration:
    def test_cis_audit_entries(self):
        from tools.parsers import PARSER_MAP

        assert ("cis_audit", "ssh_audit") in PARSER_MAP
        assert ("cis_audit", "tls_audit") in PARSER_MAP
        assert ("cis_audit", "firewall_audit") in PARSER_MAP
        assert ("cis_audit", "patch_check") in PARSER_MAP
        assert ("cis_audit", "port_baseline") in PARSER_MAP

    def test_net_monitor_entries(self):
        from tools.parsers import PARSER_MAP

        assert ("net_monitor", "traffic_baseline") in PARSER_MAP
        assert ("net_monitor", "host_discovery") in PARSER_MAP
        assert ("net_monitor", "service_diff") in PARSER_MAP
        assert ("net_monitor", "dns_monitor") in PARSER_MAP
        assert ("net_monitor", "protocol_anomaly") in PARSER_MAP

    def test_hardening_check_entries(self):
        from tools.parsers import PARSER_MAP

        assert ("hardening_check", "ssh_harden") in PARSER_MAP
        assert ("hardening_check", "nginx_harden") in PARSER_MAP
        assert ("hardening_check", "apache_harden") in PARSER_MAP
        assert ("hardening_check", "docker_harden") in PARSER_MAP
        assert ("hardening_check", "k8s_harden") in PARSER_MAP

    def test_ir_toolkit_entries(self):
        from tools.parsers import PARSER_MAP

        assert ("ir_toolkit", "log_search") in PARSER_MAP
        assert ("ir_toolkit", "ioc_scan") in PARSER_MAP
        assert ("ir_toolkit", "auth_log_analyze") in PARSER_MAP
        assert ("ir_toolkit", "timeline_build") in PARSER_MAP
        assert ("ir_toolkit", "containment_recommend") in PARSER_MAP


# ── CIS Audit Parsers ───────────────────────────────────────────────────────


class TestCisAuditParsers:
    def test_ssh_audit_with_issues(self, store):
        from tools.parsers.cis_audit import parse_cis_checks

        raw = json.dumps(
            {
                "target": "10.0.0.1",
                "checks_run": 5,
                "issues": [
                    {
                        "severity": "high",
                        "check": "PasswordAuthentication",
                        "value": "yes",
                        "recommendation": "Set to no",
                    },
                    {
                        "severity": "critical",
                        "check": "PermitEmptyPasswords",
                        "value": "yes",
                        "recommendation": "Set to no",
                    },
                ],
                "pass_count": 3,
                "fail_count": 2,
            }
        )
        entities = parse_cis_checks(raw, store)
        assert len(entities) == 2
        assert all(e["type"] == "cis_finding" for e in entities)
        assert entities[0]["target"] == "10.0.0.1"
        assert entities[0]["severity"] == "high"
        assert entities[1]["severity"] == "critical"

    def test_ssh_audit_no_issues(self, store):
        from tools.parsers.cis_audit import parse_cis_checks

        raw = json.dumps({"target": "10.0.0.1", "issues": [], "pass_count": 5})
        entities = parse_cis_checks(raw, store)
        assert entities == []

    def test_tls_audit_with_error(self, store):
        from tools.parsers.cis_audit import parse_tls_audit

        raw = json.dumps(
            {
                "target": "example.com",
                "port": 443,
                "error": "Connection refused",
                "issues": [{"severity": "info", "check": "TLS Connection", "value": "Connection refused"}],
            }
        )
        entities = parse_tls_audit(raw, store)
        assert len(entities) == 2  # error finding + issue finding
        assert entities[0]["check"] == "TLS Connection"

    def test_tls_audit_weak_cipher(self, store):
        from tools.parsers.cis_audit import parse_tls_audit

        raw = json.dumps(
            {
                "target": "10.0.0.1",
                "port": 443,
                "protocol": "TLSv1.2",
                "issues": [
                    {
                        "severity": "high",
                        "check": "Cipher Strength",
                        "value": "RC4 (40 bits)",
                        "recommendation": "Use 128-bit+ ciphers",
                    }
                ],
            }
        )
        entities = parse_tls_audit(raw, store)
        assert len(entities) == 1
        assert entities[0]["target"] == "10.0.0.1:443"
        assert entities[0]["severity"] == "high"

    def test_patch_check_with_updates(self, store):
        from tools.parsers.cis_audit import parse_patch_check

        raw = json.dumps(
            {
                "os": "Linux",
                "pending_updates": 15,
                "packages": ["openssl", "curl", "libssh"],
                "severity": "high",
            }
        )
        entities = parse_patch_check(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "cis_finding"
        assert "15 updates" in entities[0]["value"]
        assert entities[0]["severity"] == "high"

    def test_patch_check_no_updates(self, store):
        from tools.parsers.cis_audit import parse_patch_check

        raw = json.dumps({"os": "Linux", "pending_updates": 0, "packages": [], "severity": "info"})
        entities = parse_patch_check(raw, store)
        assert entities == []

    def test_port_baseline_unexpected(self, store):
        from tools.parsers.cis_audit import parse_port_baseline

        raw = json.dumps(
            {
                "target": "10.0.0.1",
                "unexpected": [{"port": 8080, "service": "http-proxy"}],
                "missing_expected": [443],
            }
        )
        entities = parse_port_baseline(raw, store)
        assert len(entities) == 2
        assert entities[0]["check"] == "Unexpected Open Port"
        assert entities[0]["severity"] == "high"
        assert entities[1]["check"] == "Missing Expected Port"
        assert entities[1]["severity"] == "medium"

    def test_invalid_json(self, store):
        from tools.parsers.cis_audit import parse_cis_checks

        assert parse_cis_checks("not json", store) == []


# ── Net Monitor Parsers ──────────────────────────────────────────────────────


class TestNetMonitorParsers:
    def test_traffic_baseline(self, store):
        from tools.parsers.net_monitor import parse_traffic_baseline

        raw = json.dumps(
            {
                "interface": "eth0",
                "duration_sec": 30,
                "packet_count": 1500,
                "total_bytes": 200000,
                "top_hosts": {"10.0.0.1": 500},
                "top_ports": {"443": 800},
            }
        )
        entities = parse_traffic_baseline(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "net_baseline"
        assert entities[0]["packet_count"] == 1500

    def test_host_discovery_new_hosts(self, store):
        from tools.parsers.net_monitor import parse_host_discovery

        raw = json.dumps(
            {
                "network": "192.168.1.0/24",
                "hosts": [
                    {"ip": "192.168.1.1", "hostname": "router"},
                    {"ip": "192.168.1.99", "hostname": ""},
                ],
                "new_hosts": [{"ip": "192.168.1.99", "hostname": ""}],
                "anomaly": True,
            }
        )
        entities = parse_host_discovery(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "net_anomaly"
        assert entities[0]["anomaly_type"] == "new_host"
        assert entities[0]["ip"] == "192.168.1.99"
        # Should upsert all discovered hosts
        assert store.upsert_host.call_count == 2

    def test_host_discovery_no_anomaly(self, store):
        from tools.parsers.net_monitor import parse_host_discovery

        raw = json.dumps({"hosts": [{"ip": "10.0.0.1"}], "new_hosts": []})
        entities = parse_host_discovery(raw, store)
        assert entities == []

    def test_service_diff_changes(self, store):
        from tools.parsers.net_monitor import parse_service_diff

        raw = json.dumps(
            {
                "target": "10.0.0.1",
                "new_services": [{"port": 9090, "service": "prometheus", "version": "2.x"}],
                "removed_services": [{"port": 8080, "service": "http-alt"}],
            }
        )
        entities = parse_service_diff(raw, store)
        assert len(entities) == 2
        new_svc = [e for e in entities if e["anomaly_type"] == "new_service"]
        removed = [e for e in entities if e["anomaly_type"] == "removed_service"]
        assert len(new_svc) == 1
        assert new_svc[0]["severity"] == "high"
        assert len(removed) == 1
        assert removed[0]["severity"] == "medium"

    def test_dns_monitor_suspicious(self, store):
        from tools.parsers.net_monitor import parse_dns_monitor

        raw = json.dumps(
            {
                "suspicious": [
                    {"type": "long_label", "domain": "a" * 50 + ".evil.com", "note": "Possible DNS tunneling"},
                    {"type": "high_volume", "domain": "api.evil.com", "note": "High query rate"},
                ],
            }
        )
        entities = parse_dns_monitor(raw, store)
        assert len(entities) == 2
        assert entities[0]["anomaly_type"] == "dns_long_label"
        assert entities[1]["anomaly_type"] == "dns_high_volume"

    def test_protocol_anomaly(self, store):
        from tools.parsers.net_monitor import parse_protocol_anomaly

        raw = json.dumps(
            {
                "unexpected_protocols": [{"protocol": "icmp:tunneling", "count": 42}],
            }
        )
        entities = parse_protocol_anomaly(raw, store)
        assert len(entities) == 1
        assert entities[0]["anomaly_type"] == "unexpected_protocol"
        assert entities[0]["count"] == 42

    def test_invalid_json(self, store):
        from tools.parsers.net_monitor import parse_traffic_baseline

        assert parse_traffic_baseline("not json", store) == []


# ── Hardening Check Parser ───────────────────────────────────────────────────


class TestHardeningCheckParser:
    def test_failed_checks_only(self, store):
        from tools.parsers.hardening_check import parse_hardening

        raw = json.dumps(
            {
                "service": "ssh",
                "target": "10.0.0.1",
                "total_checks": 8,
                "passed": 5,
                "failed": 3,
                "checks": [
                    {
                        "check": "PermitRootLogin",
                        "passed": False,
                        "severity": "critical",
                        "expected": "no",
                        "actual": "yes",
                        "remediation": "Set PermitRootLogin no",
                    },
                    {"check": "MaxAuthTries", "passed": True, "severity": "medium"},
                    {
                        "check": "PasswordAuthentication",
                        "passed": False,
                        "severity": "high",
                        "expected": "no",
                        "actual": "yes",
                        "remediation": "Set PasswordAuthentication no",
                    },
                    {
                        "check": "X11Forwarding",
                        "passed": False,
                        "severity": "medium",
                        "expected": "no",
                        "actual": "yes",
                        "remediation": "Set X11Forwarding no",
                    },
                ],
            }
        )
        entities = parse_hardening(raw, store)
        # Only failed checks (3 of 4 — MaxAuthTries passed)
        assert len(entities) == 3
        assert all(e["type"] == "hardening_finding" for e in entities)
        assert entities[0]["service"] == "ssh"
        assert entities[0]["check"] == "PermitRootLogin"
        assert entities[0]["severity"] == "critical"

    def test_all_passed(self, store):
        from tools.parsers.hardening_check import parse_hardening

        raw = json.dumps(
            {
                "service": "nginx",
                "total_checks": 3,
                "passed": 3,
                "failed": 0,
                "checks": [
                    {"check": "server_tokens", "passed": True, "severity": "high"},
                    {"check": "HSTS", "passed": True, "severity": "high"},
                    {"check": "CSP", "passed": True, "severity": "medium"},
                ],
            }
        )
        entities = parse_hardening(raw, store)
        assert entities == []

    def test_invalid_json(self, store):
        from tools.parsers.hardening_check import parse_hardening

        assert parse_hardening("not json", store) == []


# ── IR Toolkit Parsers ───────────────────────────────────────────────────────


class TestIrToolkitParsers:
    def test_log_search_with_matches(self, store):
        from tools.parsers.ir_toolkit import parse_log_search

        raw = json.dumps(
            {
                "pattern": "failed password",
                "log_path": "/var/log",
                "match_count": 25,
                "matches": [{"file": "/var/log/auth.log", "line_num": "10", "content": "Failed password"}],
            }
        )
        entities = parse_log_search(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "ir_finding"
        assert entities[0]["finding_type"] == "log_match"
        assert entities[0]["match_count"] == 25

    def test_log_search_no_matches(self, store):
        from tools.parsers.ir_toolkit import parse_log_search

        raw = json.dumps({"pattern": "xyz", "match_count": 0, "matches": []})
        entities = parse_log_search(raw, store)
        assert entities == []

    def test_ioc_scan_findings(self, store):
        from tools.parsers.ir_toolkit import parse_ioc_scan

        raw = json.dumps(
            {
                "findings": [
                    {
                        "ioc_type": "ip",
                        "ioc_value": "198.51.100.1",
                        "file": "/var/log/syslog",
                        "line": 42,
                        "context": "connection from 198.51.100.1",
                    },
                    {
                        "ioc_type": "domain",
                        "ioc_value": "evil.com",
                        "file": "/var/log/dns.log",
                        "line": 99,
                        "context": "query for evil.com",
                    },
                ],
                "total_hits": 2,
            }
        )
        entities = parse_ioc_scan(raw, store)
        assert len(entities) == 2
        assert all(e["severity"] == "critical" for e in entities)
        assert entities[0]["ioc_value"] == "198.51.100.1"

    def test_auth_log_brute_force(self, store):
        from tools.parsers.ir_toolkit import parse_auth_log

        raw = json.dumps(
            {
                "failed_auth_total": 500,
                "brute_force_detected": [
                    {"ip": "203.0.113.5", "attempts": 200, "severity": "critical"},
                ],
                "success_after_brute_force": ["203.0.113.5"],
                "compromised_likely": True,
            }
        )
        entities = parse_auth_log(raw, store)
        assert len(entities) == 2
        bf = [e for e in entities if e["finding_type"] == "brute_force"]
        comp = [e for e in entities if e["finding_type"] == "compromised_account"]
        assert len(bf) == 1
        assert bf[0]["attempts"] == 200
        assert len(comp) == 1
        assert comp[0]["severity"] == "critical"

    def test_auth_log_no_compromise(self, store):
        from tools.parsers.ir_toolkit import parse_auth_log

        raw = json.dumps(
            {
                "brute_force_detected": [{"ip": "1.2.3.4", "attempts": 50, "severity": "high"}],
                "compromised_likely": False,
                "success_after_brute_force": [],
            }
        )
        entities = parse_auth_log(raw, store)
        assert len(entities) == 1
        assert entities[0]["finding_type"] == "brute_force"

    def test_timeline_build(self, store):
        from tools.parsers.ir_toolkit import parse_timeline

        raw = json.dumps(
            {
                "keyword": "ssh",
                "log_path": "/var/log",
                "event_count": 15,
                "timeline": [
                    {"timestamp": "2026-04-12T01:00:00", "source": "auth.log", "event": "first"},
                    {"timestamp": "2026-04-12T02:00:00", "source": "auth.log", "event": "last"},
                ],
            }
        )
        entities = parse_timeline(raw, store)
        assert len(entities) == 1
        assert entities[0]["finding_type"] == "timeline"
        assert entities[0]["event_count"] == 15
        assert entities[0]["first_event"] == "2026-04-12T01:00:00"

    def test_timeline_empty(self, store):
        from tools.parsers.ir_toolkit import parse_timeline

        raw = json.dumps({"keyword": "xyz", "event_count": 0, "timeline": []})
        entities = parse_timeline(raw, store)
        assert entities == []

    def test_containment_recommend(self, store):
        from tools.parsers.ir_toolkit import parse_containment

        raw = json.dumps(
            {
                "attack_type": "malware",
                "recommendations": {
                    "immediate": ["Disconnect infected hosts", "Block C2 domains"],
                    "short_term": ["Full AV scan"],
                    "long_term": ["Deploy EDR"],
                },
            }
        )
        entities = parse_containment(raw, store)
        assert len(entities) == 2  # only immediate actions
        assert all(e["finding_type"] == "containment_action" for e in entities)
        assert all(e["severity"] == "critical" for e in entities)
        assert all(e["phase"] == "immediate" for e in entities)

    def test_invalid_json(self, store):
        from tools.parsers.ir_toolkit import parse_log_search, parse_ioc_scan

        assert parse_log_search("bad", store) == []
        assert parse_ioc_scan("bad", store) == []
