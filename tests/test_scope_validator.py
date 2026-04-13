"""Tests for ScopeValidator — engagement scope enforcement."""
import pytest

from enforcement.scope import ScopeValidator


class TestCIDRScope:
    def test_ip_in_cidr(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        assert sv.is_in_scope("192.168.4.1") is True

    def test_ip_outside_cidr(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        assert sv.is_in_scope("10.0.0.1") is False

    def test_ip_in_multi_cidr(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24", "10.0.0.0/8"]})
        assert sv.is_in_scope("10.1.2.3") is True

    def test_single_host_cidr(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.100/32"]})
        assert sv.is_in_scope("192.168.4.100") is True
        assert sv.is_in_scope("192.168.4.101") is False

    def test_url_extracts_ip(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        assert sv.is_in_scope("http://192.168.4.50:8080/admin") is True

    def test_invalid_ip_returns_false(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        assert sv.is_in_scope("not-an-ip") is False

    def test_empty_target_returns_false(self):
        sv = ScopeValidator({"type": "cidr", "targets": ["192.168.4.0/24"]})
        assert sv.is_in_scope("") is False


class TestDomainScope:
    def test_exact_domain(self):
        sv = ScopeValidator({"type": "domain", "targets": ["example.com"]})
        assert sv.is_in_scope("example.com") is True

    def test_wildcard_domain(self):
        sv = ScopeValidator({"type": "domain", "targets": ["*.example.com"]})
        assert sv.is_in_scope("sub.example.com") is True

    def test_wildcard_rejects_other_domain(self):
        sv = ScopeValidator({"type": "domain", "targets": ["*.example.com"]})
        assert sv.is_in_scope("evil.com") is False

    def test_url_extracts_domain(self):
        sv = ScopeValidator({"type": "domain", "targets": ["*.example.com"]})
        assert sv.is_in_scope("https://api.example.com/v1/users") is True

    def test_domain_case_insensitive(self):
        sv = ScopeValidator({"type": "domain", "targets": ["*.Example.COM"]})
        assert sv.is_in_scope("sub.example.com") is True

    def test_multi_domain(self):
        sv = ScopeValidator({"type": "domain", "targets": ["*.example.com", "*.test.org"]})
        assert sv.is_in_scope("api.test.org") is True
        assert sv.is_in_scope("evil.net") is False


class TestAnyScope:
    def test_any_allows_everything(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.is_in_scope("1.2.3.4") is True
        assert sv.is_in_scope("evil.com") is True
        assert sv.is_in_scope("") is True


class TestExtractTarget:
    def test_nmap_scan_extracts_target(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("nmap_scan", {"target": "192.168.1.1"}) == "192.168.1.1"

    def test_nmap_vuln_scan_extracts_target(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("nmap_vuln_scan", {"target": "10.0.0.1"}) == "10.0.0.1"

    def test_gobuster_extracts_url(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("gobuster_scan", {"url": "http://example.com"}) == "http://example.com"

    def test_nikto_extracts_url(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("nikto_scan", {"url": "https://10.0.0.1"}) == "https://10.0.0.1"

    def test_shell_exec_returns_none(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("shell_exec", {"command": "nmap 1.2.3.4"}) is None

    def test_unknown_tool_returns_none(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("unknown_tool", {"foo": "bar"}) is None

    def test_missing_arg_returns_none(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("nmap_scan", {}) is None

    def test_bettercap_recon_returns_none(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("bettercap_recon", {"interface": "eth0"}) is None

    def test_wifi_deauth_returns_none(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("wifi_deauth", {"indices": "0,1"}) is None

    def test_hashcat_returns_none(self):
        sv = ScopeValidator({"type": "any"})
        assert sv.extract_target("hashcat_crack", {"hash_file": "/tmp/hashes"}) is None


class TestEmptyAndMalformedConfig:
    def test_empty_targets_cidr(self):
        sv = ScopeValidator({"type": "cidr", "targets": []})
        assert sv.is_in_scope("1.2.3.4") is False

    def test_missing_targets_key(self):
        sv = ScopeValidator({"type": "cidr"})
        assert sv.is_in_scope("1.2.3.4") is False

    def test_unknown_type_defaults_to_deny(self):
        sv = ScopeValidator({"type": "bogus", "targets": ["*"]})
        assert sv.is_in_scope("1.2.3.4") is False
