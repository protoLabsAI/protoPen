"""Tests for ipv6_attack parsers."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from tools.parsers.ipv6_attack import (
    parse_alive6,
    parse_detect_sniffer6,
    parse_thc_text,
    parse_nmap_ipv6,
)


@pytest.fixture
def store():
    return MagicMock()


# ── alive6 ───────────────────────────────────────────────────────────────────


class TestParseAlive6:
    def test_hosts_found(self, store):
        raw = "fe80::1\nfe80::2\nfe80::dead:beef\n"
        entities = parse_alive6(raw, store)
        assert len(entities) == 3
        assert entities[0]["type"] == "ipv6_finding"
        assert entities[0]["target"] == "fe80::1"
        assert entities[2]["target"] == "fe80::dead:beef"

    def test_empty_output(self, store):
        assert parse_alive6("", store) == []

    def test_no_ipv6(self, store):
        assert parse_alive6("No hosts found\n", store) == []


# ── detect-sniffer6 ──────────────────────────────────────────────────────────


class TestParseDetectSniffer6:
    def test_sniffer_detected(self, store):
        raw = "Sniffer detected on fe80::bad\n"
        entities = parse_detect_sniffer6(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "high"

    def test_no_sniffer(self, store):
        raw = "Scan complete. No issues.\n"
        assert parse_detect_sniffer6(raw, store) == []

    def test_empty(self, store):
        assert parse_detect_sniffer6("", store) == []


# ── thc_text (generic) ───────────────────────────────────────────────────────


class TestParseThcText:
    def test_output_lines(self, store):
        raw = "Starting attack...\nPacket sent\nDone\n"
        entities = parse_thc_text(raw, store)
        assert len(entities) == 3
        assert entities[0]["type"] == "ipv6_finding"

    def test_empty(self, store):
        assert parse_thc_text("", store) == []


# ── nmap_ipv6 ────────────────────────────────────────────────────────────────


class TestParseNmapIPv6:
    def test_hosts_with_ports(self, store):
        raw = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" version="OpenSSH 9.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        entities = parse_nmap_ipv6(raw, store)
        assert len(entities) == 2
        assert entities[0]["target"] == "::1"
        assert entities[0]["port"] == "22"
        assert entities[0]["service"] == "ssh"
        assert entities[1]["port"] == "80"

    def test_no_hosts(self, store):
        raw = '<?xml version="1.0"?><nmaprun></nmaprun>'
        assert parse_nmap_ipv6(raw, store) == []

    def test_invalid_xml(self, store):
        assert parse_nmap_ipv6("not xml", store) == []
