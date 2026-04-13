"""Tests for nmap XML output parser."""
import pytest
from knowledge.target_store import TargetStore
from tools.parsers.nmap_xml import parse


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


NMAP_SINGLE_HOST = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 192.168.1.1">
  <host starttime="1712900000" endtime="1712900010">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme Corp"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.22"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.15" accuracy="95"/></os>
  </host>
</nmaprun>"""

NMAP_MULTI_HOST = """<?xml version="1.0"?>
<nmaprun>
  <host><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/>
      <service name="https"/></port></ports></host>
  <host><address addr="10.0.0.2" addrtype="ipv4"/>
    <ports><port protocol="udp" portid="53"><state state="open"/>
      <service name="dns"/></port></ports></host>
</nmaprun>"""

NMAP_NO_HOSTS = """<?xml version="1.0"?><nmaprun></nmaprun>"""

NMAP_GARBAGE = """not xml at all {{{"""


class TestNmapParser:
    def test_single_host_with_ports(self, store):
        entities = parse(NMAP_SINGLE_HOST, store)
        hosts = [e for e in entities if e["type"] == "host"]
        ports = [e for e in entities if e["type"] == "port"]
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "192.168.1.1"
        assert hosts[0]["mac"] == "AA:BB:CC:DD:EE:FF"
        assert hosts[0]["hostname"] == "router.local"
        assert hosts[0]["vendor"] == "Acme Corp"
        assert len(ports) == 2
        assert any(p["port"] == 22 and p["service"] == "ssh" for p in ports)
        assert any(p["port"] == 80 and p["service"] == "http" for p in ports)

    def test_os_detection(self, store):
        entities = parse(NMAP_SINGLE_HOST, store)
        hosts = [e for e in entities if e["type"] == "host"]
        assert hosts[0]["os"] == "Linux 5.15"

    def test_multi_host(self, store):
        entities = parse(NMAP_MULTI_HOST, store)
        hosts = [e for e in entities if e["type"] == "host"]
        assert len(hosts) == 2
        ips = {h["ip"] for h in hosts}
        assert ips == {"10.0.0.1", "10.0.0.2"}

    def test_host_persisted_to_store(self, store):
        parse(NMAP_SINGLE_HOST, store)
        rows = store.query_hosts(ip_prefix="192.168.1.")
        assert len(rows) == 1
        assert rows[0]["hostname"] == "router.local"

    def test_ports_persisted_to_store(self, store):
        parse(NMAP_SINGLE_HOST, store)
        hosts = store.query_hosts(ip_prefix="192.168.1.")
        ports = store.get_ports(hosts[0]["id"])
        assert len(ports) == 2

    def test_empty_nmaprun(self, store):
        entities = parse(NMAP_NO_HOSTS, store)
        assert entities == []

    def test_garbage_input(self, store):
        entities = parse(NMAP_GARBAGE, store)
        assert entities == []

    def test_idempotent_upsert(self, store):
        parse(NMAP_SINGLE_HOST, store)
        parse(NMAP_SINGLE_HOST, store)
        rows = store.query_hosts(ip_prefix="192.168.1.")
        assert len(rows) == 1
