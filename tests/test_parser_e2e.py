"""End-to-end: tool output → parser → TargetStore → query back."""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch
from knowledge.target_store import TargetStore


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


FULL_NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 192.168.1.0/24">
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:00:00:01" addrtype="mac" vendor="Netgear"/>
    <hostnames><hostname name="gw.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/></port>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="nginx"/></port>
      <port protocol="tcp" portid="443"><state state="open"/>
        <service name="https"/></port>
    </ports>
    <os><osmatch name="Linux 6.1" accuracy="98"/></os>
  </host>
  <host>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <address addr="AA:BB:CC:00:00:02" addrtype="mac" vendor="Raspberry Pi"/>
    <ports>
      <port protocol="tcp" portid="8080"><state state="open"/>
        <service name="http-proxy"/></port>
    </ports>
  </host>
</nmaprun>"""


class TestE2EPipeline:
    def test_nmap_full_pipeline(self, store):
        """nmap XML → parse → store → query hosts and ports."""
        from tools.blackarch import BlackArchTool

        tool = BlackArchTool()
        tool._target_store = store

        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=FULL_NMAP):
            asyncio.run(tool.execute(action="nmap_scan", target="192.168.1.0/24"))

        hosts = store.query_hosts(ip_prefix="192.168.1.")
        assert len(hosts) == 2

        gw = next(h for h in hosts if h["ip"] == "192.168.1.1")
        assert gw["hostname"] == "gw.local"
        assert gw["os"] == "Linux 6.1"
        assert gw["vendor"] == "Netgear"

        ports = store.get_ports(gw["id"])
        assert len(ports) == 3
        services = {p["service"] for p in ports}
        assert services == {"ssh", "http", "https"}

        rpi = next(h for h in hosts if h["ip"] == "192.168.1.50")
        rpi_ports = store.get_ports(rpi["id"])
        assert len(rpi_ports) == 1
        assert rpi_ports[0]["service"] == "http-proxy"

    def test_multi_tool_convergence(self, store):
        """nmap discovers host, bettercap rediscovers same host — single row, enriched."""
        from tools.blackarch import BlackArchTool

        tool = BlackArchTool()
        tool._target_store = store

        nmap_xml = """<?xml version="1.0"?><nmaprun>
          <host><address addr="10.0.0.1" addrtype="ipv4"/>
            <address addr="DE:AD:BE:EF:00:01" addrtype="mac"/>
            <ports><port protocol="tcp" portid="22"><state state="open"/>
              <service name="ssh"/></port></ports></host>
        </nmaprun>"""

        bettercap_out = "│ 10.0.0.1       │ DE:AD:BE:EF:00:01 │ router           │ Cisco            │  10k │   20k │"

        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=nmap_xml):
            asyncio.run(tool.execute(action="nmap_scan", target="10.0.0.1"))

        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=bettercap_out):
            asyncio.run(tool.execute(action="bettercap_recon", interface="eth0"))

        hosts = store.query_hosts(ip_prefix="10.0.0.")
        assert len(hosts) == 1
        assert hosts[0]["vendor"] == "Cisco"
        assert hosts[0]["hostname"] == "router"

    def test_diff_after_scans(self, store):
        """diff_since shows new entities from scans."""
        from tools.blackarch import BlackArchTool

        tool = BlackArchTool()
        tool._target_store = store

        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=FULL_NMAP):
            asyncio.run(tool.execute(action="nmap_scan", target="192.168.1.0/24"))

        diff = store.diff_since("2000-01-01T00:00:00")
        assert diff["new_hosts"] == 2
        assert diff["new_ports"] == 4

    def test_stats_after_scans(self, store):
        """get_stats reflects ingested entities."""
        from tools.blackarch import BlackArchTool

        tool = BlackArchTool()
        tool._target_store = store

        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=FULL_NMAP):
            asyncio.run(tool.execute(action="nmap_scan", target="192.168.1.0/24"))

        stats = store.get_stats()
        assert stats["hosts"] == 2
        assert stats["ports"] == 4
