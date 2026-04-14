"""Integration tests: BlackArch execute() auto-ingests to TargetStore."""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch
from knowledge.target_store import TargetStore


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22">
      <state state="open"/><service name="ssh"/>
    </port></ports>
  </host>
</nmaprun>"""

BETTERCAP_TABLE = "│ 10.0.0.99      │ AA:BB:CC:DD:EE:01 │ target-host      │ Dell Inc         │  10k │   20k │"


class TestBlackArchNmapWiring:
    def test_nmap_auto_ingests_host(self, store):
        from tools.blackarch import BlackArchTool

        tool = BlackArchTool()
        tool._target_store = store
        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=NMAP_XML):
            result = asyncio.run(tool.execute(action="nmap_scan", target="10.0.0.5"))
        assert "<nmaprun>" in result
        hosts = store.query_hosts(ip_prefix="10.0.0.")
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "10.0.0.5"

    def test_nmap_auto_ingests_ports(self, store):
        from tools.blackarch import BlackArchTool

        tool = BlackArchTool()
        tool._target_store = store
        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=NMAP_XML):
            asyncio.run(tool.execute(action="nmap_scan", target="10.0.0.5"))
        hosts = store.query_hosts(ip_prefix="10.0.0.")
        ports = store.get_ports(hosts[0]["id"])
        assert len(ports) == 1
        assert ports[0]["service"] == "ssh"


class TestBlackArchBettercapWiring:
    def test_bettercap_auto_ingests_host(self, store):
        from tools.blackarch import BlackArchTool

        tool = BlackArchTool()
        tool._target_store = store
        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=BETTERCAP_TABLE):
            result = asyncio.run(tool.execute(action="bettercap_recon", interface="eth0"))
        assert "target-host" in result
        hosts = store.query_hosts(ip_prefix="10.0.0.")
        assert len(hosts) == 1
        assert hosts[0]["vendor"] == "Dell Inc"


class TestNoStoreGraceful:
    def test_no_target_store_still_returns(self):
        from tools.blackarch import BlackArchTool

        tool = BlackArchTool()
        with patch.object(tool, "_run", new_callable=AsyncMock, return_value=NMAP_XML):
            result = asyncio.run(tool.execute(action="nmap_scan", target="10.0.0.5"))
        assert "<nmaprun>" in result
