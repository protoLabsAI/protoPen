"""Tests for bettercap net.show ASCII table parser."""
import pytest
from knowledge.target_store import TargetStore
from tools.parsers.bettercap import parse


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


BETTERCAP_TABLE = """\
192.168.1.0/24 > 192.168.1.100  » net.recon
┌───────────────┬───────────────────┬──────────────────┬────────────────┬──────┬───────┐
│    IP Address │ MAC Address       │ Hostname         │ Vendor         │ Sent │ Recvd │
├───────────────┼───────────────────┼──────────────────┼────────────────┼──────┼───────┤
│ 192.168.1.1   │ AA:BB:CC:DD:EE:01 │ gateway.local    │ Netgear Inc    │  12k │   34k │
│ 192.168.1.42  │ 11:22:33:44:55:66 │ kali             │ Intel Corp     │ 102k │  201k │
│ 192.168.1.100 │ DE:AD:BE:EF:CA:FE │                  │ Raspberry Pi   │   1k │    2k │
└───────────────┴───────────────────┴──────────────────┴────────────────┴──────┴───────┘
"""

BETTERCAP_EMPTY = """\
192.168.1.0/24 > 192.168.1.100  » net.recon
No hosts detected.
"""

BETTERCAP_GARBAGE = "something unrelated"


class TestBettercapParser:
    def test_parses_three_hosts(self, store):
        entities = parse(BETTERCAP_TABLE, store)
        assert len(entities) == 3

    def test_ip_and_mac_extracted(self, store):
        entities = parse(BETTERCAP_TABLE, store)
        gateway = next(e for e in entities if e["ip"] == "192.168.1.1")
        assert gateway["mac"] == "AA:BB:CC:DD:EE:01"
        assert gateway["hostname"] == "gateway.local"
        assert gateway["vendor"] == "Netgear Inc"

    def test_empty_hostname(self, store):
        entities = parse(BETTERCAP_TABLE, store)
        rpi = next(e for e in entities if e["ip"] == "192.168.1.100")
        assert rpi["hostname"] == ""

    def test_hosts_persisted(self, store):
        parse(BETTERCAP_TABLE, store)
        rows = store.query_hosts(ip_prefix="192.168.1.")
        assert len(rows) == 3

    def test_empty_table(self, store):
        assert parse(BETTERCAP_EMPTY, store) == []

    def test_garbage_input(self, store):
        assert parse(BETTERCAP_GARBAGE, store) == []

    def test_idempotent(self, store):
        parse(BETTERCAP_TABLE, store)
        parse(BETTERCAP_TABLE, store)
        assert len(store.query_hosts(ip_prefix="192.168.1.")) == 3
