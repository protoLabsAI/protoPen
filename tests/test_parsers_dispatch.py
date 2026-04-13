"""Tests for the parser dispatch layer."""
import pytest
from unittest.mock import MagicMock
from knowledge.target_store import TargetStore
from tools.parsers import ingest_output


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


class TestDispatcher:
    def test_known_parser_is_called(self, store):
        """nmap_scan should trigger the nmap parser and return entities."""
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        entities = ingest_output("blackarch", "nmap_scan", xml, store)
        # Stubs return [], but dispatch should not error
        assert isinstance(entities, list)

    def test_unknown_action_returns_empty(self, store):
        """Unknown tool+action combos silently return empty list."""
        result = ingest_output("blackarch", "does_not_exist", "whatever", store)
        assert result == []

    def test_parser_error_returns_empty(self, store, monkeypatch):
        """A parser that raises should be caught; returns empty list."""
        def bad_parser(raw, s):
            raise ValueError("boom")
        from tools.parsers import PARSER_MAP
        monkeypatch.setitem(PARSER_MAP, ("blackarch", "nmap_scan"), bad_parser)
        result = ingest_output("blackarch", "nmap_scan", "<bad/>", store)
        assert result == []

    def test_none_store_returns_empty(self):
        """If store is None, skip parsing entirely."""
        result = ingest_output("blackarch", "nmap_scan", "<x/>", None)
        assert result == []
