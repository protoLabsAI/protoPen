"""Tests for telecom_attack parsers."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from tools.parsers.telecom_attack import (
    parse_sip_table,
    parse_imsi_detect,
)


@pytest.fixture
def store():
    return MagicMock()


class TestParseSIP:
    def test_devices(self, store):
        raw = "| SIP Device    | User Agent   | Fingerprint |\n| 10.0.0.2:5060 | Asterisk PBX | disabled    |\n"
        entities = parse_sip_table(raw, store)
        assert len(entities) == 1
        assert entities[0]["protocol"] == "sip"
        assert entities[0]["target"] == "10.0.0.2:5060"

    def test_empty(self, store):
        assert parse_sip_table("WARNING:root:found nothing\n", store) == []

    def test_invalid(self, store):
        assert parse_sip_table("not a table", store) == []


class TestParseIMSI:
    def test_arfcn_found(self, store):
        raw = "ARFCN: 100, freq: 935.2 MHz, CID: 12345\nARFCN: 200, freq: 945.0 MHz\n"
        entities = parse_imsi_detect(raw, store)
        assert len(entities) == 2
        assert entities[0]["protocol"] == "gsm"

    def test_no_arfcn(self, store):
        raw = "Scanning...\nDone\n"
        assert parse_imsi_detect(raw, store) == []

    def test_empty(self, store):
        assert parse_imsi_detect("", store) == []
