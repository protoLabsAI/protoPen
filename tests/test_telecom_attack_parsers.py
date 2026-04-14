"""Tests for telecom_attack parsers."""

from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock

from tools.parsers.telecom_attack import (
    parse_gtp_json,
    parse_sip_json,
    parse_ss7_json,
    parse_diameter_json,
    parse_imsi_detect,
    parse_stir_shaken,
)


@pytest.fixture
def store():
    return MagicMock()


class TestParseGTP:
    def test_results(self, store):
        raw = json.dumps({"results": [{"target": "10.0.0.1", "severity": "high", "message": "GTP-C open"}]})
        entities = parse_gtp_json(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "telecom_finding"
        assert entities[0]["protocol"] == "gtp"

    def test_empty(self, store):
        assert parse_gtp_json(json.dumps({"results": []}), store) == []

    def test_invalid(self, store):
        assert parse_gtp_json("not json", store) == []


class TestParseSIP:
    def test_devices(self, store):
        raw = json.dumps([{"host": "10.0.0.2", "user_agent": "Asterisk PBX"}])
        entities = parse_sip_json(raw, store)
        assert len(entities) == 1
        assert entities[0]["protocol"] == "sip"

    def test_empty(self, store):
        assert parse_sip_json("[]", store) == []

    def test_invalid(self, store):
        assert parse_sip_json("not json", store) == []


class TestParseSS7:
    def test_elements(self, store):
        raw = json.dumps({"results": [{"target": "10.0.0.3", "message": "HLR found"}]})
        entities = parse_ss7_json(raw, store)
        assert len(entities) == 1
        assert entities[0]["protocol"] == "ss7"

    def test_invalid(self, store):
        assert parse_ss7_json("not json", store) == []


class TestParseDiameter:
    def test_audit(self, store):
        raw = json.dumps({"results": [{"peer": "10.0.0.4", "message": "Diameter peer open"}]})
        entities = parse_diameter_json(raw, store)
        assert len(entities) == 1
        assert entities[0]["protocol"] == "diameter"

    def test_invalid(self, store):
        assert parse_diameter_json("not json", store) == []


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


class TestParseStirShaken:
    def test_verified(self, store):
        raw = json.dumps({"call_id": "abc123", "verified": True, "message": "valid"})
        entities = parse_stir_shaken(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "info"

    def test_unverified(self, store):
        raw = json.dumps({"call_id": "abc123", "verified": False})
        entities = parse_stir_shaken(raw, store)
        assert entities[0]["severity"] == "high"

    def test_invalid(self, store):
        assert parse_stir_shaken("not json", store) == []
