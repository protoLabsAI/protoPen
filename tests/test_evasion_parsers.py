"""Tests for evasion parsers."""

from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock

from tools.parsers.evasion import (
    parse_payload_gen,
    parse_amsi_test,
    parse_defender_check,
    parse_entropy,
)


@pytest.fixture
def store():
    return MagicMock()


class TestParsePayloadGen:
    def test_success(self, store):
        raw = "Payload size: 354 bytes\nFinal size of exe file: 73802 bytes\nSaved as: /tmp/payload\n"
        entities = parse_payload_gen(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "evasion_finding"
        assert entities[0]["success"] is True
        assert entities[0]["size_bytes"] == 354

    def test_failure(self, store):
        raw = "Error: invalid payload\n"
        entities = parse_payload_gen(raw, store)
        assert len(entities) == 1
        assert entities[0]["success"] is False

    def test_empty(self, store):
        assert parse_payload_gen("", store) == []


class TestParseAMSI:
    def test_bypassed(self, store):
        raw = json.dumps({"results": [{"bypassed": True, "technique": "amsi_patch", "message": "AMSI bypassed"}]})
        entities = parse_amsi_test(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "info"

    def test_blocked(self, store):
        raw = json.dumps({"results": [{"bypassed": False, "message": "AMSI blocked payload"}]})
        entities = parse_amsi_test(raw, store)
        assert entities[0]["severity"] == "high"

    def test_invalid(self, store):
        assert parse_amsi_test("not json", store) == []


class TestParseDefenderCheck:
    def test_detected(self, store):
        raw = "Threat detected: Trojan.Win32.Generic\n"
        entities = parse_defender_check(raw, store)
        assert len(entities) == 1
        assert entities[0]["detected"] is True
        assert entities[0]["severity"] == "high"

    def test_clean(self, store):
        raw = "No threats found\n"
        entities = parse_defender_check(raw, store)
        assert entities[0]["detected"] is False
        assert entities[0]["severity"] == "info"

    def test_empty(self, store):
        assert parse_defender_check("", store) == []


class TestParseEntropy:
    def test_high_entropy(self, store):
        raw = json.dumps({"entropy": 7.8})
        entities = parse_entropy(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "high"
        assert entities[0]["entropy"] == 7.8

    def test_normal_entropy(self, store):
        raw = json.dumps({"entropy": 5.2})
        entities = parse_entropy(raw, store)
        assert entities[0]["severity"] == "info"

    def test_medium_entropy(self, store):
        raw = json.dumps({"entropy": 7.0})
        entities = parse_entropy(raw, store)
        assert entities[0]["severity"] == "medium"

    def test_invalid(self, store):
        assert parse_entropy("not json", store) == []
