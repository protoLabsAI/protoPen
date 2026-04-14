"""Tests for phishing parsers."""

from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock

from tools.parsers.phishing import (
    parse_gophish_json,
    parse_evilginx_text,
    parse_email_header,
    parse_dns_txt,
    parse_smtp_relay,
)


@pytest.fixture
def store():
    return MagicMock()


class TestParseGoPhish:
    def test_campaign_created(self, store):
        raw = json.dumps({"id": 1, "name": "test_campaign"})
        entities = parse_gophish_json(raw, store)
        assert len(entities) == 1
        assert "Campaign created" in entities[0]["details"]

    def test_campaign_results(self, store):
        raw = json.dumps(
            {
                "results": [
                    {"email": "user@test.com", "status": "clicked"},
                    {"email": "admin@test.com", "status": "submitted"},
                ]
            }
        )
        entities = parse_gophish_json(raw, store)
        assert len(entities) == 2

    def test_invalid(self, store):
        assert parse_gophish_json("not json", store) == []


class TestParseEvilginx:
    def test_lure_url(self, store):
        raw = "Lure created: https://evil.com/abc123\nPhishlet active\n"
        entities = parse_evilginx_text(raw, store)
        assert len(entities) >= 1
        assert any("https" in e["details"] for e in entities)

    def test_no_match(self, store):
        raw = "Starting...\nDone\n"
        assert parse_evilginx_text(raw, store) == []

    def test_empty(self, store):
        assert parse_evilginx_text("", store) == []


class TestParseEmailHeader:
    def test_findings(self, store):
        raw = json.dumps(
            {
                "findings": [
                    {"severity": "high", "message": "SPF softfail for sender domain"},
                ]
            }
        )
        entities = parse_email_header(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "high"

    def test_invalid(self, store):
        assert parse_email_header("not json", store) == []


class TestParseDnsTxt:
    def test_spf_softfail(self, store):
        raw = '"v=spf1 include:_spf.google.com ~all"\n'
        entities = parse_dns_txt(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "medium"

    def test_spf_pass_all(self, store):
        raw = '"v=spf1 +all"\n'
        entities = parse_dns_txt(raw, store)
        assert entities[0]["severity"] == "critical"

    def test_dmarc_reject(self, store):
        raw = '"v=DMARC1; p=reject; rua=mailto:d@example.com"\n'
        entities = parse_dns_txt(raw, store)
        assert entities[0]["severity"] == "info"

    def test_dmarc_none(self, store):
        raw = '"v=DMARC1; p=none"\n'
        entities = parse_dns_txt(raw, store)
        assert entities[0]["severity"] == "medium"

    def test_no_record(self, store):
        entities = parse_dns_txt("", store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "high"


class TestParseSMTPRelay:
    def test_relay_open(self, store):
        raw = "250 Ok: queued as ABC123\n"
        entities = parse_smtp_relay(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "critical"

    def test_relay_closed(self, store):
        raw = "550 Relay not permitted\n"
        entities = parse_smtp_relay(raw, store)
        assert entities[0]["severity"] == "info"

    def test_empty(self, store):
        assert parse_smtp_relay("", store) == []
