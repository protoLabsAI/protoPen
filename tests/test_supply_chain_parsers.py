"""Tests for supply_chain parsers."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from tools.parsers.supply_chain import (
    parse_dependency_confusion,
    parse_depscan,
    parse_gitleaks,
    parse_postinstall,
    parse_provenance,
    parse_trufflehog,
    parse_typosquat,
)


@pytest.fixture
def store():
    return MagicMock()


class TestDependencyConfusion:
    def test_confused_packages(self, store):
        raw = json.dumps(
            {"confused_packages": [{"name": "@acme/internal", "internal_version": "1.2.3", "public_version": "9.9.9"}]}
        )
        entities = parse_dependency_confusion(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "supply_chain_finding"
        assert entities[0]["check"] == "dependency_confusion_test"
        assert entities[0]["target"] == "@acme/internal"
        assert entities[0]["severity"] == "critical"
        assert "internal=1.2.3" in entities[0]["value"]

    def test_empty(self, store):
        assert parse_dependency_confusion(json.dumps({"confused_packages": []}), store) == []

    def test_invalid(self, store):
        assert parse_dependency_confusion("not json", store) == []


class TestTyposquat:
    def test_similarity_drives_severity(self, store):
        raw = json.dumps(
            {
                "candidates": [
                    {"name": "lodahs", "similarity": 0.95, "downloads": 12},
                    {"name": "reqeusts", "similarity": 0.5, "downloads": 3},
                ]
            }
        )
        entities = parse_typosquat(raw, store)
        assert entities[0]["severity"] == "high"  # >0.9
        assert entities[1]["severity"] == "medium"
        assert "similarity=0.95" in entities[0]["value"]

    def test_invalid(self, store):
        assert parse_typosquat("{", store) == []


class TestProvenance:
    def test_passed_vs_failed(self, store):
        raw = json.dumps(
            {
                "checks": [
                    {"check_name": "signed", "passed": True, "details": "ok"},
                    {"check_name": "2fa", "passed": False, "details": "no 2fa"},
                ]
            }
        )
        entities = parse_provenance(raw, store)
        assert entities[0]["severity"] == "info"
        assert entities[1]["severity"] == "high"
        assert entities[1]["target"] == "2fa"


class TestPostinstall:
    def test_scripts(self, store):
        raw = json.dumps({"scripts": [{"package": "evil", "risk": "critical", "content": "curl|bash"}]})
        entities = parse_postinstall(raw, store)
        assert entities[0]["target"] == "evil"
        assert entities[0]["severity"] == "critical"
        assert entities[0]["value"] == "curl|bash"


class TestTrufflehog:
    def test_jsonl_lines(self, store):
        line = json.dumps(
            {
                "DetectorName": "AWS",
                "SourceMetadata": {"Data": {"Filesystem": {"file": "config.env"}}},
            }
        )
        raw = line + "\n" + line
        entities = parse_trufflehog(raw, store)
        assert len(entities) == 2
        assert entities[0]["target"] == "config.env"
        assert entities[0]["value"] == "AWS"
        assert entities[0]["severity"] == "critical"

    def test_skips_bad_lines(self, store):
        raw = "not json\n" + json.dumps({"DetectorName": "GitHub"})
        entities = parse_trufflehog(raw, store)
        assert len(entities) == 1
        assert entities[0]["value"] == "GitHub"


class TestGitleaks:
    def test_top_level_array(self, store):
        raw = json.dumps([{"File": "src/app.js", "Description": "AWS key"}])
        entities = parse_gitleaks(raw, store)
        assert entities[0]["target"] == "src/app.js"
        assert entities[0]["value"] == "AWS key"

    def test_non_array_returns_empty(self, store):
        assert parse_gitleaks(json.dumps({"File": "x"}), store) == []


class TestDepscan:
    def test_vulnerabilities(self, store):
        raw = json.dumps({"vulnerabilities": [{"package": "log4j", "id": "CVE-2021-44228", "severity": "critical"}]})
        entities = parse_depscan(raw, store)
        assert entities[0]["target"] == "log4j"
        assert entities[0]["severity"] == "critical"
        assert "CVE-2021-44228" in entities[0]["value"]
