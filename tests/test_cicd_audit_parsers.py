"""Tests for cicd_audit parsers."""
from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock

from tools.parsers.cicd_audit import (
    parse_trufflehog,
    parse_gitleaks,
    parse_github_actions,
    parse_dependency_check,
    parse_semgrep,
    parse_checkov,
)


@pytest.fixture
def store():
    return MagicMock()


# ── truffleHog ───────────────────────────────────────────────────────────────

class TestParseTrufflehog:
    def test_single_finding(self, store):
        raw = json.dumps({
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "SourceMetadata": {"Data": {"Git": {"file": "config.py", "line": 42}}},
        })
        entities = parse_trufflehog(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "secret_finding"
        assert entities[0]["detector_name"] == "AWS"
        assert entities[0]["verified"] is True
        assert entities[0]["severity"] == "critical"

    def test_multi_line_jsonl(self, store):
        lines = [
            json.dumps({"DetectorName": "AWS", "Verified": False, "Raw": "key1", "SourceMetadata": {"Data": {"Git": {"file": "a.py", "line": 1}}}}),
            json.dumps({"DetectorName": "GitHub", "Verified": False, "Raw": "ghp_xxx", "SourceMetadata": {"Data": {"Git": {"file": "b.py", "line": 5}}}}),
        ]
        entities = parse_trufflehog("\n".join(lines), store)
        assert len(entities) == 2
        assert entities[1]["detector_name"] == "GitHub"

    def test_empty_output(self, store):
        assert parse_trufflehog("", store) == []

    def test_invalid_json(self, store):
        assert parse_trufflehog("not json at all", store) == []


# ── gitleaks ─────────────────────────────────────────────────────────────────

class TestParseGitleaks:
    def test_findings(self, store):
        raw = json.dumps([
            {"RuleID": "aws-access-key", "Secret": "AKIAIOSFODNN7EXAMPLE",
             "File": "config.py", "StartLine": 10, "Commit": "abc12345678"},
        ])
        entities = parse_gitleaks(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "secret_finding"
        assert entities[0]["rule"] == "aws-access-key"
        assert entities[0]["commit"] == "abc12345"
        assert len(entities[0]["secret"]) <= 23  # truncated

    def test_empty_array(self, store):
        assert parse_gitleaks("[]", store) == []

    def test_invalid_json(self, store):
        assert parse_gitleaks("not json", store) == []


# ── actionlint ───────────────────────────────────────────────────────────────

class TestParseGithubActions:
    def test_findings(self, store):
        raw = json.dumps([
            {"message": "shell injection via ${{ inputs.name }}",
             "filepath": ".github/workflows/ci.yml", "line": 15,
             "column": 20, "kind": "expression"},
        ])
        entities = parse_github_actions(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "cicd_finding"
        assert entities[0]["kind"] == "expression"

    def test_empty_array(self, store):
        assert parse_github_actions("[]", store) == []

    def test_invalid_json(self, store):
        assert parse_github_actions("not json", store) == []


# ── dependency-check ─────────────────────────────────────────────────────────

class TestParseDependencyCheck:
    def test_vuln_found(self, store):
        raw = json.dumps({"dependencies": [{
            "fileName": "log4j-core-2.14.1.jar",
            "vulnerabilities": [{
                "name": "CVE-2021-44228",
                "severity": "CRITICAL",
                "description": "Log4Shell RCE",
                "cvssv3": {"baseScore": 10.0},
            }],
        }]})
        entities = parse_dependency_check(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "dependency_vuln"
        assert entities[0]["cve"] == "CVE-2021-44228"
        assert entities[0]["cvss_score"] == 10.0

    def test_no_vulns(self, store):
        raw = json.dumps({"dependencies": [{"fileName": "safe.jar", "vulnerabilities": []}]})
        assert parse_dependency_check(raw, store) == []

    def test_invalid_json(self, store):
        assert parse_dependency_check("not json", store) == []


# ── semgrep ──────────────────────────────────────────────────────────────────

class TestParseSemgrep:
    def test_results(self, store):
        raw = json.dumps({"results": [{
            "check_id": "python.lang.security.audit.exec-used",
            "path": "app.py",
            "start": {"line": 42},
            "extra": {"severity": "ERROR", "message": "Use of exec()"},
        }]})
        entities = parse_semgrep(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "code_finding"
        assert entities[0]["severity"] == "error"

    def test_empty_results(self, store):
        assert parse_semgrep(json.dumps({"results": []}), store) == []

    def test_invalid_json(self, store):
        assert parse_semgrep("not json", store) == []


# ── checkov ──────────────────────────────────────────────────────────────────

class TestParseCheckov:
    def test_failed_checks(self, store):
        raw = json.dumps({"results": {"failed_checks": [{
            "check_id": "CKV_DOCKER_2",
            "resource": "Dockerfile",
            "name": "Ensure healthcheck exists",
            "guideline": "https://docs.bridgecrew.io/CKV_DOCKER_2",
            "file_path": "/Dockerfile",
        }]}})
        entities = parse_checkov(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "iac_finding"
        assert entities[0]["check_id"] == "CKV_DOCKER_2"

    def test_all_passed(self, store):
        raw = json.dumps({"results": {"failed_checks": [], "passed_checks": [{"check_id": "CKV_1"}]}})
        assert parse_checkov(raw, store) == []

    def test_invalid_json(self, store):
        assert parse_checkov("not json", store) == []

    def test_list_format(self, store):
        """checkov can return a list of check-type results."""
        raw = json.dumps([
            {"results": {"failed_checks": [{"check_id": "CKV_1", "resource": "r1", "name": "n1", "guideline": "", "file_path": "/f"}]}},
            {"results": {"failed_checks": []}},
        ])
        entities = parse_checkov(raw, store)
        assert len(entities) == 1
