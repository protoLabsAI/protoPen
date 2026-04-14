"""Tests for container_audit parsers — kube-hunter, kube-bench, deepce, CDK, Trivy."""
from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock

from tools.parsers.container_audit import (
    parse_kube_hunter,
    parse_kube_bench,
    parse_deepce,
    parse_cdk_evaluate,
    parse_trivy_image,
)


@pytest.fixture
def store():
    return MagicMock()


# ── kube-hunter ──────────────────────────────────────────────────────────────

class TestParseKubeHunter:
    def test_empty_vulns(self, store):
        raw = json.dumps({"vulnerabilities": []})
        assert parse_kube_hunter(raw, store) == []

    def test_parse_vulns(self, store):
        raw = json.dumps({"vulnerabilities": [
            {"vulnerability": "Exposed K8s Dashboard", "severity": "high",
             "location": "10.0.0.1:8443", "category": "Information Disclosure",
             "hunter": "Dashboard", "description": "Dashboard is publicly accessible"},
            {"vulnerability": "Unauthenticated Kubelet", "severity": "critical",
             "location": "10.0.0.2:10250", "category": "Remote Code Execution",
             "hunter": "Kubelet", "description": "Kubelet allows anonymous access"},
        ]})
        entities = parse_kube_hunter(raw, store)
        assert len(entities) == 2
        assert entities[0]["type"] == "k8s_finding"
        assert entities[0]["severity"] == "high"
        assert entities[0]["target"] == "10.0.0.1:8443"
        assert entities[1]["severity"] == "critical"

    def test_invalid_json(self, store):
        assert parse_kube_hunter("not json", store) == []


# ── kube-bench ───────────────────────────────────────────────────────────────

class TestParseKubeBench:
    def test_empty_controls(self, store):
        raw = json.dumps({"Controls": []})
        assert parse_kube_bench(raw, store) == []

    def test_only_fail_and_warn(self, store):
        raw = json.dumps({"Controls": [{
            "node_type": "master",
            "tests": [{
                "results": [
                    {"test_number": "1.1.1", "test_desc": "API server anonymous auth",
                     "status": "FAIL", "remediation": "Set --anonymous-auth=false", "scored": True},
                    {"test_number": "1.1.2", "test_desc": "API server basic auth",
                     "status": "PASS", "scored": True},
                    {"test_number": "1.1.3", "test_desc": "Insecure port",
                     "status": "WARN", "remediation": "Set --insecure-port=0", "scored": False},
                ],
            }],
        }]})
        entities = parse_kube_bench(raw, store)
        assert len(entities) == 2
        assert entities[0]["severity"] == "high"
        assert entities[0]["check"].startswith("1.1.1")
        assert entities[1]["severity"] == "medium"
        assert entities[1]["scored"] is False

    def test_invalid_json(self, store):
        assert parse_kube_bench("not json", store) == []


# ── deepce ───────────────────────────────────────────────────────────────────

class TestParseDeepce:
    def test_escapes_and_info(self, store):
        raw = json.dumps({
            "escapes": [
                {"name": "docker.sock", "severity": "high",
                 "description": "Docker socket mounted", "exploitable": True},
            ],
            "info": [
                {"name": "container_runtime", "value": "docker"},
            ],
        })
        entities = parse_deepce(raw, store)
        assert len(entities) == 2
        assert entities[0]["type"] == "container_finding"
        assert entities[0]["severity"] == "high"
        assert entities[0]["exploitable"] is True
        assert entities[1]["severity"] == "info"

    def test_empty(self, store):
        raw = json.dumps({"escapes": [], "info": []})
        assert parse_deepce(raw, store) == []

    def test_invalid_json(self, store):
        assert parse_deepce("not json", store) == []


# ── CDK evaluate ─────────────────────────────────────────────────────────────

class TestParseCDK:
    def test_findings(self, store):
        raw = json.dumps({"findings": [
            {"name": "service-account", "severity": "high",
             "description": "Default SA with cluster-admin", "exploit_available": True},
        ]})
        entities = parse_cdk_evaluate(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "container_finding"
        assert entities[0]["exploit_available"] is True

    def test_empty_findings(self, store):
        raw = json.dumps({"findings": []})
        assert parse_cdk_evaluate(raw, store) == []

    def test_invalid_json(self, store):
        assert parse_cdk_evaluate("not json", store) == []


# ── Trivy ────────────────────────────────────────────────────────────────────

class TestParseTrivy:
    def test_image_vulns(self, store):
        raw = json.dumps({"Results": [{
            "Target": "alpine:3.19",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-1234", "Severity": "HIGH",
                 "Title": "OpenSSL buffer overflow", "PkgName": "openssl",
                 "InstalledVersion": "3.1.4", "FixedVersion": "3.1.5"},
                {"VulnerabilityID": "CVE-2024-5678", "Severity": "CRITICAL",
                 "Title": "zlib heap overflow", "PkgName": "zlib",
                 "InstalledVersion": "1.3.0", "FixedVersion": "1.3.1"},
            ],
        }]})
        entities = parse_trivy_image(raw, store)
        assert len(entities) == 2
        assert entities[0]["type"] == "container_vuln"
        assert entities[0]["check"] == "CVE-2024-1234"
        assert entities[0]["severity"] == "high"
        assert entities[0]["package"] == "openssl"
        assert entities[0]["fixed_version"] == "3.1.5"
        assert entities[1]["severity"] == "critical"

    def test_no_vulns(self, store):
        raw = json.dumps({"Results": [{"Target": "scratch", "Vulnerabilities": []}]})
        assert parse_trivy_image(raw, store) == []

    def test_empty_results(self, store):
        raw = json.dumps({"Results": []})
        assert parse_trivy_image(raw, store) == []

    def test_invalid_json(self, store):
        assert parse_trivy_image("not json", store) == []
