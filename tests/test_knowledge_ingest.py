"""Tests for KnowledgeIngestMiddleware — LLM extraction + parser fallback."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

try:
    import langchain_core  # noqa: F401

    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False

needs_langchain = pytest.mark.skipif(not HAS_LANGCHAIN, reason="langchain not installed")

if HAS_LANGCHAIN:
    from graph.middleware.knowledge_ingest import (
        KnowledgeIngestMiddleware,
        _INGESTIBLE_TOOLS,
        _NullStore,
    )


@pytest.fixture
def store():
    """Mock KnowledgeStore with add_threat_intel."""
    s = MagicMock()
    s.add_threat_intel.return_value = True
    return s


@pytest.fixture
def middleware(store):
    mw = KnowledgeIngestMiddleware(store)
    # Force LLM unavailable so tests use deterministic parser fallback
    mw._llm_available = False
    return mw


def _make_request(tool_name: str, action: str = ""):
    req = MagicMock()
    req.tool_call = {"name": tool_name, "args": {"action": action}}
    return req


def _make_tool_message(content: str):
    from langchain_core.messages import ToolMessage

    return ToolMessage(content=content, tool_call_id="test")


# ── NullStore ────────────────────────────────────────────────────────────────


@needs_langchain
class TestNullStore:
    def test_swallows_any_call(self):
        ns = _NullStore()
        assert ns.upsert_host(ip="1.2.3.4") is None
        assert ns.whatever(a=1, b=2) is None


# ── Middleware filtering ─────────────────────────────────────────────────────


@needs_langchain
class TestIngestFiltering:
    def test_skips_non_ingestible_tools(self, middleware, store):
        req = _make_request("engagement", "start")
        result = _make_tool_message('{"status": "ok"}')
        middleware._try_ingest(req, result)
        store.add_threat_intel.assert_not_called()

    def test_skips_blocked_output(self, middleware, store):
        req = _make_request("cis_audit", "ssh_audit")
        result = _make_tool_message("[BLOCKED] No engagement active")
        middleware._try_ingest(req, result)
        store.add_threat_intel.assert_not_called()

    def test_skips_error_output(self, middleware, store):
        req = _make_request("cis_audit", "ssh_audit")
        result = _make_tool_message("Error: connection refused")
        middleware._try_ingest(req, result)
        store.add_threat_intel.assert_not_called()

    def test_skips_empty_output(self, middleware, store):
        req = _make_request("cis_audit", "ssh_audit")
        result = _make_tool_message("")
        middleware._try_ingest(req, result)
        store.add_threat_intel.assert_not_called()


# ── Parser fallback path ─────────────────────────────────────────────────────


@needs_langchain
class TestParserFallback:
    def test_cis_audit_findings_ingested(self, middleware, store):
        req = _make_request("cis_audit", "ssh_audit")
        raw = json.dumps(
            {
                "target": "10.0.0.1",
                "issues": [
                    {"severity": "high", "check": "PasswordAuth", "value": "yes", "recommendation": "Disable"},
                ],
            }
        )
        result = _make_tool_message(raw)
        middleware._try_ingest(req, result)

        assert store.add_threat_intel.call_count == 1
        call_kwargs = store.add_threat_intel.call_args
        assert call_kwargs[1]["source"] == "cis_audit/ssh_audit"
        assert call_kwargs[1]["source_type"] == "defensive_scan"
        assert call_kwargs[1]["severity"] == "high"

    def test_hardening_failed_checks_ingested(self, middleware, store):
        req = _make_request("hardening_check", "ssh_harden")
        raw = json.dumps(
            {
                "service": "ssh",
                "target": "10.0.0.1",
                "checks": [
                    {"check": "PermitRootLogin", "passed": False, "severity": "critical", "remediation": "Set to no"},
                    {"check": "MaxAuthTries", "passed": True, "severity": "medium"},
                ],
            }
        )
        result = _make_tool_message(raw)
        middleware._try_ingest(req, result)

        # Only the failed check should be ingested
        assert store.add_threat_intel.call_count == 1
        assert store.add_threat_intel.call_args[1]["severity"] == "critical"

    def test_ir_ioc_scan_ingested(self, middleware, store):
        req = _make_request("ir_toolkit", "ioc_scan")
        raw = json.dumps(
            {
                "findings": [
                    {
                        "ioc_type": "ip",
                        "ioc_value": "198.51.100.1",
                        "file": "/var/log/syslog",
                        "line": 42,
                        "context": "bad ip",
                    },
                ],
                "total_hits": 1,
            }
        )
        result = _make_tool_message(raw)
        middleware._try_ingest(req, result)

        assert store.add_threat_intel.call_count == 1
        assert store.add_threat_intel.call_args[1]["severity"] == "critical"

    def test_no_findings_no_ingest(self, middleware, store):
        req = _make_request("cis_audit", "ssh_audit")
        raw = json.dumps({"target": "10.0.0.1", "issues": []})
        result = _make_tool_message(raw)
        middleware._try_ingest(req, result)
        store.add_threat_intel.assert_not_called()

    def test_unknown_action_no_parser(self, middleware, store):
        req = _make_request("cis_audit", "nonexistent_action")
        result = _make_tool_message('{"data": "something"}')
        middleware._try_ingest(req, result)
        store.add_threat_intel.assert_not_called()


# ── LLM extraction path ─────────────────────────────────────────────────────


@needs_langchain
class TestLlmExtraction:
    def test_llm_returns_findings(self, store):
        mw = KnowledgeIngestMiddleware(store)
        mw._llm_available = None  # untested

        findings_json = json.dumps(
            [
                {
                    "type": "ssh_misconfiguration",
                    "severity": "high",
                    "summary": "Root login enabled",
                    "details": "PermitRootLogin yes",
                },
            ]
        )

        mock_response = MagicMock()
        mock_response.content = findings_json

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_response
        mw._llm = mock_llm

        req = _make_request("cis_audit", "ssh_audit")
        result = _make_tool_message('{"issues": [{"check": "PermitRootLogin"}]}')
        mw._try_ingest(req, result)

        assert store.add_threat_intel.call_count == 1
        assert mw._llm_available is True

    def test_llm_failure_falls_back_to_parsers(self, store):
        mw = KnowledgeIngestMiddleware(store)
        mw._llm_available = None  # untested

        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = Exception("Connection refused")
        mw._llm = mock_llm

        req = _make_request("cis_audit", "ssh_audit")
        raw = json.dumps(
            {
                "target": "10.0.0.1",
                "issues": [{"severity": "high", "check": "X", "value": "Y", "recommendation": "Z"}],
            }
        )
        result = _make_tool_message(raw)
        mw._try_ingest(req, result)

        # LLM failed → marked unavailable → parser fallback used
        assert mw._llm_available is False
        assert store.add_threat_intel.call_count == 1

    def test_llm_strips_markdown_fences(self, store):
        mw = KnowledgeIngestMiddleware(store)
        mw._llm_available = True

        findings = [{"type": "test", "severity": "info", "summary": "ok", "details": ""}]
        mock_response = MagicMock()
        mock_response.content = f"```json\n{json.dumps(findings)}\n```"

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_response
        mw._llm = mock_llm

        req = _make_request("cis_audit", "ssh_audit")
        result = _make_tool_message('{"issues": []}')
        mw._try_ingest(req, result)

        assert store.add_threat_intel.call_count == 1


# ── Ingestible tools set ─────────────────────────────────────────────────────


@needs_langchain
class TestIngestibleToolsCoverage:
    def test_all_blue_team_tools_included(self):
        blue_team = {"cis_audit", "net_monitor", "hardening_check", "ir_toolkit", "purple_team"}
        assert blue_team.issubset(_INGESTIBLE_TOOLS)

    def test_high_signal_red_tools_included(self):
        assert "vuln_scan" in _INGESTIBLE_TOOLS
        assert "cve_match" in _INGESTIBLE_TOOLS
