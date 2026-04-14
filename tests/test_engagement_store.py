"""Tests for EngagementStore — SQLite audit trail for engagements."""

import json

import pytest

from knowledge.engagement_store import EngagementStore


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "test_engagements.db")
    return EngagementStore(db_path=db_path)


class TestEngagementLifecycle:
    def test_create_engagement(self, store):
        eid = store.create_engagement(
            name="test-engagement",
            scope_json=json.dumps({"type": "cidr", "targets": ["192.168.4.0/24"]}),
            mode="ACTIVE",
            max_phase="exploitation",
        )
        assert eid > 0

    def test_end_engagement(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="PASSIVE")
        store.end_engagement(eid, outcome="completed")
        eng = store.get_engagement(eid)
        assert eng["ended_at"] is not None
        assert eng["outcome"] == "completed"

    def test_get_engagement(self, store):
        eid = store.create_engagement(name="my-eng", scope_json="{}", mode="REDTEAM", max_phase="recon")
        eng = store.get_engagement(eid)
        assert eng["name"] == "my-eng"
        assert eng["mode"] == "REDTEAM"
        assert eng["max_phase"] == "recon"

    def test_get_nonexistent(self, store):
        assert store.get_engagement(999) is None


class TestFindings:
    def test_log_finding(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        fid = store.log_finding(
            engagement_id=eid,
            severity="high",
            category="wifi",
            title="Open AP detected",
            detail="SSID 'FreeWiFi' no encryption",
            target_ip="192.168.4.1",
        )
        assert fid > 0

    def test_query_by_engagement(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        store.log_finding(eid, "high", "wifi", "Finding 1", "detail 1")
        store.log_finding(eid, "low", "network", "Finding 2", "detail 2")
        findings = store.query_findings(engagement_id=eid)
        assert len(findings) == 2

    def test_query_by_severity(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        store.log_finding(eid, "critical", "wifi", "Critical", "")
        store.log_finding(eid, "low", "rf", "Low", "")
        findings = store.query_findings(engagement_id=eid, severity="critical")
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"


class TestToolCalls:
    def test_log_tool_call(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        tcid = store.log_tool_call(
            engagement_id=eid,
            tool_name="blackarch",
            action="nmap_scan",
            args_json=json.dumps({"target": "192.168.4.1"}),
            result_summary="scan complete",
            success=True,
            duration_ms=1500,
            phase="RECON",
        )
        assert tcid > 0

    def test_log_blocked_call(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="PASSIVE")
        tcid = store.log_tool_call(
            engagement_id=eid,
            tool_name="blackarch",
            action="wifi_deauth",
            blocked=True,
            block_reason="mode enforcement",
            phase="EXPLOITATION",
        )
        assert tcid > 0

    def test_query_by_tool(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        store.log_tool_call(eid, "blackarch", "nmap_scan", "{}", "ok", True, duration_ms=100, phase="RECON")
        store.log_tool_call(eid, "marauder", "scan", "{}", "ok", True, duration_ms=50, phase="RECON")
        calls = store.query_tool_calls(engagement_id=eid, tool_name="blackarch")
        assert len(calls) == 1

    def test_query_blocked_only(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        store.log_tool_call(eid, "blackarch", "nmap_scan", "{}", "ok", True, phase="RECON")
        store.log_tool_call(eid, "blackarch", "deauth", "{}", "", False, blocked=True, block_reason="mode")
        calls = store.query_tool_calls(engagement_id=eid, blocked_only=True)
        assert len(calls) == 1
        assert calls[0]["block_reason"] == "mode"


class TestPhaseTransitions:
    def test_log_transition(self, store):
        eid = store.create_engagement(name="test", scope_json="{}", mode="ACTIVE")
        tid = store.log_phase_transition(eid, from_phase="RECON", to_phase="ENUMERATION", reason="manual")
        assert tid > 0


class TestSummary:
    def test_engagement_summary(self, store):
        eid = store.create_engagement(name="summary-test", scope_json="{}", mode="ACTIVE")
        store.log_finding(eid, "high", "wifi", "F1")
        store.log_finding(eid, "low", "rf", "F2")
        store.log_tool_call(eid, "blackarch", "nmap", "{}", "ok", True, duration_ms=100, phase="RECON")
        store.log_tool_call(eid, "blackarch", "deauth", "{}", "", False, blocked=True, block_reason="mode")
        summary = store.get_engagement_summary(eid)
        assert summary["name"] == "summary-test"
        assert summary["finding_count"] == 2
        assert summary["tool_call_count"] == 2
        assert summary["blocked_count"] == 1

    def test_summary_nonexistent(self, store):
        assert store.get_engagement_summary(999) is None


class TestClose:
    def test_close_and_reopen(self, tmp_path):
        db_path = str(tmp_path / "reopen.db")
        s1 = EngagementStore(db_path=db_path)
        eid = s1.create_engagement(name="persist", scope_json="{}", mode="ACTIVE")
        s1.close()
        s2 = EngagementStore(db_path=db_path)
        eng = s2.get_engagement(eid)
        assert eng["name"] == "persist"
        s2.close()
