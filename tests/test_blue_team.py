"""Tests for Phase 4 blue-team tools — purple team, IR containment, chain planner."""
from __future__ import annotations

import json

import pytest

from tools.purple_team import PurpleTeamTool, MITRE_TACTICS
from tools.ir_toolkit import IrToolkitTool
from knowledge.chain_planner import suggest_next_steps, format_suggestions
from knowledge.target_profile import TargetProfile, TargetPort


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def purple():
    return PurpleTeamTool()


@pytest.fixture
def ir():
    return IrToolkitTool()


def _red_results(*technique_ids, success=True):
    """Helper to build red-team result dicts."""
    return [
        {"technique_id": tid, "technique_name": f"Tech {tid}", "success": success}
        for tid in technique_ids
    ]


def _blue_results(*technique_ids):
    """Helper to build blue-team detection dicts."""
    return [
        {"technique_id": tid, "detected": True}
        for tid in technique_ids
    ]


# ── PurpleTeamTool ───────────────────────────────────────────────────────────

class TestPurpleTeamInstantiation:
    def test_name_and_actions(self, purple):
        assert purple.name == "purple_team"
        assert set(purple.ACTIONS) == {"coverage_matrix", "detection_gap", "exercise_report"}

    @pytest.mark.asyncio
    async def test_unknown_action(self, purple):
        result = await purple.execute("bogus")
        assert "Unknown action" in result

    @pytest.mark.asyncio
    async def test_invalid_json_input(self, purple):
        result = await purple.execute("coverage_matrix", red_results="not json")
        data = json.loads(result)
        assert "error" in data
        assert "Invalid JSON" in data["error"]


class TestCoverageMatrix:
    def test_empty_results(self, purple):
        raw = purple._coverage_matrix([], [])
        data = json.loads(raw)
        assert data["summary"]["techniques_tested"] == 0
        assert data["summary"]["detection_rate"] == 0.0
        assert data["summary"]["gaps"] == []
        # Matrix should contain all MITRE tactics
        assert set(data["matrix"].keys()) == set(MITRE_TACTICS.keys())

    def test_all_techniques_in_matrix_are_not_tested(self, purple):
        raw = purple._coverage_matrix([], [])
        data = json.loads(raw)
        for tactic, techniques in data["matrix"].items():
            for t in techniques:
                assert t["status"] == "not_tested", f"{tactic}/{t['id']} should be not_tested"

    def test_attacked_and_detected(self, purple):
        red = _red_results("T1190", "T1046")
        blue = _blue_results("T1190")
        raw = purple._coverage_matrix(red, blue)
        data = json.loads(raw)

        assert data["summary"]["techniques_tested"] == 2
        assert data["summary"]["techniques_detected"] == 1
        assert data["summary"]["detection_rate"] == 50.0
        assert data["summary"]["gaps"] == ["T1046"]

    def test_full_detection_100_pct(self, purple):
        red = _red_results("T1190", "T1046")
        blue = _blue_results("T1190", "T1046")
        raw = purple._coverage_matrix(red, blue)
        data = json.loads(raw)

        assert data["summary"]["detection_rate"] == 100.0
        assert data["summary"]["gaps"] == []

    def test_matrix_status_values(self, purple):
        red = _red_results("T1190", "T1046")
        blue = _blue_results("T1190")
        data = json.loads(purple._coverage_matrix(red, blue))

        # T1190 is in initial_access — should be "detected"
        ia = data["matrix"]["initial_access"]
        t1190 = next(t for t in ia if t["id"] == "T1190")
        assert t1190["status"] == "detected"

        # T1046 is in discovery — should be "gap"
        disc = data["matrix"]["discovery"]
        t1046 = next(t for t in disc if t["id"] == "T1046")
        assert t1046["status"] == "gap"

    def test_technique_key_fallback(self, purple):
        """Results using 'technique' key instead of 'technique_id' should still work."""
        red = [{"technique": "T1190", "success": True}]
        blue = [{"technique": "T1190", "detected": True}]
        data = json.loads(purple._coverage_matrix(red, blue))
        assert data["summary"]["techniques_tested"] == 1
        assert data["summary"]["techniques_detected"] == 1

    def test_blue_without_detected_flag(self, purple):
        """Blue results missing 'detected': True should not count as detected."""
        red = _red_results("T1190")
        blue = [{"technique_id": "T1190", "detected": False}]
        data = json.loads(purple._coverage_matrix(red, blue))
        assert data["summary"]["techniques_detected"] == 0
        assert data["summary"]["gaps"] == ["T1190"]


class TestDetectionGap:
    def test_empty_inputs(self, purple):
        data = json.loads(purple._detection_gap([], []))
        assert data["total_attacks"] == 0
        assert data["detected"] == 0
        assert data["gaps"] == []
        assert data["gap_count"] == 0

    def test_all_detected_no_gaps(self, purple):
        red = _red_results("T1190", "T1046")
        blue = _blue_results("T1190", "T1046")
        data = json.loads(purple._detection_gap(red, blue))
        assert data["gap_count"] == 0
        assert data["detected"] == 2

    def test_gaps_with_severity(self, purple):
        red = [
            {"technique_id": "T1190", "technique_name": "Exploit", "success": True},
            {"technique_id": "T1046", "technique_name": "Discovery", "success": False},
        ]
        blue = []  # no detections
        data = json.loads(purple._detection_gap(red, blue))
        assert data["gap_count"] == 2

        gap_map = {g["technique_id"]: g for g in data["gaps"]}
        # Successful attack → critical severity
        assert gap_map["T1190"]["severity"] == "critical"
        assert gap_map["T1190"]["attack_succeeded"] is True
        # Failed attack → info severity (attack didn't succeed, just a capability gap)
        assert gap_map["T1046"]["severity"] == "info"
        assert gap_map["T1046"]["attack_succeeded"] is False

    def test_recommendation_text(self, purple):
        red = _red_results("T1190")
        data = json.loads(purple._detection_gap(red, []))
        assert data["gaps"][0]["recommendation"].startswith("Add detection for T1190")


class TestExerciseReport:
    def test_empty_exercise(self, purple):
        data = json.loads(purple._exercise_report("Test Ex", "10.0.0.0/24", [], []))
        assert data["exercise"] == "Test Ex"
        assert data["scope"] == "10.0.0.0/24"
        assert data["detection_rate_pct"] == 0.0
        assert data["rating"] == "CRITICAL — significant gaps"

    def test_good_rating(self, purple):
        red = _red_results("T1190", "T1046", "T1110")
        blue = _blue_results("T1190", "T1046", "T1110")
        data = json.loads(purple._exercise_report("Ex", "", red, blue))
        assert data["detection_rate_pct"] == 100.0
        assert data["rating"] == "GOOD"

    def test_needs_improvement_rating(self, purple):
        red = _red_results("T1190", "T1046")
        blue = _blue_results("T1190")  # 50% detection
        data = json.loads(purple._exercise_report("Ex", "", red, blue))
        assert data["detection_rate_pct"] == 50.0
        assert data["rating"] == "NEEDS IMPROVEMENT"

    def test_critical_rating_below_50(self, purple):
        red = _red_results("T1190", "T1046", "T1110")
        blue = _blue_results("T1190")  # 33% detection
        data = json.loads(purple._exercise_report("Ex", "", red, blue))
        assert data["detection_rate_pct"] < 50.0
        assert data["rating"] == "CRITICAL — significant gaps"

    def test_report_contains_critical_findings(self, purple):
        red = [
            {"technique_id": "T1190", "technique_name": "Exploit", "success": True},
            {"technique_id": "T1046", "technique_name": "Discovery", "success": False},
        ]
        blue = []
        data = json.loads(purple._exercise_report("Ex", "", red, blue))
        assert data["summary"]["critical_gaps"] == 1  # T1190 success=True → critical
        assert data["summary"]["high_gaps"] == 0  # T1046 success=False → info (not high)
        assert len(data["critical_findings"]) == 1
        assert data["critical_findings"][0]["technique_id"] == "T1190"

    def test_report_has_recommendations(self, purple):
        red = _red_results("T1190")
        data = json.loads(purple._exercise_report("Ex", "", red, []))
        assert len(data["recommendations"]) > 0

    def test_report_includes_coverage_matrix(self, purple):
        red = _red_results("T1190")
        blue = _blue_results("T1190")
        data = json.loads(purple._exercise_report("Ex", "", red, blue))
        assert "coverage_matrix" in data
        assert "initial_access" in data["coverage_matrix"]


# ── IrToolkitTool — containment_recommend ────────────────────────────────────

class TestIrToolkitInstantiation:
    def test_name_and_actions(self, ir):
        assert ir.name == "ir_toolkit"
        expected = {"log_search", "ioc_scan", "auth_log_analyze", "timeline_build", "containment_recommend"}
        assert set(ir.ACTIONS) == expected

    @pytest.mark.asyncio
    async def test_unknown_action(self, ir):
        result = await ir.execute("bogus")
        assert "Unknown action" in result


class TestContainmentRecommend:
    def test_generic_no_attack_type(self, ir):
        raw = ir._containment_recommend("", "[]")
        data = json.loads(raw)
        assert data["attack_type"] == "generic"
        assert data["compromised_hosts"] == []
        # Should still have universal immediate actions
        assert len(data["recommendations"]["immediate"]) >= 3

    def test_brute_force(self, ir):
        raw = ir._containment_recommend("brute_force", "[]")
        data = json.loads(raw)
        assert data["attack_type"] == "brute_force"
        immediate = " ".join(data["recommendations"]["immediate"])
        assert "Block" in immediate or "block" in immediate
        assert len(data["recommendations"]["short_term"]) > 0
        assert len(data["recommendations"]["long_term"]) > 0

    def test_malware(self, ir):
        raw = ir._containment_recommend("malware", "[]")
        data = json.loads(raw)
        assert any("C2" in r for r in data["recommendations"]["immediate"])

    def test_data_exfil(self, ir):
        raw = ir._containment_recommend("data_exfil", "[]")
        data = json.loads(raw)
        assert any("exfiltration" in r.lower() for r in data["recommendations"]["immediate"])

    def test_privilege_escalation(self, ir):
        raw = ir._containment_recommend("privilege_escalation", "[]")
        data = json.loads(raw)
        assert any("privilege" in r.lower() for r in data["recommendations"]["immediate"])

    def test_unknown_attack_type_still_returns_universal(self, ir):
        raw = ir._containment_recommend("zero_day_magic", "[]")
        data = json.loads(raw)
        assert data["attack_type"] == "zero_day_magic"
        # Universal recommendations always present
        assert len(data["recommendations"]["immediate"]) >= 3

    def test_compromised_hosts_listed(self, ir):
        hosts = json.dumps(["10.0.0.5", "10.0.0.12"])
        raw = ir._containment_recommend("brute_force", hosts)
        data = json.loads(raw)
        assert data["compromised_hosts"] == ["10.0.0.5", "10.0.0.12"]
        # First immediate action should reference priority hosts
        assert "10.0.0.5" in data["recommendations"]["immediate"][0]

    def test_invalid_hosts_json(self, ir):
        raw = ir._containment_recommend("malware", "not-json")
        data = json.loads(raw)
        # Should not crash — falls back to empty hosts
        assert data["compromised_hosts"] == []

    def test_empty_hosts_string(self, ir):
        raw = ir._containment_recommend("malware", "")
        data = json.loads(raw)
        assert data["compromised_hosts"] == []


# ── ChainPlanner ─────────────────────────────────────────────────────────────

class TestChainPlanner:
    def _profile(self, **kwargs) -> TargetProfile:
        return TargetProfile(ip="10.0.0.1", **kwargs)

    def test_no_services_no_suggestions(self):
        profile = self._profile()
        suggestions = suggest_next_steps(profile)
        assert suggestions == []

    def test_web_service_triggers_web_suggestions(self):
        profile = self._profile(
            ports=[TargetPort(port=80, service="http")]
        )
        suggestions = suggest_next_steps(profile)
        tools = [s["tool"] for s in suggestions]
        assert "web_enum" in tools
        assert "ssl_audit" in tools
        assert "vuln_scan" in tools
        assert all(s["rule_name"] == "web_discovered" for s in suggestions)

    def test_smb_service_by_name(self):
        profile = self._profile(
            ports=[TargetPort(port=445, service="microsoft-ds")]
        )
        suggestions = suggest_next_steps(profile)
        tools = [s["tool"] for s in suggestions]
        assert "service_enum" in tools

    def test_smb_service_by_port(self):
        profile = self._profile(
            ports=[TargetPort(port=445, service="")]
        )
        suggestions = suggest_next_steps(profile)
        tools = [s["tool"] for s in suggestions]
        assert "service_enum" in tools

    def test_ssh_service(self):
        profile = self._profile(
            ports=[TargetPort(port=22, service="ssh")]
        )
        suggestions = suggest_next_steps(profile)
        tools = [s["tool"] for s in suggestions]
        assert "credential_attack" in tools

    def test_dns_service(self):
        profile = self._profile(
            ports=[TargetPort(port=53, service="domain")]
        )
        suggestions = suggest_next_steps(profile)
        tools = [s["tool"] for s in suggestions]
        assert "dns_enum" in tools

    def test_web_paths_trigger_vuln_assessment(self):
        profile = self._profile(
            web_paths=[{"path": "/admin", "status": 200}]
        )
        suggestions = suggest_next_steps(profile)
        tools = [s["tool"] for s in suggestions]
        assert "web_vuln" in tools
        assert "sql_test" in tools

    def test_users_found_triggers_spray(self):
        profile = self._profile(users=["admin", "root"])
        suggestions = suggest_next_steps(profile)
        actions = [s["action"] for s in suggestions]
        assert "hydra_spray" in actions

    def test_vulns_trigger_exploit_search(self):
        profile = self._profile(
            vulnerabilities=[{"cve": "CVE-2024-1234", "severity": "critical"}]
        )
        suggestions = suggest_next_steps(profile)
        tools = [s["tool"] for s in suggestions]
        assert "msf_exploit" in tools
        assert "cve_match" in tools

    def test_creds_trigger_lateral_movement(self):
        profile = self._profile(
            credentials=[{"username": "admin", "password": "pass"}]
        )
        suggestions = suggest_next_steps(profile)
        tools = [s["tool"] for s in suggestions]
        assert "lateral_move" in tools

    def test_multiple_services_compound(self):
        """A rich profile should trigger multiple rule sets."""
        profile = self._profile(
            ports=[
                TargetPort(port=80, service="http"),
                TargetPort(port=22, service="ssh"),
                TargetPort(port=445, service="microsoft-ds"),
            ],
            web_paths=[{"path": "/login", "status": 200}],
        )
        suggestions = suggest_next_steps(profile)
        rules = {s["rule_name"] for s in suggestions}
        assert "web_discovered" in rules
        assert "ssh_discovered" in rules
        assert "smb_discovered" in rules
        assert "web_paths_found" in rules

    def test_max_suggestions_limit(self):
        profile = self._profile(
            ports=[
                TargetPort(port=80, service="http"),
                TargetPort(port=22, service="ssh"),
                TargetPort(port=445, service="microsoft-ds"),
                TargetPort(port=53, service="domain"),
            ],
            web_paths=[{"path": "/a"}],
            users=["admin"],
            vulnerabilities=[{"cve": "X"}],
            credentials=[{"username": "a", "password": "b"}],
        )
        suggestions = suggest_next_steps(profile, max_suggestions=3)
        assert len(suggestions) == 3

    def test_suggestion_has_required_keys(self):
        profile = self._profile(
            ports=[TargetPort(port=80, service="http")]
        )
        suggestions = suggest_next_steps(profile)
        for s in suggestions:
            assert "tool" in s
            assert "action" in s
            assert "reason" in s
            assert "rule_name" in s


class TestFormatSuggestions:
    def test_empty_suggestions(self):
        output = format_suggestions([])
        assert "No specific recommendations" in output

    def test_formatted_output(self):
        suggestions = [
            {"tool": "web_enum", "action": "gobuster_dir", "reason": "Enum dirs"},
            {"tool": "ssl_audit", "action": "ssl_full_audit", "reason": "Check SSL"},
        ]
        output = format_suggestions(suggestions)
        assert "Recommended next steps:" in output
        assert "1. [web_enum.gobuster_dir]" in output
        assert "2. [ssl_audit.ssl_full_audit]" in output
