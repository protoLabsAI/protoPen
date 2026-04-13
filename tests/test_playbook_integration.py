"""Integration tests for the playbook system — loader, runner, schema."""
from __future__ import annotations

import json

import pytest

from playbooks.loader import load_playbook, list_playbooks
from playbooks.runner import run_playbook
from playbooks.schema import Playbook, PlaybookStep, StepStatus


# ── Loader ───────────────────────────────────────────────────────────────────


class TestPlaybookLoader:
    def test_list_playbooks_returns_all(self):
        names = list_playbooks()
        stems = [p["name"] for p in names]
        assert len(names) >= 6
        assert "full_recon" in stems
        assert "purple_team_exercise" in stems
        assert "defensive_assessment" in stems
        assert "incident_response" in stems

    def test_load_purple_team_exercise(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        assert isinstance(pb, Playbook)
        assert pb.name == "purple_team_exercise"
        assert len(pb.steps) == 9
        assert all(s.status == StepStatus.PENDING for s in pb.steps)

    def test_load_with_variable_substitution(self):
        pb = load_playbook("purple_team_exercise", {"target": "192.168.4.0/24"})
        nmap_step = pb.steps[0]
        assert nmap_step.params.get("target") == "192.168.4.0/24"

    def test_load_nonexistent_playbook(self):
        with pytest.raises(FileNotFoundError):
            load_playbook("does_not_exist")

    def test_load_defensive_assessment(self):
        pb = load_playbook("defensive_assessment", {"target": "10.0.0.1"})
        assert isinstance(pb, Playbook)
        assert len(pb.steps) == 6

    def test_load_incident_response(self):
        pb = load_playbook("incident_response", {"target": "10.0.0.1"})
        assert isinstance(pb, Playbook)
        assert len(pb.steps) == 5

    def test_variable_override(self):
        pb = load_playbook("incident_response", {
            "log_path": "/tmp/test-logs",
            "pattern": "segfault",
        })
        log_step = pb.steps[0]
        assert log_step.params["log_path"] == "/tmp/test-logs"
        assert log_step.params["pattern"] == "segfault"

    def test_step_on_fail_preserved(self):
        pb = load_playbook("purple_team_exercise", {"target": "x"})
        # First 8 steps explicitly set on_fail: continue; last defaults to stop
        for step in pb.steps[:8]:
            assert step.on_fail == "continue", f"{step.name} should be continue"
        assert pb.steps[8].on_fail == "stop"

    def test_step_tools_and_actions(self):
        pb = load_playbook("purple_team_exercise", {"target": "x"})
        tools_used = {s.tool for s in pb.steps}
        assert "blackarch" in tools_used
        assert "cis_audit" in tools_used
        assert "purple_team" in tools_used


# ── Runner ───────────────────────────────────────────────────────────────────


class TestPlaybookRunner:
    @pytest.mark.asyncio
    async def test_run_all_steps_succeed(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        call_log = []

        async def mock_dispatch(tool: str, action: str, params: dict) -> str:
            call_log.append((tool, action))
            if tool == "purple_team" and action == "coverage_matrix":
                return json.dumps({"matrix": [], "summary": {"detection_rate": 0.75}})
            if tool == "purple_team" and action == "exercise_report":
                return json.dumps({"rating": "NEEDS IMPROVEMENT", "detection_rate": 0.75})
            return json.dumps({"status": "ok", "results": []})

        await run_playbook(pb, mock_dispatch)
        assert pb.completed
        assert len(call_log) == 9
        tools_called = [t for t, _a in call_log]
        assert "blackarch" in tools_called
        assert "cis_audit" in tools_called
        assert "purple_team" in tools_called

    @pytest.mark.asyncio
    async def test_step_failure_continues(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})

        async def failing_dispatch(tool: str, action: str, params: dict) -> str:
            if action == "nmap_scan":
                raise RuntimeError("Connection refused")
            return json.dumps({"status": "ok"})

        await run_playbook(pb, failing_dispatch)
        # nmap step fails, rest still run because on_fail: continue
        assert pb.steps[0].status == StepStatus.FAILED
        assert pb.steps[0].error == "Connection refused"
        completed_count = sum(1 for s in pb.steps if s.status == StepStatus.COMPLETED)
        assert completed_count == 8

    @pytest.mark.asyncio
    async def test_step_failure_stops_on_stop_policy(self):
        """A step with on_fail='stop' should halt execution."""
        pb = Playbook(
            name="stop-test",
            steps=[
                PlaybookStep(name="s1", tool="t", action="a", on_fail="stop"),
                PlaybookStep(name="s2", tool="t", action="b"),
            ],
        )

        async def fail_dispatch(tool: str, action: str, params: dict) -> str:
            raise RuntimeError("boom")

        await run_playbook(pb, fail_dispatch)
        assert pb.steps[0].status == StepStatus.FAILED
        assert pb.steps[1].status == StepStatus.PENDING

    @pytest.mark.asyncio
    async def test_run_defensive_assessment(self):
        pb = load_playbook("defensive_assessment", {"target": "10.0.0.1"})
        call_log = []

        async def mock_dispatch(tool: str, action: str, params: dict) -> str:
            call_log.append((tool, action))
            return json.dumps({"checks": [], "passed": True})

        await run_playbook(pb, mock_dispatch)
        assert pb.completed
        assert len(call_log) == 6

    @pytest.mark.asyncio
    async def test_run_incident_response(self):
        pb = load_playbook("incident_response", {
            "log_path": "/var/log",
            "pattern": "sshd",
            "keyword": "failed",
            "iocs": "[]",
            "attack_type": "brute_force",
            "compromised_hosts": "[]",
        })
        call_log = []

        async def mock_dispatch(tool: str, action: str, params: dict) -> str:
            call_log.append((tool, action))
            return json.dumps({"events": [], "status": "clean"})

        await run_playbook(pb, mock_dispatch)
        assert pb.completed
        assert len(call_log) == 5
        assert all(t == "ir_toolkit" for t, _a in call_log)

    @pytest.mark.asyncio
    async def test_on_step_complete_callback(self):
        pb = load_playbook("defensive_assessment", {"target": "10.0.0.1"})
        completed_names = []

        async def mock_dispatch(tool: str, action: str, params: dict) -> str:
            return json.dumps({"ok": True})

        def on_complete(step):
            completed_names.append(step.name)

        await run_playbook(pb, mock_dispatch, on_step_complete=on_complete)
        assert len(completed_names) == len(pb.steps)
        assert completed_names[0] == "ssh_cis_audit"

    @pytest.mark.asyncio
    async def test_progress_tracking(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        assert pb.progress == "0/9"

        async def mock_dispatch(tool: str, action: str, params: dict) -> str:
            return json.dumps({"ok": True})

        await run_playbook(pb, mock_dispatch)
        assert pb.progress == "9/9"
        assert pb.completed

    @pytest.mark.asyncio
    async def test_step_output_stored(self):
        pb = load_playbook("defensive_assessment", {"target": "10.0.0.1"})

        async def mock_dispatch(tool: str, action: str, params: dict) -> str:
            return json.dumps({"check": action, "passed": True})

        await run_playbook(pb, mock_dispatch)
        for step in pb.steps:
            assert step.output
            parsed = json.loads(step.output)
            assert parsed["passed"] is True


# ── Step Output References ───────────────────────────────────────────────────


class TestStepOutputReferences:
    """Test ${steps.<name>.output} param resolution at runtime."""

    @pytest.mark.asyncio
    async def test_step_ref_resolved_from_prior_output(self):
        """A step can reference a prior step's output in its params."""
        pb = Playbook(
            name="ref-test",
            steps=[
                PlaybookStep(name="producer", tool="t", action="produce", on_fail="continue"),
                PlaybookStep(
                    name="consumer",
                    tool="t",
                    action="consume",
                    params={"data": "${steps.producer.output}"},
                    on_fail="continue",
                ),
            ],
        )
        call_log = []

        async def dispatch(tool: str, action: str, params: dict) -> str:
            call_log.append((action, params))
            if action == "produce":
                return '{"findings": ["CVE-2024-1234"]}'
            return json.dumps({"received": params.get("data", "")})

        await run_playbook(pb, dispatch)
        assert call_log[1][1]["data"] == '{"findings": ["CVE-2024-1234"]}'

    @pytest.mark.asyncio
    async def test_unresolved_ref_left_as_is(self):
        """If the referenced step doesn't exist, leave the ref as literal."""
        pb = Playbook(
            name="ref-test",
            steps=[
                PlaybookStep(
                    name="lonely",
                    tool="t",
                    action="a",
                    params={"data": "${steps.nonexistent.output}"},
                    on_fail="continue",
                ),
            ],
        )

        async def dispatch(tool: str, action: str, params: dict) -> str:
            return json.dumps({"got": params.get("data", "")})

        await run_playbook(pb, dispatch)
        assert pb.steps[0].status == StepStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_failed_step_ref_resolves_to_empty(self):
        """If referenced step failed (no output), resolve to empty string."""
        pb = Playbook(
            name="ref-test",
            steps=[
                PlaybookStep(name="broken", tool="t", action="fail", on_fail="continue"),
                PlaybookStep(
                    name="consumer",
                    tool="t",
                    action="consume",
                    params={"data": "${steps.broken.output}"},
                    on_fail="continue",
                ),
            ],
        )

        async def dispatch(tool: str, action: str, params: dict) -> str:
            if action == "fail":
                raise RuntimeError("boom")
            return json.dumps({"got": params.get("data", "")})

        await run_playbook(pb, dispatch)
        assert pb.steps[0].status == StepStatus.FAILED
        assert pb.steps[1].status == StepStatus.COMPLETED
        parsed = json.loads(pb.steps[1].output)
        assert parsed["got"] == ""

    @pytest.mark.asyncio
    async def test_multiple_refs_in_separate_params(self):
        """Multiple params can each reference different steps."""
        pb = Playbook(
            name="multi-ref",
            steps=[
                PlaybookStep(name="red", tool="t", action="r", on_fail="continue"),
                PlaybookStep(name="blue", tool="t", action="b", on_fail="continue"),
                PlaybookStep(
                    name="combine",
                    tool="t",
                    action="c",
                    params={"red": "${steps.red.output}", "blue": "${steps.blue.output}"},
                    on_fail="continue",
                ),
            ],
        )

        async def dispatch(tool: str, action: str, params: dict) -> str:
            if action == "r":
                return '[{"technique_id":"T1046"}]'
            if action == "b":
                return '[{"technique_id":"T1046","detected":true}]'
            return json.dumps({"red": params["red"], "blue": params["blue"]})

        await run_playbook(pb, dispatch)
        result = json.loads(pb.steps[2].output)
        assert "T1046" in result["red"]
        assert "detected" in result["blue"]

    @pytest.mark.asyncio
    async def test_non_string_params_untouched(self):
        """Integer/bool params should not be affected by ref resolution."""
        pb = Playbook(
            name="types-test",
            steps=[
                PlaybookStep(
                    name="s1",
                    tool="t",
                    action="a",
                    params={"port": 443, "verbose": True, "name": "${steps.x.output}"},
                    on_fail="continue",
                ),
            ],
        )

        async def dispatch(tool: str, action: str, params: dict) -> str:
            return json.dumps(params, default=str)

        await run_playbook(pb, dispatch)
        result = json.loads(pb.steps[0].output)
        assert result["port"] == 443
        assert result["verbose"] is True


# ── Purple Team Step Refs ────────────────────────────────────────────────────


class TestPurpleTeamStepRefs:
    """Verify purple_team_exercise uses step output refs for correlation."""

    def test_coverage_matrix_refs_red_and_blue(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        matrix_step = next(s for s in pb.steps if s.name == "coverage_matrix")
        assert "${steps." in matrix_step.params["red_results"]
        assert "${steps." in matrix_step.params["blue_results"]

    def test_exercise_report_refs_red_and_blue(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        report_step = next(s for s in pb.steps if s.name == "exercise_report")
        assert "${steps." in report_step.params["red_results"]
        assert "${steps." in report_step.params["blue_results"]

    @pytest.mark.asyncio
    async def test_correlation_receives_real_data(self):
        """End-to-end: red/blue outputs flow into correlation steps."""
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        correlation_params = {}

        async def tracking_dispatch(tool: str, action: str, params: dict) -> str:
            if tool == "blackarch" and action == "nmap_scan":
                return '[{"technique_id":"T1046","technique_name":"Network Service Scanning","success":true}]'
            if tool == "cis_audit":
                return '[{"technique_id":"T1046","detected":true}]'
            if tool == "purple_team":
                correlation_params[action] = dict(params)
                return json.dumps({"rating": "GOOD", "detection_rate": 1.0})
            return "[]"

        await run_playbook(pb, tracking_dispatch)

        matrix_params = correlation_params.get("coverage_matrix", {})
        assert "T1046" in matrix_params.get("red_results", "")

        report_params = correlation_params.get("exercise_report", {})
        assert "T1046" in report_params.get("red_results", "")
