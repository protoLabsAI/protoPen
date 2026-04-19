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
        pb = load_playbook(
            "incident_response",
            {
                "log_path": "/tmp/test-logs",
                "pattern": "segfault",
            },
        )
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
        pb = load_playbook(
            "incident_response",
            {
                "log_path": "/var/log",
                "pattern": "sshd",
                "keyword": "failed",
                "iocs": "[]",
                "attack_type": "brute_force",
                "compromised_hosts": "[]",
            },
        )
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

    def test_red_steps_have_phase(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        red_steps = [s for s in pb.steps if s.name.startswith("red_")]
        assert len(red_steps) == 3
        for step in red_steps:
            assert step.phase == "red", f"{step.name} should have phase=red"

    def test_blue_steps_have_phase(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        blue_steps = [s for s in pb.steps if s.name.startswith("blue_")]
        assert len(blue_steps) == 4
        for step in blue_steps:
            assert step.phase == "blue", f"{step.name} should have phase=blue"


# ── Step output field refs ────────────────────────────────────────────────────


class TestStepOutputFieldRefs:
    """${steps.NAME.output.FIELD} extracts a JSON field from a prior step's output."""

    @pytest.mark.asyncio
    async def test_field_ref_extracts_json_key(self):
        """Basic field extraction: producer outputs JSON, consumer reads one key."""
        pb = Playbook(
            name="field-ref-test",
            steps=[
                PlaybookStep(name="capture", tool="traffic_analysis", action="pcap_capture", on_fail="continue"),
                PlaybookStep(
                    name="parse",
                    tool="traffic_analysis",
                    action="pcap_parse",
                    params={"pcap_file": "${steps.capture.output.pcap_file}"},
                    on_fail="continue",
                ),
            ],
        )

        async def dispatch(tool: str, action: str, params: dict) -> str:
            if action == "pcap_capture":
                return json.dumps({"pcap_file": "/tmp/capture.pcap", "packet_count": 42})
            return json.dumps({"received_path": params.get("pcap_file", "")})

        await run_playbook(pb, dispatch)
        assert pb.steps[1].status == StepStatus.COMPLETED
        result = json.loads(pb.steps[1].output)
        assert result["received_path"] == "/tmp/capture.pcap"

    @pytest.mark.asyncio
    async def test_field_ref_missing_key_leaves_empty(self):
        """If the field doesn't exist in the JSON output, resolves to empty string."""
        pb = Playbook(
            name="field-ref-missing",
            steps=[
                PlaybookStep(name="step1", tool="t", action="a", on_fail="continue"),
                PlaybookStep(
                    name="step2",
                    tool="t",
                    action="b",
                    params={"path": "${steps.step1.output.nonexistent_field}"},
                    on_fail="continue",
                ),
            ],
        )

        async def dispatch(tool: str, action: str, params: dict) -> str:
            if action == "a":
                return json.dumps({"other_field": "value"})
            return json.dumps({"got": params.get("path", "UNSET")})

        await run_playbook(pb, dispatch)
        result = json.loads(pb.steps[1].output)
        assert result["got"] == ""

    @pytest.mark.asyncio
    async def test_field_ref_non_json_output_leaves_ref(self):
        """If prior step output is not JSON, the ref is left as-is."""
        pb = Playbook(
            name="field-ref-non-json",
            steps=[
                PlaybookStep(name="step1", tool="t", action="a", on_fail="continue"),
                PlaybookStep(
                    name="step2",
                    tool="t",
                    action="b",
                    params={"path": "${steps.step1.output.pcap_file}"},
                    on_fail="continue",
                ),
            ],
        )
        original_ref = "${steps.step1.output.pcap_file}"
        dispatched_path = None

        async def dispatch(tool: str, action: str, params: dict) -> str:
            nonlocal dispatched_path
            if action == "a":
                return "plain text, not JSON"
            dispatched_path = params.get("path")
            return "{}"

        await run_playbook(pb, dispatch)
        assert dispatched_path == original_ref

    @pytest.mark.asyncio
    async def test_field_ref_network_traffic_survey_wiring(self):
        """network_traffic_survey playbook correctly wires pcap_file between steps."""
        pb = load_playbook(
            "network_traffic_survey",
            {"interface": "eth0", "duration": "10", "filter": ""},
        )
        parse_step = next(s for s in pb.steps if s.name == "parse_capture")
        harvest_step = next(s for s in pb.steps if s.name == "harvest_cleartext")
        assert "${steps.capture_traffic.output.pcap_file}" in parse_step.params["pcap_file"]
        assert "${steps.capture_traffic.output.pcap_file}" in harvest_step.params["pcap_file"]

    def test_correlation_steps_have_no_phase(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        for step in pb.steps:
            if step.tool == "purple_team":
                assert step.phase is None

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


# ── ATT&CK Normalization in Runner ──────────────────────────────────────────


NMAP_XML_SAMPLE = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

SSH_AUDIT_SAMPLE = json.dumps(
    {
        "target": "10.0.0.1",
        "checks_run": 5,
        "issues": [
            {
                "severity": "high",
                "check": "PasswordAuthentication",
                "value": "yes",
                "recommendation": "Disable password auth",
            },
        ],
        "pass_count": 4,
        "fail_count": 1,
    }
)


class TestATTACKNormalization:
    """Phase-tagged steps are auto-normalized to ATT&CK format."""

    @pytest.mark.asyncio
    async def test_single_red_step_normalized(self):
        """A single phase=red step ref is normalized to ATT&CK JSON."""
        pb = Playbook(
            name="norm-test",
            steps=[
                PlaybookStep(
                    name="nmap",
                    tool="blackarch",
                    action="nmap_scan",
                    phase="red",
                    on_fail="continue",
                ),
                PlaybookStep(
                    name="consumer",
                    tool="t",
                    action="a",
                    params={"red_results": "${steps.nmap.output}"},
                    on_fail="continue",
                ),
            ],
        )
        received = {}

        async def dispatch(tool: str, action: str, params: dict) -> str:
            if action == "nmap_scan":
                return NMAP_XML_SAMPLE
            received.update(params)
            return "{}"

        await run_playbook(pb, dispatch)
        red = json.loads(received["red_results"])
        assert isinstance(red, list)
        assert red[0]["technique_id"] == "T1046"
        assert red[0]["success"] is True

    @pytest.mark.asyncio
    async def test_multi_ref_merge(self):
        """Multiple phase-tagged refs in one param are merged into one array."""
        pb = Playbook(
            name="merge-test",
            steps=[
                PlaybookStep(
                    name="nmap",
                    tool="blackarch",
                    action="nmap_scan",
                    phase="red",
                    on_fail="continue",
                ),
                PlaybookStep(
                    name="nikto",
                    tool="vuln_scan",
                    action="nikto_scan",
                    phase="red",
                    on_fail="continue",
                ),
                PlaybookStep(
                    name="correlate",
                    tool="t",
                    action="a",
                    params={
                        "red_results": "${steps.nmap.output},${steps.nikto.output}",
                    },
                    on_fail="continue",
                ),
            ],
        )
        received = {}

        async def dispatch(tool: str, action: str, params: dict) -> str:
            if action == "nmap_scan":
                return NMAP_XML_SAMPLE
            if action == "nikto_scan":
                return "Found vulnerable endpoint /admin"
            received.update(params)
            return "{}"

        await run_playbook(pb, dispatch)
        red = json.loads(received["red_results"])
        assert isinstance(red, list)
        technique_ids = {r["technique_id"] for r in red}
        assert "T1046" in technique_ids  # from nmap
        assert "T1190" in technique_ids  # from nikto

    @pytest.mark.asyncio
    async def test_blue_normalization(self):
        """Phase=blue steps produce detected fields."""
        pb = Playbook(
            name="blue-norm",
            steps=[
                PlaybookStep(
                    name="ssh",
                    tool="cis_audit",
                    action="ssh_audit",
                    phase="blue",
                    on_fail="continue",
                ),
                PlaybookStep(
                    name="consumer",
                    tool="t",
                    action="a",
                    params={"blue_results": "${steps.ssh.output}"},
                    on_fail="continue",
                ),
            ],
        )
        received = {}

        async def dispatch(tool: str, action: str, params: dict) -> str:
            if action == "ssh_audit":
                return SSH_AUDIT_SAMPLE
            received.update(params)
            return "{}"

        await run_playbook(pb, dispatch)
        blue = json.loads(received["blue_results"])
        assert isinstance(blue, list)
        assert any(b["technique_id"] == "T1021" and b["detected"] for b in blue)

    @pytest.mark.asyncio
    async def test_no_phase_no_normalization(self):
        """Steps without phase tag pass raw output through."""
        pb = Playbook(
            name="raw-test",
            steps=[
                PlaybookStep(
                    name="producer",
                    tool="t",
                    action="a",
                    on_fail="continue",
                ),
                PlaybookStep(
                    name="consumer",
                    tool="t",
                    action="b",
                    params={"data": "${steps.producer.output}"},
                    on_fail="continue",
                ),
            ],
        )
        received = {}

        async def dispatch(tool: str, action: str, params: dict) -> str:
            if action == "a":
                return "raw prose output"
            received.update(params)
            return "{}"

        await run_playbook(pb, dispatch)
        assert received["data"] == "raw prose output"

    @pytest.mark.asyncio
    async def test_end_to_end_purple_exercise_normalization(self):
        """Full purple_team_exercise with raw tool outputs → normalized correlation."""
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})
        correlation_params = {}

        async def dispatch(tool: str, action: str, params: dict) -> str:
            if tool == "blackarch":
                return NMAP_XML_SAMPLE
            if tool == "dns_enum":
                return "Found A record for host"
            if tool == "vuln_scan":
                return "Found vulnerable endpoint"
            if tool == "cis_audit":
                return SSH_AUDIT_SAMPLE
            if tool == "hardening_check":
                return json.dumps({"issues": [{"check": "weak"}], "fail_count": 1})
            if tool == "purple_team":
                correlation_params[action] = dict(params)
                return json.dumps({"matrix": {}, "summary": {"detection_rate": 50.0}})
            return "{}"

        await run_playbook(pb, dispatch)

        # Verify correlation received valid JSON arrays
        red = json.loads(correlation_params["coverage_matrix"]["red_results"])
        blue = json.loads(correlation_params["coverage_matrix"]["blue_results"])
        assert isinstance(red, list)
        assert isinstance(blue, list)
        assert len(red) > 0
        assert len(blue) > 0

        # Verify technique IDs present
        red_tids = {r["technique_id"] for r in red}
        blue_tids = {b["technique_id"] for b in blue}
        assert "T1046" in red_tids  # from nmap
        assert "T1021" in blue_tids  # from ssh_audit
