"""Tests for the /purple command logic.

server.py requires Python 3.10+ and heavy deps (gradio, nanobot, langgraph)
that aren't available in the local test env. We test the purple command logic
by exercising the same code path it uses: load playbook → run → format output.
"""

from __future__ import annotations

import json
import re

import pytest

from playbooks.loader import load_playbook
from playbooks.runner import run_playbook
from playbooks.schema import StepStatus


# ── Helpers mimicking _handle_purple_command internals ────────────────────────


def _strip_code_fences(raw: str) -> str:
    """Strip markdown code fences the LLM may wrap around JSON."""
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*\n?", "", raw)
        raw = re.sub(r"\n?```\s*$", "", raw)
    return raw


def _format_purple_output(pb, scope: str) -> str:
    """Reproduce the output formatting from _handle_purple_command."""
    lines = [f"## 🟣 Purple Team Exercise\n**Scope:** `{scope}`\n"]

    for step in pb.steps:
        if step.status in (StepStatus.COMPLETED, StepStatus.FAILED, StepStatus.SKIPPED):
            icon = "✅" if step.status == StepStatus.COMPLETED else "❌"
            lines.append(f"{icon} **{step.name}** ({step.tool}.{step.action})")

    completed = sum(1 for s in pb.steps if s.status == StepStatus.COMPLETED)
    failed = sum(1 for s in pb.steps if s.status == StepStatus.FAILED)
    total = len(pb.steps)
    lines.append(f"\n**Results:** {completed}/{total} steps completed, {failed} failed")

    report_step = next(
        (
            s
            for s in reversed(pb.steps)
            if s.tool == "purple_team" and s.action == "exercise_report" and s.status == StepStatus.COMPLETED
        ),
        None,
    )
    if report_step and report_step.output:
        try:
            raw = _strip_code_fences(report_step.output)
            report = json.loads(raw)
            rate = report.get("detection_rate", report.get("detection_rate_pct", 0))
            rating = report.get("rating", "UNKNOWN")
            lines.append("\n### ATT&CK Coverage")
            lines.append(f"**Rating:** {rating} ({rate:.0%} detection rate)")
            if report.get("critical_findings"):
                lines.append(f"**Critical gaps:** {len(report['critical_findings'])}")
        except (json.JSONDecodeError, TypeError):
            lines.append(f"\n### Raw Report Output\n```\n{report_step.output[:2000]}\n```")

    return "\n".join(lines)


# ── Tests ────────────────────────────────────────────────────────────────────


class TestPurpleCommandEndToEnd:
    """Exercises the full playbook load → run → format pipeline."""

    @pytest.mark.asyncio
    async def test_all_steps_succeed(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})

        async def mock_dispatch(tool: str, action: str, params: dict) -> str:
            if tool == "purple_team" and action == "exercise_report":
                return json.dumps(
                    {
                        "rating": "GOOD",
                        "detection_rate": 0.85,
                        "critical_findings": [],
                    }
                )
            if tool == "purple_team" and action == "coverage_matrix":
                return json.dumps({"matrix": [], "summary": {"detection_rate": 0.85}})
            return json.dumps({"status": "ok"})

        await run_playbook(pb, mock_dispatch)
        output = _format_purple_output(pb, "10.0.0.1")

        assert "Purple Team Exercise" in output
        assert "10.0.0.1" in output
        assert "9/9 steps completed, 0 failed" in output
        assert "ATT&CK Coverage" in output
        assert "GOOD" in output
        assert "85%" in output

    @pytest.mark.asyncio
    async def test_some_steps_fail(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})

        async def partial_dispatch(tool: str, action: str, params: dict) -> str:
            if tool == "blackarch":
                raise RuntimeError("nmap not available")
            return json.dumps({"status": "ok"})

        await run_playbook(pb, partial_dispatch)
        output = _format_purple_output(pb, "10.0.0.1")

        assert "❌" in output
        assert "✅" in output
        assert "1 failed" in output

    @pytest.mark.asyncio
    async def test_critical_rating(self):
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})

        async def low_rate_dispatch(tool: str, action: str, params: dict) -> str:
            if tool == "purple_team" and action == "exercise_report":
                return json.dumps(
                    {
                        "rating": "CRITICAL",
                        "detection_rate": 0.20,
                        "critical_findings": [
                            {"technique": "T1046", "gap": "undetected"},
                            {"technique": "T1595", "gap": "undetected"},
                        ],
                    }
                )
            return json.dumps({"status": "ok"})

        await run_playbook(pb, low_rate_dispatch)
        output = _format_purple_output(pb, "192.168.4.0/24")

        assert "CRITICAL" in output
        assert "20%" in output
        assert "Critical gaps:** 2" in output

    @pytest.mark.asyncio
    async def test_no_report_step(self):
        """When exercise_report fails, output still has step summary."""
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})

        async def report_fails(tool: str, action: str, params: dict) -> str:
            if action == "exercise_report":
                raise RuntimeError("purple_team unavailable")
            return json.dumps({"ok": True})

        await run_playbook(pb, report_fails)
        output = _format_purple_output(pb, "10.0.0.1")

        assert "Results:" in output
        assert "ATT&CK Coverage" not in output
        assert "1 failed" in output

    @pytest.mark.asyncio
    async def test_malformed_report_json(self):
        """When report output is not valid JSON, show raw output."""
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})

        async def bad_json_dispatch(tool: str, action: str, params: dict) -> str:
            if tool == "purple_team" and action == "exercise_report":
                return "NOT VALID JSON {{{}"
            return json.dumps({"ok": True})

        await run_playbook(pb, bad_json_dispatch)
        output = _format_purple_output(pb, "10.0.0.1")

        assert "Raw Report Output" in output
        assert "NOT VALID JSON" in output


class TestCodeFenceStripping:
    """The LLM often wraps JSON in markdown fences — verify we handle it."""

    def test_strip_json_fence(self):
        raw = '```json\n{"rating": "GOOD"}\n```'
        assert _strip_code_fences(raw) == '{"rating": "GOOD"}'

    def test_strip_bare_fence(self):
        raw = '```\n{"x": 1}\n```'
        assert _strip_code_fences(raw) == '{"x": 1}'

    def test_no_fence_passthrough(self):
        raw = '{"x": 1}'
        assert _strip_code_fences(raw) == '{"x": 1}'

    def test_strip_with_trailing_whitespace(self):
        raw = '```json\n{"x": 1}\n```  \n'
        assert _strip_code_fences(raw) == '{"x": 1}'

    @pytest.mark.asyncio
    async def test_fenced_report_parsed_correctly(self):
        """End-to-end: LLM returns fenced JSON, output still shows coverage."""
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})

        async def fenced_dispatch(tool: str, action: str, params: dict) -> str:
            if tool == "purple_team" and action == "exercise_report":
                return '```json\n{"rating": "GOOD", "detection_rate": 0.9}\n```'
            return '{"ok": true}'

        await run_playbook(pb, fenced_dispatch)
        output = _format_purple_output(pb, "10.0.0.1")

        assert "ATT&CK Coverage" in output
        assert "GOOD" in output
        assert "90%" in output
        assert "Raw Report Output" not in output

    @pytest.mark.asyncio
    async def test_detection_rate_pct_fallback(self):
        """The live API returns detection_rate_pct instead of detection_rate."""
        pb = load_playbook("purple_team_exercise", {"target": "10.0.0.1"})

        async def pct_dispatch(tool: str, action: str, params: dict) -> str:
            if tool == "purple_team" and action == "exercise_report":
                return json.dumps(
                    {
                        "rating": "CRITICAL",
                        "detection_rate_pct": 0.15,
                    }
                )
            return '{"ok": true}'

        await run_playbook(pb, pct_dispatch)
        output = _format_purple_output(pb, "10.0.0.1")

        assert "CRITICAL" in output
        assert "15%" in output


class TestPurpleCommandScope:
    """Test scope parameter handling."""

    @pytest.mark.asyncio
    async def test_scope_substituted_into_params(self):
        pb = load_playbook("purple_team_exercise", {"target": "172.16.0.0/12"})
        assert pb.steps[0].params["target"] == "172.16.0.0/12"

    @pytest.mark.asyncio
    async def test_exercise_name_in_params(self):
        pb = load_playbook(
            "purple_team_exercise",
            {
                "target": "10.0.0.1",
                "exercise_name": "purple-abc12345",
            },
        )
        report_step = pb.steps[-1]
        assert report_step.params["exercise_name"] == "purple-abc12345"

    @pytest.mark.asyncio
    async def test_step_callbacks_fire_for_all_steps(self):
        pb = load_playbook("purple_team_exercise", {"target": "x"})
        names = []

        async def dispatch(t, a, p):
            return '{"ok": true}'

        def on_complete(step):
            names.append(step.name)

        await run_playbook(pb, dispatch, on_step_complete=on_complete)
        assert len(names) == 9
        assert names[0] == "red_nmap_scan"
        assert names[-1] == "exercise_report"
