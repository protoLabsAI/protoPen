from __future__ import annotations

import pytest

from operator_api.engagement import (
    build_engagement_status,
    control_engagement,
    generate_engagement_report,
    read_engagement_report,
)


class _Manager:
    def __init__(self, *, workspace=None, findings=None, name="op-1"):
        self.active_engagement = (
            {"name": name, "scope": "10.0.0.0/24", "mode": "REDTEAM", "workspace": str(workspace)} if workspace else {}
        )
        self.findings = findings or []
        self.current_phase = "recon"
        self._generated = False

    def generate_report(self):
        self._generated = True
        from pathlib import Path

        path = Path(self.active_engagement["workspace"]) / "report.md"
        path.write_text("# generated report\n")
        return "# generated report\n"


def test_build_engagement_status_surfaces_detail(tmp_path) -> None:
    mgr = _Manager(
        workspace=tmp_path,
        findings=[{"severity": "high", "category": "auth", "title": "weak ssh", "detail": "password auth enabled"}],
    )
    status = build_engagement_status(mgr)
    assert status["active"] is True
    assert status["findings"][0]["detail"] == "password auth enabled"
    assert status["findings"][0]["severity"] == "high"


def test_read_report_unavailable_when_not_generated(tmp_path) -> None:
    mgr = _Manager(workspace=tmp_path)
    result = read_engagement_report(mgr)
    assert result["available"] is False
    assert result["name"] == "op-1"


def test_read_report_returns_markdown_when_present(tmp_path) -> None:
    (tmp_path / "report.md").write_text("# existing\n")
    mgr = _Manager(workspace=tmp_path)
    result = read_engagement_report(mgr)
    assert result["available"] is True
    assert result["markdown"] == "# existing\n"


def test_read_report_handles_no_manager() -> None:
    assert read_engagement_report(None) == {"available": False, "name": "", "path": "", "markdown": ""}


def test_generate_report_writes_and_returns_markdown(tmp_path) -> None:
    mgr = _Manager(workspace=tmp_path)
    result = generate_engagement_report(mgr)
    assert mgr._generated is True
    assert result["available"] is True
    assert result["markdown"] == "# generated report\n"
    assert (tmp_path / "report.md").exists()


def test_generate_report_rejects_no_active_engagement() -> None:
    mgr = _Manager()  # no workspace → empty active_engagement
    with pytest.raises(ValueError):
        generate_engagement_report(mgr)


# ── operator engagement control (start / end / set_mode) ────────────────────────


class _ControlManager:
    """Records start/end/set_mode; exposes the attrs build_engagement_status reads."""

    def __init__(self):
        self.active_engagement = None
        self._mode = "PASSIVE"
        self.findings = []
        self.current_phase = ""
        self.calls = []

    def start(self, name, scope="", mode=None):
        self.calls.append(("start", name, scope, mode))
        if mode:
            self._mode = mode.upper()
        self.active_engagement = {"name": name, "scope": scope, "mode": self._mode, "started_at": "now"}

    def end(self):
        self.calls.append(("end",))
        self.active_engagement = None

    def set_mode(self, mode):
        self.calls.append(("set_mode", mode))
        self._mode = getattr(mode, "name", str(mode))


def test_control_start_activates_and_returns_status() -> None:
    mgr = _ControlManager()
    status = control_engagement(mgr, {"action": "start", "name": "op-x", "scope": "1.2.3.4"})
    assert mgr.calls[0] == ("start", "op-x", "1.2.3.4", None)
    assert status["active"] is True
    assert status["name"] == "op-x"
    assert status["scope"] == "1.2.3.4"


def test_control_start_requires_name() -> None:
    with pytest.raises(ValueError, match="name"):
        control_engagement(_ControlManager(), {"action": "start", "scope": "x"})


def test_control_end_deactivates() -> None:
    mgr = _ControlManager()
    control_engagement(mgr, {"action": "start", "name": "op-x"})
    status = control_engagement(mgr, {"action": "end"})
    assert ("end",) in mgr.calls
    assert status["active"] is False


def test_control_set_mode_maps_enum() -> None:
    mgr = _ControlManager()
    control_engagement(mgr, {"action": "start", "name": "op-x"})
    control_engagement(mgr, {"action": "set_mode", "mode": "active"})
    call = next(c for c in mgr.calls if c[0] == "set_mode")
    assert getattr(call[1], "name", str(call[1])) == "ACTIVE"


def test_control_set_mode_requires_mode() -> None:
    with pytest.raises(ValueError, match="mode"):
        control_engagement(_ControlManager(), {"action": "set_mode"})


def test_control_set_mode_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown mode"):
        control_engagement(_ControlManager(), {"action": "set_mode", "mode": "bogus"})


def test_control_unknown_action_rejected() -> None:
    with pytest.raises(ValueError, match="unknown action"):
        control_engagement(_ControlManager(), {"action": "frobnicate"})
    with pytest.raises(ValueError, match="unknown action"):
        control_engagement(_ControlManager(), {})
