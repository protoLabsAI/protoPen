from __future__ import annotations

import pytest

from operator_api.engagement import (
    build_engagement_status,
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
