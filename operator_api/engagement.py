"""Engagement + findings status for the operator console monitor view.

protoPen-specific: surfaces the live EngagementManager state (active engagement,
phase, mode) and its findings, summarized by severity, so the React console can
monitor an in-flight assessment.
"""

from __future__ import annotations

from typing import Any

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def build_engagement_status(engagement_mgr: Any) -> dict[str, Any]:
    """UI-safe snapshot of the current engagement + findings.

    Tolerant of a missing/unstarted manager: returns active=False with empty
    findings rather than raising.
    """
    if engagement_mgr is None:
        return {
            "active": False,
            "name": "",
            "scope": "",
            "mode": "",
            "phase": "",
            "started_at": "",
            "finding_counts": {},
            "total_findings": 0,
            "findings": [],
        }

    eng = getattr(engagement_mgr, "active_engagement", None) or {}
    findings = list(getattr(engagement_mgr, "findings", []) or [])

    counts: dict[str, int] = {}
    for finding in findings:
        sev = str(finding.get("severity", "") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1

    mode = eng.get("mode", "")
    if not mode:
        mode_obj = getattr(engagement_mgr, "mode", None)
        mode = getattr(mode_obj, "name", "") if mode_obj is not None else ""

    return {
        "active": bool(eng),
        "name": eng.get("name", ""),
        "scope": eng.get("scope", ""),
        "mode": mode,
        "phase": getattr(engagement_mgr, "current_phase", "") or "",
        "started_at": eng.get("started_at", ""),
        "finding_counts": {sev: counts[sev] for sev in _SEVERITY_ORDER if sev in counts}
        | {k: v for k, v in counts.items() if k not in _SEVERITY_ORDER},
        "total_findings": len(findings),
        # Most recent first, capped — UI-safe subset of each finding.
        "findings": [
            {
                "severity": str(f.get("severity", "")),
                "category": str(f.get("category", "")),
                "title": str(f.get("title", "")),
                "detail": str(f.get("detail", "")),
                "timestamp": str(f.get("timestamp", "")),
            }
            for f in reversed(findings[-100:])
        ],
    }


def control_engagement(engagement_mgr: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """Operator-side engagement control: ``start`` / ``end`` / ``set_mode`` on the
    live EngagementManager. Returns the new status snapshot. Raises ValueError on
    bad input (the route maps that to HTTP 400).

    Acts on the same manager the enforcement middleware checks, so starting an
    engagement here unblocks the agent's engagement-gated tools — the operator no
    longer has to rely on the agent calling its own engagement tool.
    """
    action = (payload or {}).get("action", "").strip().lower()
    if action == "start":
        name = (payload.get("name") or "").strip()
        if not name:
            raise ValueError("engagement 'name' is required to start")
        engagement_mgr.start(
            name,
            scope=(payload.get("scope") or "").strip(),
            mode=(payload.get("mode") or None),
        )
    elif action == "end":
        engagement_mgr.end()
    elif action == "set_mode":
        from tools.engagement import EngagementMode

        mode = (payload.get("mode") or "").strip()
        if not mode:
            raise ValueError("'mode' is required for set_mode")
        try:
            engagement_mgr.set_mode(EngagementMode[mode.upper()])
        except KeyError as exc:
            raise ValueError(f"unknown mode {mode!r} (use passive/active/redteam)") from exc
    else:
        raise ValueError(f"unknown action {action!r} (use start | end | set_mode)")
    return build_engagement_status(engagement_mgr)


def _report_path(engagement_mgr: Any):
    """Resolve the report.md path for the active engagement, or None."""
    from pathlib import Path

    eng = getattr(engagement_mgr, "active_engagement", None) or {}
    workspace = eng.get("workspace")
    if not workspace:
        return None
    return Path(workspace) / "report.md"


def read_engagement_report(engagement_mgr: Any) -> dict[str, Any]:
    """Read the already-generated report.md (no side effects).

    Returns available=False when there's no active engagement or the report
    hasn't been generated yet — the console then offers to generate one.
    """
    if engagement_mgr is None:
        return {"available": False, "name": "", "path": "", "markdown": ""}

    path = _report_path(engagement_mgr)
    eng = getattr(engagement_mgr, "active_engagement", None) or {}
    if path is None or not path.exists():
        return {"available": False, "name": eng.get("name", ""), "path": str(path or ""), "markdown": ""}

    try:
        markdown = path.read_text()
    except OSError:
        markdown = ""
    return {"available": True, "name": eng.get("name", ""), "path": str(path), "markdown": markdown}


def generate_engagement_report(engagement_mgr: Any) -> dict[str, Any]:
    """Generate (or regenerate) the report — writes report.md and delivers to
    Discord, per EngagementManager.generate_report. Explicit operator action."""
    if engagement_mgr is None:
        raise RuntimeError("engagement manager is not loaded")
    eng = getattr(engagement_mgr, "active_engagement", None)
    if not eng:
        raise ValueError("no active engagement")

    markdown = engagement_mgr.generate_report()
    path = _report_path(engagement_mgr)
    return {"available": True, "name": eng.get("name", ""), "path": str(path or ""), "markdown": markdown}
