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
            }
            for f in reversed(findings[-100:])
        ],
    }
