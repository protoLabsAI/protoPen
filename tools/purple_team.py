"""Purple team mode — correlate red-team attacks with blue-team detections."""
from __future__ import annotations

import json
import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


# MITRE ATT&CK tactic → common technique mapping for coverage analysis
MITRE_TACTICS: dict[str, list[dict[str, str]]] = {
    "initial_access": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1566", "name": "Phishing"},
        {"id": "T1078", "name": "Valid Accounts"},
    ],
    "execution": [
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
        {"id": "T1053", "name": "Scheduled Task/Job"},
    ],
    "persistence": [
        {"id": "T1098", "name": "Account Manipulation"},
        {"id": "T1136", "name": "Create Account"},
        {"id": "T1053", "name": "Scheduled Task/Job"},
    ],
    "privilege_escalation": [
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    ],
    "defense_evasion": [
        {"id": "T1070", "name": "Indicator Removal"},
        {"id": "T1036", "name": "Masquerading"},
    ],
    "credential_access": [
        {"id": "T1110", "name": "Brute Force"},
        {"id": "T1003", "name": "OS Credential Dumping"},
    ],
    "discovery": [
        {"id": "T1046", "name": "Network Service Discovery"},
        {"id": "T1087", "name": "Account Discovery"},
    ],
    "lateral_movement": [
        {"id": "T1021", "name": "Remote Services"},
        {"id": "T1080", "name": "Taint Shared Content"},
    ],
    "collection": [
        {"id": "T1005", "name": "Data from Local System"},
        {"id": "T1039", "name": "Data from Network Shared Drive"},
    ],
    "exfiltration": [
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
    ],
    "impact": [
        {"id": "T1486", "name": "Data Encrypted for Impact"},
        {"id": "T1489", "name": "Service Stop"},
    ],
}


class PurpleTeamTool(BasePentestTool):
    """Purple team — correlate attacks with detections, measure coverage gaps."""

    name = "purple_team"
    description = (
        "Purple team mode — red→blue attack/detect cycle, detection gap measurement, "
        "MITRE ATT&CK coverage matrix, combined assessment reports."
    )

    # This tool is primarily computational (no subprocess commands).
    ACTIONS: dict[str, dict[str, Any]] = {
        "coverage_matrix": {
            "cmd": [],
            "timeout": 5,
            "description": "Generate MITRE ATT&CK coverage matrix from red/blue results",
        },
        "detection_gap": {
            "cmd": [],
            "timeout": 5,
            "description": "Identify detection gaps — attacks that succeeded without alerts",
        },
        "exercise_report": {
            "cmd": [],
            "timeout": 5,
            "description": "Generate combined purple team exercise report",
        },
    }

    async def execute(
        self,
        action: str,
        red_results: str = "[]",
        blue_results: str = "[]",
        exercise_name: str = "Purple Team Exercise",
        target_scope: str = "",
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        try:
            red = json.loads(red_results) if red_results else []
            blue = json.loads(blue_results) if blue_results else []
        except json.JSONDecodeError as exc:
            return json.dumps({"error": f"Invalid JSON input: {exc}"})

        if action == "coverage_matrix":
            return self._coverage_matrix(red, blue)
        elif action == "detection_gap":
            return self._detection_gap(red, blue)
        elif action == "exercise_report":
            return self._exercise_report(exercise_name, target_scope, red, blue)
        return json.dumps({"error": "Unknown action"})

    # ------------------------------------------------------------------

    def _coverage_matrix(
        self,
        red_results: list[dict],
        blue_results: list[dict],
    ) -> str:
        """Build a MITRE ATT&CK–aligned coverage matrix."""
        attacked_techniques: set[str] = set()
        detected_techniques: set[str] = set()

        for r in red_results:
            tid = r.get("technique_id") or r.get("technique", "")
            if tid:
                attacked_techniques.add(tid)

        for b in blue_results:
            tid = b.get("technique_id") or b.get("technique", "")
            if tid and b.get("detected"):
                detected_techniques.add(tid)

        matrix: dict[str, list[dict]] = {}
        for tactic, techniques in MITRE_TACTICS.items():
            rows = []
            for t in techniques:
                tid = t["id"]
                status = "not_tested"
                if tid in attacked_techniques and tid in detected_techniques:
                    status = "detected"
                elif tid in attacked_techniques:
                    status = "gap"
                rows.append({**t, "status": status})
            matrix[tactic] = rows

        total_tested = len(attacked_techniques)
        total_detected = len(attacked_techniques & detected_techniques)
        gaps = attacked_techniques - detected_techniques

        return json.dumps({
            "matrix": matrix,
            "summary": {
                "techniques_tested": total_tested,
                "techniques_detected": total_detected,
                "detection_rate": round(total_detected / max(total_tested, 1) * 100, 1),
                "gaps": sorted(gaps),
            },
        }, indent=2)

    def _detection_gap(
        self,
        red_results: list[dict],
        blue_results: list[dict],
    ) -> str:
        """Identify attacks that succeeded without corresponding detections."""
        detected_set: set[str] = set()
        for b in blue_results:
            tid = b.get("technique_id") or b.get("technique", "")
            if tid and b.get("detected"):
                detected_set.add(tid)

        gaps: list[dict] = []
        for r in red_results:
            tid = r.get("technique_id") or r.get("technique", "")
            if tid and tid not in detected_set:
                severity = "critical" if r.get("success") else "high"
                gaps.append({
                    "technique_id": tid,
                    "technique_name": r.get("technique_name", ""),
                    "attack_succeeded": r.get("success", False),
                    "severity": severity,
                    "recommendation": (
                        f"Add detection for {tid}: deploy log rule / "
                        "SIEM alert covering this technique"
                    ),
                })

        return json.dumps({
            "total_attacks": len(red_results),
            "detected": len(detected_set),
            "gaps": gaps,
            "gap_count": len(gaps),
        }, indent=2)

    def _exercise_report(
        self,
        exercise_name: str,
        target_scope: str,
        red_results: list[dict],
        blue_results: list[dict],
    ) -> str:
        """Generate a combined purple-team exercise summary report."""
        matrix = json.loads(self._coverage_matrix(red_results, blue_results))
        gap_analysis = json.loads(self._detection_gap(red_results, blue_results))

        critical_gaps = [g for g in gap_analysis["gaps"] if g["severity"] == "critical"]
        high_gaps = [g for g in gap_analysis["gaps"] if g["severity"] == "high"]

        overall_score = matrix["summary"]["detection_rate"]
        if overall_score >= 80:
            rating = "GOOD"
        elif overall_score >= 50:
            rating = "NEEDS IMPROVEMENT"
        else:
            rating = "CRITICAL — significant gaps"

        return json.dumps({
            "exercise": exercise_name,
            "scope": target_scope,
            "rating": rating,
            "detection_rate_pct": overall_score,
            "summary": {
                "attacks_executed": len(red_results),
                "detections_fired": len(blue_results),
                "critical_gaps": len(critical_gaps),
                "high_gaps": len(high_gaps),
            },
            "critical_findings": critical_gaps[:10],
            "high_findings": high_gaps[:10],
            "coverage_matrix": matrix["matrix"],
            "recommendations": [
                g["recommendation"] for g in gap_analysis["gaps"][:15]
            ],
        }, indent=2)
