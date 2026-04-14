"""Engagement manager — mission control for pen testing operations.

Handles engagement lifecycle (start/end), mode enforcement (passive/active/redteam),
finding logging, markdown report generation, and Discord delivery.

Discord delivery model:
  ONE message per engagement, sent only when generate_report() is called.
  Payload: summary embed (severity breakdown + top findings) + full report.md attachment.
  No intermediate alerts — all findings are captured in the final report.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections import Counter
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Optional

import httpx

from tools._tool_base import Tool

logger = logging.getLogger(__name__)


class EngagementMode(IntEnum):
    PASSIVE = 0
    ACTIVE = 1
    REDTEAM = 2


class EngagementManager(Tool):
    """Manages pen testing engagements — mode enforcement, logging, reporting."""

    def __init__(self, config: dict):
        self._config = config
        self._mode = EngagementMode[config["engagement"].get("default_mode", "passive").upper()]
        self._tool_risk: dict[str, int] = config.get("tool_risk", {})
        self._workspace_root = Path(config["engagement"]["workspace_dir"])
        self._webhook_url = os.environ.get("DISCORD_WEBHOOK_URL", "") or config["engagement"].get("alert_webhook", "")
        self.active_engagement: Optional[dict] = None
        self.findings: list[dict] = []
        self.target_store = None
        self.current_phase: str = ""

    _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b")

    @property
    def name(self) -> str:
        return "engagement"

    @property
    def description(self) -> str:
        return (
            "Manage pen testing engagements. Start/end engagements with defined scope. "
            "Set operation mode (passive/active/redteam) which controls what tools are permitted. "
            "Log findings with severity ratings. Generate markdown report — delivers one "
            "Discord message with a summary embed and full report attachment."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": [
                        "start",
                        "end",
                        "set_mode",
                        "status",
                        "log_finding",
                        "check_permission",
                        "generate_report",
                        "list_findings",
                        "transition_phase",
                    ],
                },
                "name": {"type": "string", "description": "Engagement name"},
                "scope": {"type": "string", "description": "Target scope (CIDR, domain, etc.)"},
                "mode": {"type": "string", "enum": ["passive", "active", "redteam"]},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "category": {"type": "string", "description": "Finding category"},
                "title": {"type": "string", "description": "Finding title"},
                "detail": {"type": "string", "description": "Finding detail"},
                "tool_name": {"type": "string", "description": "Tool name for permission check"},
                "phase": {"type": "string", "description": "Engagement phase (recon, scan, exploit, report)"},
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        dispatch = {
            "start": lambda: self._exec_start(kwargs),
            "end": lambda: self._exec_end(),
            "set_mode": lambda: self._exec_set_mode(kwargs),
            "status": lambda: self._exec_status(),
            "log_finding": lambda: self._exec_log_finding(kwargs),
            "check_permission": lambda: self._exec_check_permission(kwargs),
            "generate_report": lambda: self._exec_generate_report(),
            "list_findings": lambda: self._exec_list_findings(),
            "transition_phase": lambda: self._exec_transition_phase(kwargs),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            return fn()
        except Exception as exc:
            return f"Engagement error ({action}): {exc}"

    @property
    def mode(self) -> EngagementMode:
        return self._mode

    def set_mode(self, mode: EngagementMode):
        self._mode = mode
        logger.info("Engagement mode set to: %s", mode.name)

    def is_allowed(self, tool_name: str) -> bool:
        risk = self._tool_risk.get(tool_name, 0)
        return risk <= self._mode.value

    def start(self, name: str, scope: str = "", mode: str = None):
        ws = self._workspace_root / name
        ws.mkdir(parents=True, exist_ok=True)
        if mode:
            self._mode = EngagementMode[mode.upper()]
        self.active_engagement = {
            "name": name,
            "scope": scope,
            "mode": self._mode.name,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "workspace": str(ws),
        }
        self.findings = []
        self.current_phase = ""
        (ws / "engagement.json").write_text(json.dumps(self.active_engagement, indent=2))
        logger.info("Engagement '%s' started — scope: %s, mode: %s", name, scope, self._mode.name)

    def end(self):
        if self.active_engagement:
            self.active_engagement["ended_at"] = datetime.now(timezone.utc).isoformat()
            ws = Path(self.active_engagement["workspace"])
            (ws / "engagement.json").write_text(json.dumps(self.active_engagement, indent=2))
            if self.findings:
                (ws / "findings.json").write_text(json.dumps(self.findings, indent=2))
            logger.info("Engagement '%s' ended", self.active_engagement["name"])
        self.active_engagement = None
        self.findings = []

    def log_finding(self, severity: str, category: str, title: str, detail: str):
        finding = {
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": self._mode.name,
        }
        self.findings.append(finding)
        logger.info("[%s] %s: %s", severity.upper(), category, title)
        self._auto_upsert_targets(detail)

    def _auto_upsert_targets(self, detail: str):
        """Extract IPs and MACs from finding detail and upsert into target store."""
        if self.target_store is None:
            return
        try:
            ips = self._IP_RE.findall(detail)
            macs = self._MAC_RE.findall(detail)
            for ip in ips:
                self.target_store.upsert_host(ip=ip)
            for mac in macs:
                self.target_store.upsert_host(mac=mac)
        except Exception as exc:
            logger.warning("Auto-upsert failed: %s", exc)

    def transition_phase(self, new_phase: str):
        """Advance the engagement phase (no Discord side effects)."""
        old_phase = self.current_phase or "(start)"
        self.current_phase = new_phase
        logger.info("Engagement phase: %s -> %s", old_phase, new_phase)

    def _send_report_to_discord(self, report: str, eng: dict):
        """Post one summary embed + full report.md attachment.

        This is the ONLY Discord message sent per engagement.
        """
        if not self._webhook_url:
            return

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        severity_counts = Counter(f["severity"] for f in self.findings)

        # Top findings for embed (critical first, then high)
        top = sorted(
            (f for f in self.findings if f["severity"] in ("critical", "high")),
            key=lambda f: severity_order.get(f["severity"], 5),
        )[:8]

        # Severity breakdown line
        breakdown = (
            f"🔴 Critical: **{severity_counts.get('critical', 0)}**  "
            f"🟠 High: **{severity_counts.get('high', 0)}**  "
            f"🟡 Medium: **{severity_counts.get('medium', 0)}**  "
            f"🟢 Low: **{severity_counts.get('low', 0)}**  "
            f"ℹ️ Info: **{severity_counts.get('info', 0)}**"
        )

        # Top findings block
        if top:
            findings_block = "\n".join(
                f"`{i}.` **[{f['severity'].upper()}]** {f['title']} `{f['category']}`" for i, f in enumerate(top, 1)
            )
        else:
            findings_block = "_No critical or high findings._"

        # Overall risk colour + label
        if severity_counts.get("critical", 0):
            color, risk = 0xEF4444, "CRITICAL"
        elif severity_counts.get("high", 0):
            color, risk = 0xF97316, "HIGH"
        elif severity_counts.get("medium", 0):
            color, risk = 0xEAB308, "MEDIUM"
        else:
            color, risk = 0x22C55E, "LOW / INFORMATIONAL"

        total = len(self.findings)
        description = (
            f"**Scope:** {eng.get('scope', 'N/A')}\n"
            f"**Mode:** {eng.get('mode', 'N/A')}\n"
            f"**Started:** {eng.get('started_at', 'N/A')[:19].replace('T', ' ')} UTC\n\n"
            f"**Severity Breakdown** ({total} total findings)\n"
            f"{breakdown}\n\n"
            f"**Top Findings**\n"
            f"{findings_block}\n\n"
            f"_Full report attached._"
        )

        embed = {
            "title": f"🔐 Pen Test Report — {eng['name']}",
            "description": description,
            "color": color,
            "footer": {
                "text": f"Overall Risk: {risk}  •  protoPen  •  {eng.get('started_at', '')[:10]}",
            },
        }

        payload_json = json.dumps({"embeds": [embed]})
        filename = f"{eng['name']}-report.md"

        try:
            httpx.post(
                self._webhook_url,
                data={"payload_json": payload_json},
                files={"file": (filename, report.encode("utf-8"), "text/markdown")},
                timeout=10,
            )
            logger.info("Report delivered to Discord: %s", filename)
        except Exception as exc:
            logger.warning("Failed to send report to Discord: %s", exc)

    def generate_report(self) -> str:
        """Generate the markdown report, save it, and deliver once to Discord."""
        if not self.active_engagement:
            return "No active engagement"
        eng = self.active_engagement

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f["severity"], 5))
        severity_counts = Counter(f["severity"] for f in self.findings)

        # ── Executive summary ─────────────────────────────────────────────────
        total = len(self.findings)
        risk_label = (
            "CRITICAL"
            if severity_counts.get("critical", 0)
            else "HIGH"
            if severity_counts.get("high", 0)
            else "MEDIUM"
            if severity_counts.get("medium", 0)
            else "LOW / INFORMATIONAL"
        )
        started = eng.get("started_at", "N/A")[:19].replace("T", " ")
        ended = datetime.now(timezone.utc).isoformat()[:19].replace("T", " ")

        lines = [
            f"# Pen Test Report: {eng['name']}",
            "",
            "## Engagement Details",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| **Scope** | {eng.get('scope', 'N/A')} |",
            f"| **Mode** | {eng.get('mode', 'N/A')} |",
            f"| **Started** | {started} UTC |",
            f"| **Completed** | {ended} UTC |",
            f"| **Overall Risk** | **{risk_label}** |",
            "",
            "## Severity Summary",
            "",
            "| Severity | Count |",
            "|---|---|",
            f"| 🔴 Critical | {severity_counts.get('critical', 0)} |",
            f"| 🟠 High | {severity_counts.get('high', 0)} |",
            f"| 🟡 Medium | {severity_counts.get('medium', 0)} |",
            f"| 🟢 Low | {severity_counts.get('low', 0)} |",
            f"| ℹ️ Info | {severity_counts.get('info', 0)} |",
            f"| **Total** | **{total}** |",
            "",
        ]

        # ── Findings by severity ──────────────────────────────────────────────
        lines += ["## Findings", ""]
        if not sorted_findings:
            lines += ["_No findings recorded._", ""]
        else:
            for f in sorted_findings:
                sev_upper = f["severity"].upper()
                ts = f.get("timestamp", "")[:19].replace("T", " ")
                lines += [
                    f"### [{sev_upper}] {f['title']}",
                    "",
                    f"- **Category:** {f['category']}",
                    f"- **Mode at time:** {f.get('mode', 'N/A')}",
                    f"- **Logged:** {ts} UTC",
                    "",
                    f"{f['detail']}",
                    "",
                    "---",
                    "",
                ]

        # ── Remediation priorities (critical + high only) ─────────────────────
        priority = [f for f in sorted_findings if f["severity"] in ("critical", "high")]
        if priority:
            lines += ["## Remediation Priorities", ""]
            for i, f in enumerate(priority[:10], 1):
                lines.append(f"{i}. **[{f['severity'].upper()}]** {f['title']} — _{f['category']}_")
            lines += ["", "_Full details for each finding are in the Findings section above._", ""]

        report = "\n".join(lines)

        # Write to disk
        ws = Path(eng["workspace"])
        (ws / "report.md").write_text(report)
        logger.info("Report written to %s/report.md (%d findings)", ws, total)

        # One Discord delivery
        self._send_report_to_discord(report, eng)

        return report

    def _exec_start(self, kwargs) -> str:
        self.start(kwargs.get("name", "unnamed"), kwargs.get("scope", ""), kwargs.get("mode"))
        return (
            f"Engagement '{kwargs.get('name')}' started in {self._mode.name} mode\n\n"
            f"[OPSEC REQUIRED] Before any scanning, run:\n"
            f"  opsec pre_scan_setup — pass the list of active interfaces to randomize MACs\n"
            f"Save the original MACs from the output. Restore them with opsec mac_restore before ending the engagement."
        )

    def _exec_end(self) -> str:
        name = self.active_engagement["name"] if self.active_engagement else "none"
        self.end()
        return f"Engagement '{name}' ended"

    def _exec_set_mode(self, kwargs) -> str:
        mode_str = kwargs.get("mode", "passive")
        self.set_mode(EngagementMode[mode_str.upper()])
        return f"Mode set to {self._mode.name}"

    def _exec_status(self) -> str:
        if not self.active_engagement:
            return "No active engagement"
        eng = self.active_engagement
        return (
            f"Engagement: {eng['name']}\n"
            f"Scope: {eng.get('scope', 'N/A')}\n"
            f"Mode: {self._mode.name}\n"
            f"Findings: {len(self.findings)}\n"
            f"Started: {eng['started_at']}"
        )

    def _exec_log_finding(self, kwargs) -> str:
        self.log_finding(
            kwargs.get("severity", "info"),
            kwargs.get("category", "general"),
            kwargs.get("title", ""),
            kwargs.get("detail", ""),
        )
        return f"Finding logged: [{kwargs.get('severity', 'info').upper()}] {kwargs.get('title', '')}"

    def _exec_check_permission(self, kwargs) -> str:
        tool_name = kwargs.get("tool_name", "")
        allowed = self.is_allowed(tool_name)
        risk = self._tool_risk.get(tool_name, 0)
        return (
            f"{'Allowed' if allowed else 'Denied'}: {tool_name} "
            f"(risk={risk}, mode={self._mode.name}={self._mode.value})"
        )

    def _exec_transition_phase(self, kwargs) -> str:
        phase = kwargs.get("phase", "")
        if not phase:
            return "Error: 'phase' is required for transition_phase"
        if not self.active_engagement:
            return "No active engagement"
        old = self.current_phase or "(start)"
        self.transition_phase(phase)
        return f"Phase transition: {old} -> {phase}"

    def _exec_generate_report(self) -> str:
        return self.generate_report()

    def _exec_list_findings(self) -> str:
        if not self.findings:
            return "No findings recorded"
        lines = []
        for i, f in enumerate(self.findings):
            lines.append(f"{i + 1}. [{f['severity'].upper()}] {f['category']}: {f['title']}")
        return "\n".join(lines)
