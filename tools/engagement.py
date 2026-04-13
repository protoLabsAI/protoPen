"""Engagement manager — mission control for pen testing operations.

Handles engagement lifecycle (start/end), mode enforcement (passive/active/redteam),
finding logging, markdown report generation, and Discord alerts.

Report delivery model (see docs/superpowers/specs/2026-04-13-report-delivery-system-design.md):
  CRITICAL  → immediate webhook (60s dedup)
  HIGH      → batched per phase transition
  MED/LOW/INFO → final report only
"""
from __future__ import annotations

import json
import logging
import re
import time
from collections import Counter
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Optional

import httpx

try:
    from nanobot.agent.tools.base import Tool
except ImportError:
    from tools._tool_base import Tool

logger = logging.getLogger(__name__)

# ── Discord message templates (consistent across all engagements) ────────────
# These are format-string constants — never LLM-generated.

_CRITICAL_ALERT_TEMPLATE = (
    "[CRITICAL] {title}\n"
    "Category: {category}\n"
    "{detail}\n"
    "— {engagement_name}"
)

_PHASE_BATCH_TEMPLATE = (
    "{count} findings\n\n"
    "{finding_lines}"
)

_REPORT_SUMMARY_TEMPLATE = (
    "Scope: {scope}\n"
    "Mode: {mode}\n\n"
    "Severity Breakdown:\n"
    "- Critical: {critical}\n"
    "- High: {high}\n"
    "- Medium: {medium}\n"
    "- Low: {low}\n"
    "- Info: {info}\n\n"
    "Top Findings:\n"
    "{top_findings}\n\n"
    "Priority Remediation:\n"
    "{remediation}"
)

_DEDUP_WINDOW_SECS = 60


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
        self._webhook_url = config["engagement"].get("alert_webhook", "")
        self.active_engagement: Optional[dict] = None
        self.findings: list[dict] = []
        self.target_store = None

        # Report delivery state
        self._alert_queue: list[dict] = []       # HIGH findings waiting for phase flush
        self._alert_dedup: dict[str, float] = {}  # title → last-alert timestamp
        self.current_phase: str = ""               # current engagement phase

    _IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    _MAC_RE = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b')

    @property
    def name(self) -> str:
        return "engagement"

    @property
    def description(self) -> str:
        return (
            "Manage pen testing engagements. Start/end engagements with defined scope. "
            "Set operation mode (passive/active/redteam) which controls what tools are permitted. "
            "Log findings with severity ratings. Generate markdown reports. "
            "Send critical/high findings to Discord as alerts."
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
                        "start", "end", "set_mode", "status",
                        "log_finding", "check_permission",
                        "generate_report", "list_findings",
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
        self._alert_queue = []
        self._alert_dedup = {}
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

        if self._webhook_url:
            if severity == "critical":
                self._send_alert(finding)
            elif severity == "high":
                self._alert_queue.append(finding)

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

    def _send_alert(self, finding: dict):
        """Immediate alert for CRITICAL findings only, with 60s title-based dedup."""
        now = time.monotonic()
        title = finding["title"]
        last_sent = self._alert_dedup.get(title, 0.0)
        if now - last_sent < _DEDUP_WINDOW_SECS:
            logger.debug("Dedup: skipping duplicate alert for '%s'", title)
            return
        self._alert_dedup[title] = now

        eng_name = self.active_engagement["name"] if self.active_engagement else "unknown"
        content = _CRITICAL_ALERT_TEMPLATE.format(
            title=title,
            category=finding["category"],
            detail=finding["detail"],
            engagement_name=eng_name,
        )
        try:
            httpx.post(self._webhook_url, json={"content": content}, timeout=5)
        except Exception as exc:
            logger.warning("Failed to send Discord alert: %s", exc)

    def transition_phase(self, new_phase: str):
        """Flush queued HIGH alerts for the completed phase, then advance."""
        old_phase = self.current_phase
        if self._alert_queue:
            self._flush_phase_alerts(old_phase or "pre-phase")
        self.current_phase = new_phase
        logger.info("Engagement phase: %s -> %s", old_phase or "(start)", new_phase)

    def _flush_phase_alerts(self, phase_name: str):
        """Post one batched embed for all queued HIGH findings, then clear the queue."""
        if not self._alert_queue or not self._webhook_url:
            return

        finding_lines = "\n".join(
            f"- [HIGH] {f['title']} ({f['category']})"
            for f in self._alert_queue
        )
        eng_name = self.active_engagement["name"] if self.active_engagement else "unknown"
        description = _PHASE_BATCH_TEMPLATE.format(
            count=len(self._alert_queue),
            finding_lines=finding_lines,
        )
        embed = {
            "title": f"Phase Complete: {phase_name}",
            "description": description,
            "color": 0xF97316,
            "footer": {"text": f"protoPen — {eng_name}"},
        }
        try:
            httpx.post(self._webhook_url, json={"embeds": [embed]}, timeout=5)
        except Exception as exc:
            logger.warning("Failed to send phase batch alert: %s", exc)

        self._alert_queue = []

    def _send_report_to_discord(self, report: str, eng: dict):
        """Post summary embed + full report file attachment to Discord."""
        if not self._webhook_url:
            return

        severity_counts = Counter(f["severity"] for f in self.findings)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        top = sorted(
            (f for f in self.findings if f["severity"] in ("critical", "high")),
            key=lambda f: severity_order.get(f["severity"], 5),
        )[:5]
        top_lines = "\n".join(
            f"{i}. [{f['severity'].upper()}] {f['title']}"
            for i, f in enumerate(top, 1)
        ) or "None"

        remediation_items = []
        for f in top[:3]:
            remediation_items.append(f"{len(remediation_items) + 1}. {f['title']}")
        remediation = "\n".join(remediation_items) or "None"

        description = _REPORT_SUMMARY_TEMPLATE.format(
            scope=eng.get("scope", "N/A"),
            mode=eng.get("mode", "N/A"),
            critical=severity_counts.get("critical", 0),
            high=severity_counts.get("high", 0),
            medium=severity_counts.get("medium", 0),
            low=severity_counts.get("low", 0),
            info=severity_counts.get("info", 0),
            top_findings=top_lines,
            remediation=remediation,
        )

        if severity_counts.get("critical", 0):
            color = 0xEF4444
            risk = "CRITICAL"
        elif severity_counts.get("high", 0):
            color = 0xF97316
            risk = "HIGH"
        else:
            color = 0xEAB308
            risk = "MEDIUM"

        embed = {
            "title": f"Pen Test Report — {eng['name']}",
            "description": description,
            "color": color,
            "footer": {
                "text": f"Assessment: {eng.get('started_at', 'N/A')[:10]} | Overall Risk: {risk} | protoPen",
            },
        }
        payload_json = json.dumps({"embeds": [embed]})
        report_bytes = report.encode("utf-8")
        filename = f"{eng['name']}-report.md"

        try:
            httpx.post(
                self._webhook_url,
                data={"payload_json": payload_json},
                files={"file": (filename, report_bytes, "text/markdown")},
                timeout=10,
            )
        except Exception as exc:
            logger.warning("Failed to send report to Discord: %s", exc)

    def generate_report(self) -> str:
        if not self.active_engagement:
            return "No active engagement"
        eng = self.active_engagement

        # Flush any remaining queued HIGH alerts before the final report
        if self._alert_queue:
            phase_label = self.current_phase or "pre-report"
            self._flush_phase_alerts(phase_label)

        lines = [
            f"# Pen Test Report: {eng['name']}",
            "",
            f"**Scope:** {eng.get('scope', 'N/A')}",
            f"**Mode:** {eng.get('mode', 'N/A')}",
            f"**Started:** {eng.get('started_at', 'N/A')}",
            "",
            "## Findings",
            "",
        ]
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f["severity"], 5))
        for f in sorted_findings:
            lines.append(f"### [{f['severity'].upper()}] {f['title']}")
            lines.append(f"**Category:** {f['category']}  ")
            lines.append(f"**Time:** {f['timestamp']}  ")
            lines.append(f"\n{f['detail']}\n")
        report = "\n".join(lines)
        ws = Path(eng["workspace"])
        (ws / "report.md").write_text(report)

        self._send_report_to_discord(report, eng)

        return report

    def _exec_start(self, kwargs) -> str:
        self.start(kwargs.get("name", "unnamed"), kwargs.get("scope", ""), kwargs.get("mode"))
        return f"Engagement '{kwargs.get('name')}' started in {self._mode.name} mode"

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
        queued = len(self._alert_queue)
        return f"Phase transition: {old} -> {phase} (queued alerts: {queued})"

    def _exec_generate_report(self) -> str:
        return self.generate_report()

    def _exec_list_findings(self) -> str:
        if not self.findings:
            return "No findings recorded"
        lines = []
        for i, f in enumerate(self.findings):
            lines.append(f"{i+1}. [{f['severity'].upper()}] {f['category']}: {f['title']}")
        return "\n".join(lines)
