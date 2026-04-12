"""Engagement manager — mission control for pen testing operations.

Handles engagement lifecycle (start/end), mode enforcement (passive/active/redteam),
finding logging, markdown report generation, and Discord alerts.
"""
from __future__ import annotations

import json
import logging
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
        if severity in ("critical", "high") and self._webhook_url:
            self._send_alert(finding)

    def _send_alert(self, finding: dict):
        emoji = {"critical": "\U0001f534", "high": "\U0001f7e0"}.get(finding["severity"], "\u26aa")
        content = (
            f"{emoji} **{finding['severity'].upper()}** — {finding['title']}\n"
            f"Category: {finding['category']}\n"
            f"```\n{finding['detail']}\n```"
        )
        try:
            httpx.post(self._webhook_url, json={"content": content}, timeout=5)
        except Exception as exc:
            logger.warning("Failed to send Discord alert: %s", exc)

    def generate_report(self) -> str:
        if not self.active_engagement:
            return "No active engagement"
        eng = self.active_engagement
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
            emoji = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1",
                     "low": "\U0001f535", "info": "\u26aa"}.get(f["severity"], "\u26aa")
            lines.append(f"### {emoji} [{f['severity'].upper()}] {f['title']}")
            lines.append(f"**Category:** {f['category']}  ")
            lines.append(f"**Time:** {f['timestamp']}  ")
            lines.append(f"\n{f['detail']}\n")
        report = "\n".join(lines)
        ws = Path(eng["workspace"])
        (ws / "report.md").write_text(report)
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

    def _exec_generate_report(self) -> str:
        return self.generate_report()

    def _exec_list_findings(self) -> str:
        if not self.findings:
            return "No findings recorded"
        lines = []
        for i, f in enumerate(self.findings):
            lines.append(f"{i+1}. [{f['severity'].upper()}] {f['category']}: {f['title']}")
        return "\n".join(lines)
