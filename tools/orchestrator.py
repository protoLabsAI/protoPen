"""Engagement orchestrator — automated end-to-end pen test pipeline.

Chains: engagement setup → opsec pre-flight → recon playbook
     → finding scoring → attack suggestion generation → report → cleanup.

The agent reads the structured output to decide which high-value findings
warrant deeper autonomous investigation (manual or via probe_finding).

Usage (from agent):
    orchestrator run name="web_audit" scope="app.example.com" targets="app.example.com" mode="active"

    # After reviewing scored_findings, probe a specific finding:
    orchestrator probe_finding finding_id="a3f9c12b1e4d"
"""
from __future__ import annotations

import json
import logging
from typing import Any, Callable, Awaitable

from tools._tool_base import Tool

logger = logging.getLogger(__name__)

DispatchFn = Callable[[str, str, dict], Awaitable[str]]


class EngagementOrchestratorTool(Tool):
    """Automated engagement orchestrator — scripted pipeline with agent hand-off."""

    def __init__(
        self,
        engagement_mgr=None,
        dispatch_fn: DispatchFn | None = None,
    ):
        self._engagement = engagement_mgr
        self._dispatch   = dispatch_fn
        # Per-session state — populated by `run`, consumed by `probe_finding`
        self._session: dict = {}

    @property
    def name(self) -> str:
        return "orchestrator"

    @property
    def description(self) -> str:
        return (
            "Automated engagement orchestrator — runs the full scripted pen test pipeline "
            "(opsec pre-flight → recon playbook → finding scoring → attack suggestion → "
            "report generation) and hands off a prioritized finding list + attack suggestions "
            "to the agent for deeper autonomous probing.\n\n"
            "Actions:\n"
            "  run           — Start a full automated assessment\n"
            "  probe_finding — Run targeted probes against a specific scored finding\n"
            "  status        — Current pipeline state\n\n"
            "After `run` completes, review the returned 'Priority Targets' section and use "
            "`probe_finding` or direct tool calls to investigate HIGH/CRITICAL findings."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["run", "probe_finding", "status"],
                },
                "name": {
                    "type": "string",
                    "description": "Engagement name (slug, no spaces)",
                },
                "scope": {
                    "type": "string",
                    "description": "Human-readable scope — CIDR, domain, or description",
                },
                "targets": {
                    "type": "string",
                    "description": "Comma-separated targets (IPs, CIDRs, or hostnames)",
                },
                "mode": {
                    "type": "string",
                    "enum": ["passive", "active", "redteam"],
                    "description": "Assessment mode — controls which tools may run",
                },
                "scope_type": {
                    "type": "string",
                    "enum": ["web", "network", "hardware", "full"],
                    "description": "Assessment type — selects the default playbook",
                },
                "playbook": {
                    "type": "string",
                    "description": "Override playbook name (default: automated_assessment)",
                },
                "finding_id": {
                    "type": "string",
                    "description": "Finding ID (from run output) for probe_finding",
                },
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        if action == "run":
            return await self._run(kwargs)
        elif action == "probe_finding":
            return await self._probe_finding(kwargs)
        elif action == "status":
            return self._status()
        return f"Unknown action: {action}. Available: run, probe_finding, status"

    # ─────────────────────────────────────────────────────────────────────────
    # run — scripted pipeline
    # ─────────────────────────────────────────────────────────────────────────

    async def _run(self, kwargs: dict) -> str:
        from tools.finding_scorer import score_all, format_findings_summary
        from playbooks.loader import load_playbook
        from playbooks.runner import run_playbook

        name      = kwargs.get("name") or "auto_assessment"
        scope     = kwargs.get("scope", "")
        raw_tgts  = kwargs.get("targets", "") or scope
        targets   = [t.strip() for t in raw_tgts.split(",") if t.strip()]
        mode      = kwargs.get("mode", "active")
        pb_name   = kwargs.get("playbook", "automated_assessment")

        if not targets:
            return "Error: 'targets' or 'scope' is required."

        self._session = {
            "name": name,
            "scope": scope or ", ".join(targets),
            "mode": mode,
            "targets": targets,
            "phase": "init",
        }

        # 1 ── Start engagement ──────────────────────────────────────────────
        await self._call("engagement", "start", {
            "name": name, "scope": scope or ", ".join(targets), "mode": mode,
        })
        self._session["phase"] = "opsec"

        # 2 ── Opsec pre-flight ──────────────────────────────────────────────
        opsec_ok = False
        original_macs: dict[str, str] = {}  # iface -> original MAC for restore
        try:
            out = await self._call("opsec", "pre_scan_setup", {"interfaces": ["wlan0", "eth0"]})
            opsec_ok = "original" in out.lower() or "randomized" in out.lower() or "mac" in out.lower()
            # Parse "  iface: AA:BB:CC:DD:EE:FF → 11:22:33:44:55:66 ✓" lines
            import re as _re
            _MAC = r'[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}'
            for m in _re.finditer(rf'(\w+):\s+({_MAC})\s+[→>]\s+{_MAC}', out):
                original_macs[m.group(1)] = m.group(2)
            logger.info("Opsec pre-flight: %s (saved %d original MACs)", out[:80], len(original_macs))
        except Exception as e:
            logger.warning("Opsec pre-flight skipped: %s", e)

        # 3 ── Run recon playbook per target (max 3) ─────────────────────────
        self._session["phase"] = "recon"
        await self._call("engagement", "transition_phase", {"phase": "recon"})

        step_outputs: list[dict] = []
        for target in targets[:3]:
            try:
                pb = load_playbook(pb_name, {"target": target})
                result = await run_playbook(
                    pb,
                    self._dispatch_wrap,
                    engagement_mgr=self._engagement,
                )
                for step in result.steps:
                    step_outputs.append({
                        "step": step.name,
                        "tool": step.tool,
                        "target": target,
                        "status": step.status.value,
                        "output_len": len(step.output),
                    })
            except FileNotFoundError:
                logger.warning("Playbook '%s' not found — falling back to direct nmap + nuclei", pb_name)
                for tool, act, params in [
                    ("blackarch", "nmap_scan", {
                        "target": target,
                        "flags": "-sV -sC -T2 --spoof-mac 0 --randomize-hosts --data-length 25",
                    }),
                    ("vuln_scan", "nuclei_scan", {
                        "target": target, "severity": "medium,high,critical",
                    }),
                ]:
                    try:
                        out = await self._call(tool, act, params)
                        step_outputs.append({"step": act, "tool": tool, "target": target,
                                             "status": "completed", "output_len": len(out)})
                    except Exception as e:
                        step_outputs.append({"step": act, "tool": tool, "target": target,
                                             "status": "failed", "error": str(e)})

        # 4 ── Score and prioritize findings ─────────────────────────────────
        self._session["phase"] = "analysis"
        raw_findings: list[dict] = []
        if self._engagement and hasattr(self._engagement, "findings"):
            raw_findings = list(self._engagement.findings)

        scored = score_all(raw_findings, mode)
        self._session["scored"] = [f.to_dict() for f in scored]

        # 5 ── Transition to reporting ────────────────────────────────────────
        self._session["phase"] = "reporting"
        await self._call("engagement", "transition_phase", {"phase": "reporting"})
        report_out = await self._call("engagement", "generate_report", {})
        workspace  = (self._engagement.active_engagement or {}).get("workspace", "")
        report_path = f"{workspace}/report.md" if workspace else "(in-memory)"

        # 6 ── Opsec cleanup ─────────────────────────────────────────────────
        if opsec_ok and original_macs:
            for iface, orig_mac in original_macs.items():
                try:
                    await self._call("opsec", "mac_restore", {
                        "interface": iface, "original_mac": orig_mac,
                    })
                except Exception as e:
                    logger.warning("MAC restore failed for %s: %s", iface, e)

        # 7 ── End engagement ─────────────────────────────────────────────────
        await self._call("engagement", "end", {})
        self._session["phase"] = "done"

        # 8 ── Return structured hand-off for the agent ───────────────────────
        return self._format_handoff(scored, step_outputs, report_path)

    # ─────────────────────────────────────────────────────────────────────────
    # probe_finding — targeted follow-up on a specific finding
    # ─────────────────────────────────────────────────────────────────────────

    async def _probe_finding(self, kwargs: dict) -> str:
        fid = kwargs.get("finding_id", "")
        if not fid:
            return "Error: finding_id required"

        scored_dicts = self._session.get("scored", [])
        finding = next((f for f in scored_dicts if f.get("id") == fid), None)
        if not finding:
            return (
                f"Finding '{fid}' not found in current session. "
                f"Run `orchestrator run` first, or check the finding ID from the run output."
            )

        suggestions = finding.get("suggestions", [])[:3]
        if not suggestions:
            return f"No attack suggestions available for finding {fid}."

        results: list[str] = [
            f"## Targeted Probe: {finding['title']} (id={fid})",
            f"Severity: {finding['severity'].upper()} | Score: {finding['score']}",
            "",
        ]
        for s in suggestions:
            results.append(f"### {s['tool']} {s['action']}")
            results.append(f"_{s['description']}_")
            try:
                out = await self._call(s["tool"], s["action"], s["params"])
                results.append(out[:800])
            except Exception as e:
                results.append(f"**Error:** {e}")
            results.append("")

        return "\n".join(results)

    # ─────────────────────────────────────────────────────────────────────────
    # status
    # ─────────────────────────────────────────────────────────────────────────

    def _status(self) -> str:
        if not self._session:
            return "No active orchestration session. Run `orchestrator run` to start."
        snapshot = {
            k: v for k, v in self._session.items()
            if k not in ("scored",)
        }
        snapshot["findings_scored"] = len(self._session.get("scored", []))
        return json.dumps(snapshot, indent=2)

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    async def _call(self, tool: str, action: str, params: dict) -> str:
        if self._dispatch is None:
            return f"[orchestrator] No dispatcher — skipping {tool}.{action}"
        try:
            return await self._dispatch(tool, action, params)
        except Exception as e:
            logger.warning("Dispatch %s.%s failed: %s", tool, action, e)
            return f"[error] {tool}.{action}: {e}"

    async def _dispatch_wrap(self, tool: str, action: str, params: dict) -> str:
        """Playbook runner dispatch signature adapter."""
        return await self._call(tool, action, params)

    def _format_handoff(
        self,
        scored: list,
        step_outputs: list[dict],
        report_path: str,
    ) -> str:
        from collections import Counter
        from tools.finding_scorer import format_findings_summary

        counts = Counter(f.severity for f in scored)
        steps_done    = sum(1 for s in step_outputs if s.get("status") == "completed")
        steps_failed  = sum(1 for s in step_outputs if s.get("status") == "failed")

        lines = [
            "## Automated Assessment Complete",
            "",
            f"Playbook steps: {steps_done} completed, {steps_failed} failed",
            f"Report: {report_path}",
            "",
            format_findings_summary(scored),
            "",
            "---",
            "## Agent Instructions",
            "",
            "The scripted pipeline is done. Your job is the follow-up:",
            "",
            "1. **Review** the Priority Targets above — focus on CRITICAL and HIGH",
            "2. **Probe deeper** with `orchestrator probe_finding finding_id=<id>`",
            "   or call the suggested tools directly",
            "3. **Log new findings** via `engagement log_finding`",
            "4. **Request manual testing** if the user has specified specific objectives",
            "",
            "For each finding, the suggestions give you concrete next tool calls.",
            "Start with score ≥ 80 findings first.",
        ]
        return "\n".join(lines)
