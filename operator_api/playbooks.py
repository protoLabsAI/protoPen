"""Playbook browse + manual run for the operator console (Phase 1 + 2).

protoPen ships 23 declarative playbooks (``playbooks/library/*.yaml`` — ordered
tool-chains, no LLM). The agent reaches them via the ``playbook`` tool; this
exposes the same library to the operator: list them with mode/variables/steps,
and fire one manually. The run reuses the *exact* dispatch + runner the agent's
tool uses (``dispatch_pentest_tool`` + ``run_playbook``), so step semantics stay
identical.

Phase 2 — the safety gate. A playbook's mode is the max tool risk across its
steps (0 passive · 1 active · 2 redteam, from engagement-config ``tool_risk``).
Passive playbooks fire freely; active/redteam require an **active engagement**
whose mode permits them and whose **scope covers the targets** (else HTTP 409).
Every manual fire is recorded in the audit log tagged ``source=operator_manual``.
Operator-key-gated at the route layer like the rest of the console.
"""

from __future__ import annotations

import json
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

_RISK_MODE = {0: "passive", 1: "active", 2: "redteam"}
_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "engagement-config.json"


class PlaybookGateError(Exception):
    """Manual fire blocked by the engagement/scope gate → HTTP 409."""

    status_code = 409


@lru_cache(maxsize=1)
def _tool_risk() -> dict[str, int]:
    """tool_name → risk level (0/1/2), read from engagement-config.json."""
    try:
        data = json.loads(_CONFIG_PATH.read_text())
        return {str(k): int(v) for k, v in (data.get("tool_risk") or {}).items()}
    except (OSError, ValueError):
        return {}


# Clearly-offensive playbook tags set a mode floor, in case a step's action
# isn't in the risk map. (Risk is keyed by *action*; ambiguous tags like
# "active"/"scan"/"vuln" are left to the precise per-action risk.)
_TAG_FLOOR = {
    "redteam": 2,
    "post-exploitation": 2,
    "persistence": 2,
    "exfil": 2,
    "lateral-movement": 2,
    "attack": 1,
    "exploit": 1,
}


def _playbook_risk(steps, tags=()) -> int:
    """Required mode for a playbook, 0 passive · 1 active · 2 redteam.

    Max over steps of the per-action risk (``tool_risk`` is keyed by action, with
    the tool name as a fallback), floored by any clearly-offensive tag, clamped to
    redteam — so REDTEAM mode permits the highest-risk tools (mirrors
    EngagementManager.is_allowed: permitted iff risk <= mode.value)."""
    risk = _tool_risk()

    def _step_risk(s) -> int:
        action = getattr(s, "action", s.get("action", "") if isinstance(s, dict) else "")
        tool = getattr(s, "tool", s.get("tool", "") if isinstance(s, dict) else "")
        return max(risk.get(action, 0), risk.get(tool, 0))

    step_risk = max((_step_risk(s) for s in steps), default=0)
    tag_floor = max((_TAG_FLOOR.get(str(t).lower(), 0) for t in (tags or [])), default=0)
    return min(max(step_risk, tag_floor), 2)


def list_playbooks_for_console() -> dict[str, Any]:
    """List the playbook library with enough detail to render + collect inputs:
    name, description, tags, mode (computed from tool risk), whether it needs an
    engagement, declared variables (defaults), and a step preview.
    """
    from playbooks.loader import list_playbooks, load_playbook

    playbooks: list[dict[str, Any]] = []
    for summary in list_playbooks():
        name = summary.get("name", "")
        if not name:
            continue
        try:
            pb = load_playbook(name)
        except Exception:
            continue
        tags = list(pb.tags or summary.get("tags", []))
        risk = _playbook_risk(pb.steps, tags)
        playbooks.append(
            {
                "name": name,
                "description": pb.description or summary.get("description", ""),
                "tags": tags,
                "mode": _RISK_MODE.get(risk, "passive"),
                "requires_engagement": risk > 0 or bool(getattr(pb, "requires_engagement", False)),
                "variables": dict(pb.variables or {}),
                "steps": [{"name": s.name, "tool": s.tool, "action": s.action} for s in pb.steps],
            }
        )
    return {"count": len(playbooks), "playbooks": playbooks}


def _scope_config_from_string(scope: str) -> dict:
    """Best-effort scope-config from an engagement's freeform scope string.
    CIDR/IP tokens → cidr; otherwise domain (matching the host + its subdomains);
    unrecognized → ``any`` (can't enforce, so don't false-reject)."""
    import ipaddress

    tokens = [t.strip() for t in scope.replace(",", " ").split() if t.strip()]
    if not tokens:
        return {"type": "any"}
    try:
        for t in tokens:
            ipaddress.ip_network(t, strict=False)
        return {"type": "cidr", "targets": tokens}
    except ValueError:
        pass
    if all(("." in t and "/" not in t) for t in tokens):
        targets: list[str] = []
        for t in tokens:
            targets.append(t)
            if not t.startswith("*"):
                targets.append(f"*.{t}")
        return {"type": "domain", "targets": targets}
    return {"type": "any"}


def _enforce_gate(playbook, engagement_mgr) -> str:
    """Raise PlaybookGateError if this manual fire isn't permitted; return the
    playbook's mode name. Passive playbooks pass unless they self-declare
    ``requires_engagement`` (e.g. personal OSINT — passive tools, but collection
    must happen inside an authorized, scoped engagement)."""
    risk = _playbook_risk(playbook.steps, getattr(playbook, "tags", ()))
    mode_name = _RISK_MODE.get(risk, "passive")
    needs_engagement = risk > 0 or getattr(playbook, "requires_engagement", False)
    if not needs_engagement:
        return mode_name  # passive and engagement-free — always allowed

    active = getattr(engagement_mgr, "active_engagement", None) if engagement_mgr else None
    if not active:
        detail = (
            f"This playbook runs {mode_name} tools"
            if risk > 0
            else "This playbook collects OSINT on a personal/in-scope target"
        )
        raise PlaybookGateError(
            f"{detail} — start an engagement (with the target recorded in scope) before firing it from the console."
        )

    eng_mode = getattr(engagement_mgr, "mode", None)
    eng_mode_val = getattr(eng_mode, "value", 0)
    if risk > eng_mode_val:
        raise PlaybookGateError(
            f"Engagement mode {getattr(eng_mode, 'name', '?')} doesn't permit a {mode_name} playbook."
        )

    scope = (active.get("scope") or "").strip()
    if scope:
        from enforcement.scope import ScopeValidator

        validator = ScopeValidator(_scope_config_from_string(scope))
        for step in playbook.steps:
            # extract_target is keyed by action (same call the agent's enforcement
            # middleware makes), not the tool name.
            target = validator.extract_target(step.action, step.params)
            if target and not validator.is_in_scope(target):
                raise PlaybookGateError(
                    f"Target {target!r} (step '{step.name}') is outside the engagement scope: {scope}"
                )
    return mode_name


async def run_manual_playbook(name: str, variables: dict[str, str] | None = None) -> dict[str, Any]:
    """Load + gate + run a playbook by name, returning its ``to_dict()`` result.

    Raises ValueError for an unknown playbook (→ 400) and PlaybookGateError when
    the engagement/scope gate blocks an offensive fire (→ 409). Reuses the agent's
    dispatch + runner so the manual run behaves identically to the agent firing the
    same playbook; records the fire in the audit log (source=operator_manual).
    """
    cleaned = (name or "").strip()
    if not cleaned:
        raise ValueError("playbook name is required")

    from playbooks.loader import load_playbook

    try:
        playbook = load_playbook(cleaned, variables or {})
    except FileNotFoundError as exc:
        raise ValueError(f"playbook not found: {cleaned}") from exc

    from playbooks.runner import run_playbook
    from tools.lg_tools import dispatch_pentest_tool, get_engagement_manager

    try:
        engagement_mgr = get_engagement_manager()
    except Exception:
        engagement_mgr = None

    mode_name = _enforce_gate(playbook, engagement_mgr)  # raises PlaybookGateError if blocked

    started = time.monotonic()
    result = await run_playbook(playbook, dispatch_pentest_tool, engagement_mgr=engagement_mgr)
    out = result.to_dict()

    # Audit the manual fire alongside the agent's tool calls.
    try:
        from audit import audit_logger

        audit_logger.log(
            session_id="operator-manual",
            tool=f"playbook:{cleaned}",
            args={"variables": variables or {}, "mode": mode_name, "source": "operator_manual"},
            result_summary=f"{out.get('progress', '')} {'failed' if out.get('failed') else 'ok'}".strip(),
            duration_ms=int((time.monotonic() - started) * 1000),
            success=not out.get("failed", False),
        )
    except Exception:
        pass  # audit is best-effort — never fail the run on a logging hiccup

    return out
