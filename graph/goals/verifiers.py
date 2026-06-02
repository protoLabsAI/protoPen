"""Goal verifiers — the testable-outcome backing for goal mode.

protoPen's verifiers are **read-only and domain-backed** — they never execute
shell, keeping goal mode inside the tight no-code-exec profile (the divergence
from protoAgent, whose command/test/ci verifiers run on the host).

``spec["type"]`` selects an entry in ``VERIFIERS``:

  findings — assert over the active engagement's findings: ``severity`` (this
             level or higher), ``category`` (substring), ``min`` count. Met when
             at least ``min`` findings match. The precise, no-LLM check.
  targets  — assert over discovered hosts: ``query`` (free-text over host fields),
             ``device_type`` (substring), ``min`` count. Met when at least ``min``
             hosts match. Recon/enumeration goals ("find ≥5 live hosts").
  task     — assert over the beads task tracker: ``id`` (exact) or ``title``
             (substring) selects task(s); met when all selected reach ``status``
             (default: any done-state). With no selector, met when every tracked
             task is done ("clear the board").
  llm      — fuzzy judgment: an LLM decides if the goal's condition is met given
             the engagement state + the agent's latest message. The fallback.

All checks read existing stores only — no shell, no host execution.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass

from graph.goals.types import VerifyResult

log = logging.getLogger(__name__)

_EVIDENCE_CAP = 800
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_LLM_SYSTEM = (
    "You are a strict goal-completion evaluator. Decide whether the GOAL is met "
    "based ONLY on the evidence provided. Reply with a single JSON object: "
    '{"met": true|false, "reason": "<one sentence>"}. '
    "Be conservative — default to met:false when the evidence is insufficient."
)


@dataclass
class VerifyContext:
    config: object = None
    condition: str = ""
    last_text: str = ""
    tool_summary: str = ""


def _tail(text: str, cap: int = _EVIDENCE_CAP) -> str:
    text = text or ""
    return text if len(text) <= cap else "…" + text[-cap:]


def _engagement_manager():
    """The EngagementManager singleton, or None (lazy lg_tools import isolated)."""
    try:
        from tools.lg_tools import get_engagement_manager

        return get_engagement_manager()
    except Exception:
        return None


def _merge_findings(mgr) -> list[dict]:
    """Engagement-logged findings PLUS target-store (parser-produced) findings
    recorded since the engagement started.

    The agent logs key findings via ``engagement log_finding`` (in-memory list),
    while tool parsers persist structured findings (OSINT accounts, scan results,
    …) to the target store. Goals should see both. Scoping target-store findings
    to ``started_at`` avoids counting stale findings from prior engagements (the
    store is global; the engagement's logged list resets each engagement).
    """
    if mgr is None:
        return []
    findings = list(getattr(mgr, "findings", []) or [])

    active = getattr(mgr, "active_engagement", None)
    started = active.get("started_at", "") if isinstance(active, dict) else ""
    store = getattr(mgr, "target_store", None)
    if store is not None and started and hasattr(store, "get_findings"):
        try:
            for f in store.get_findings():
                # ISO-8601 UTC timestamps compare lexically (same format on both).
                if str(f.get("first_seen", "")) >= started:
                    findings.append(f)
        except Exception:
            pass
    return findings


def _active_findings() -> list[dict]:
    """Findings visible to a goal verifier (engagement + scoped target-store)."""
    return _merge_findings(_engagement_manager())


def _search_hosts(query: str = "") -> list[dict]:
    """Discovered hosts (empty query → most-recently-seen). Read-only TargetStore."""
    try:
        from tools.lg_tools import get_target_store

        store = get_target_store()
    except Exception:
        return []
    if store is None:
        return []
    try:
        return list(store.search_hosts(query or "", limit=500) or [])
    except Exception:
        return []


def _list_tasks() -> list[dict]:
    """Tracked beads tasks (empty if the tracker isn't wired). Read-only."""
    try:
        from tools.lg_tools import get_beads_handle

        service, project = get_beads_handle()
    except Exception:
        return []
    if service is None or not project:
        return []
    try:
        return list(service.list(project) or [])
    except Exception:
        return []


_TASK_DONE = {"closed", "done", "resolved", "completed"}


async def _verify_findings(spec: dict, ctx: VerifyContext) -> VerifyResult:
    findings = _active_findings()
    sev = str(spec.get("severity", "")).lower().strip()
    cat = str(spec.get("category", "")).lower().strip()
    minimum = max(1, int(spec.get("min", 1) or 1))
    min_rank = _SEV_RANK.get(sev, 0)

    matched = 0
    for f in findings:
        if sev and _SEV_RANK.get(str(f.get("severity", "info")).lower(), 0) < min_rank:
            continue
        if cat and cat not in str(f.get("category", "")).lower():
            continue
        matched += 1

    desc = " · ".join(p for p in [f"sev≥{sev}" if sev else "", f"category~{cat}" if cat else ""] if p) or "any"
    # Same string for reason + evidence so the controller's no-progress signature
    # tracks the *count* — when findings advance, this changes and the streak resets.
    line = f"{matched} finding(s) matching [{desc}] (need {minimum})"
    return VerifyResult(matched >= minimum, line, line)


async def _verify_targets(spec: dict, ctx: VerifyContext) -> VerifyResult:
    query = str(spec.get("query", spec.get("q", "")) or "").strip()
    device_type = str(spec.get("device_type", "")).lower().strip()
    minimum = max(1, int(spec.get("min", 1) or 1))

    hosts = await asyncio.to_thread(_search_hosts, query)
    if device_type:
        hosts = [h for h in hosts if device_type in str(h.get("device_type", "")).lower()]

    desc = (
        " · ".join(p for p in [f"q~{query}" if query else "", f"type~{device_type}" if device_type else ""] if p)
        or "any"
    )
    # reason == evidence so the controller's no-progress signature tracks the count.
    line = f"{len(hosts)} host(s) matching [{desc}] (need {minimum})"
    return VerifyResult(len(hosts) >= minimum, line, line)


async def _verify_task(spec: dict, ctx: VerifyContext) -> VerifyResult:
    task_id = str(spec.get("id", "")).strip()
    title_sub = str(spec.get("title", "")).lower().strip()
    want = str(spec.get("status", "")).lower().strip()
    done = {want} if want else _TASK_DONE

    tasks = await asyncio.to_thread(_list_tasks)
    if task_id:
        matched = [t for t in tasks if str(t.get("id", "")) == task_id]
    elif title_sub:
        matched = [t for t in tasks if title_sub in str(t.get("title", "")).lower()]
    else:
        matched = list(tasks)

    if not matched:
        sel = task_id or (f"title~{title_sub}" if title_sub else "any")
        line = f"no tracked task matching [{sel}]"
        return VerifyResult(False, line, line)

    done_ct = sum(1 for t in matched if str(t.get("status", "")).lower() in done)
    target = "/".join(sorted(done))
    line = f"{done_ct}/{len(matched)} matched task(s) at [{target}]"
    return VerifyResult(done_ct == len(matched), line, line)


async def _verify_llm(spec: dict, ctx: VerifyContext) -> VerifyResult:
    if ctx.config is None:
        return VerifyResult(False, "llm verifier unavailable (no config)", "")
    try:
        from langchain_core.messages import HumanMessage, SystemMessage

        from graph.agent import _resolve_aux_model
        from graph.llm import create_llm

        # Verification is classification, not the main task → aux/fast model.
        llm = create_llm(ctx.config, model_name=_resolve_aux_model(ctx.config))

        findings = _active_findings()
        sev_counts: dict[str, int] = {}
        for f in findings:
            s = str(f.get("severity", "info")).lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        eng = f"{len(findings)} findings " + (str(sev_counts) if sev_counts else "(none)")

        prompt = (
            f"GOAL: {spec.get('condition') or ctx.condition}\n\n"
            f"Engagement findings: {eng}\n\n"
            f"Recent tool calls:\n{ctx.tool_summary or '(none)'}\n\n"
            f"Agent's latest message:\n{ctx.last_text or '(empty)'}"
        )
        resp = await llm.ainvoke([SystemMessage(content=_LLM_SYSTEM), HumanMessage(content=prompt)])
        content = resp.content if isinstance(resp.content, str) else str(resp.content)
        start, end = content.find("{"), content.rfind("}")
        if start == -1 or end == -1:
            return VerifyResult(False, "evaluator returned no JSON", _tail(content))
        parsed = json.loads(content[start : end + 1])
        return VerifyResult(bool(parsed.get("met")), str(parsed.get("reason") or ""), "")
    except Exception as exc:  # fail safe: never let evaluator errors mark a goal met
        log.warning("[goal] llm verifier error: %s", exc)
        return VerifyResult(False, f"evaluator error: {type(exc).__name__}", "")


VERIFIERS = {
    "findings": _verify_findings,
    "targets": _verify_targets,
    "task": _verify_task,
    "llm": _verify_llm,
}


async def run_verifier(spec: dict, ctx: VerifyContext) -> VerifyResult:
    """Dispatch to the verifier named by ``spec['type']`` (default llm)."""
    vtype = (spec or {}).get("type", "llm")
    fn = VERIFIERS.get(vtype)
    if fn is None:
        return VerifyResult(False, f"unknown verifier type {vtype!r}", "")
    return await fn(spec, ctx)
