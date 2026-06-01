"""Goal verifiers — the testable-outcome backing for goal mode.

protoPen's verifiers are **read-only and domain-backed** — they never execute
shell, keeping goal mode inside the tight no-code-exec profile (the divergence
from protoAgent, whose command/test/ci verifiers run on the host).

``spec["type"]`` selects an entry in ``VERIFIERS``:

  findings — assert over the active engagement's findings: ``severity`` (this
             level or higher), ``category`` (substring), ``min`` count. Met when
             at least ``min`` findings match. The precise, no-LLM check.
  llm      — fuzzy judgment: an LLM decides if the goal's condition is met given
             the engagement state + the agent's latest message. The fallback.
"""

from __future__ import annotations

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


def _active_findings() -> list[dict]:
    """The active engagement's findings (empty if no engagement / unavailable)."""
    try:
        from tools.lg_tools import get_engagement_manager

        mgr = get_engagement_manager()
    except Exception:
        return []
    return list(getattr(mgr, "findings", []) or [])


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
    "llm": _verify_llm,
}


async def run_verifier(spec: dict, ctx: VerifyContext) -> VerifyResult:
    """Dispatch to the verifier named by ``spec['type']`` (default llm)."""
    vtype = (spec or {}).get("type", "llm")
    fn = VERIFIERS.get(vtype)
    if fn is None:
        return VerifyResult(False, f"unknown verifier type {vtype!r}", "")
    return await fn(spec, ctx)
