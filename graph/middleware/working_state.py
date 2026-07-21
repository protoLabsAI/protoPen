"""WorkingStateMiddleware — inject a <working_state> block each turn (ADR 0079, h34.8).

The self-driving backbone. Every model call gets a compact snapshot of the agent's
live operating state — the active goal (+ its running plan), live watches, and pending
scheduled turns — plus the operating doctrine that turns the primitives into a loop:
when work is running out-of-band, YIELD to a watch/wait and end the turn, then RESUME
on the trip with "why am I awake" framing, instead of spinning the iteration budget.

Written into ``state["context"]`` (appended after KnowledgeMiddleware's retrieved
knowledge, since that channel is a plain last-write-wins string) and delivered into the
system message by PromptCacheMiddleware. Emitted only when there IS live state, so an
idle turn carries no extra tokens. Fully best-effort: a render failure never breaks the
turn. The controllers are read lazily (the graph is built before they're wired).
"""

from __future__ import annotations

import logging

from langchain.agents.middleware import AgentMiddleware

from graph.state import session_id_from_state

log = logging.getLogger(__name__)

_DOCTRINE = (
    "Operating doctrine: you self-drive. When work is running out-of-band — a scan, a "
    "capture, a background job, a rate-limit window — do NOT loop or poll it: set a `watch` "
    "(condition) or `wait` (delay) and END your turn. You'll be re-invoked when it trips or "
    "the delay elapses; reorient from this block (why am I awake, what's still open) before acting."
)

_PLAN_CAP = 600
_PROMPT_CAP = 70
_MAX_WATCHES = 8
_MAX_SCHEDULES = 8


class WorkingStateMiddleware(AgentMiddleware):
    """Append a <working_state> snapshot to the per-turn context channel."""

    def before_model(self, state, runtime) -> dict | None:
        try:
            block = self._render(state)
        except Exception:  # noqa: BLE001 — orientation context must never break the turn
            log.exception("[working_state] render failed")
            return None
        if not block:
            return None
        existing = (state.get("context") or "").strip()
        return {"context": f"{existing}\n\n{block}" if existing else block}

    def _render(self, state) -> str:
        session_id = session_id_from_state(state)
        if not session_id:
            return ""

        goal_line, plan = self._goal(session_id)
        watches = self._watches(session_id)
        schedules = self._schedules(session_id)
        if not (goal_line or watches or schedules):
            return ""  # nothing live — emit nothing (idle turns stay lean)

        lines = ["<working_state>"]
        if goal_line:
            lines.append(f"Active goal: {goal_line}")
            if plan:
                lines.append(f"Plan:\n{plan}")
        if watches:
            lines.append("Live watches:")
            lines.extend(watches)
        if schedules:
            lines.append("Pending scheduled turns:")
            lines.extend(schedules)
        lines.append(_DOCTRINE)
        lines.append("</working_state>")
        return "\n".join(lines)

    # ── lazy reads (controllers are wired after the graph is built) ────────────
    def _goal(self, session_id: str):
        from tools.lg_tools import _goal_controller

        if _goal_controller is None:
            return "", ""
        try:
            g = _goal_controller.active_goal(session_id)
        except Exception:  # noqa: BLE001
            return "", ""
        if g is None:
            return "", ""
        plan = (g.checklist or "").strip()
        if len(plan) > _PLAN_CAP:
            plan = plan[:_PLAN_CAP] + "…"
        return g.status_line(), plan

    def _watches(self, session_id: str) -> list[str]:
        from tools.lg_tools import _watch_manager

        if _watch_manager is None:
            return []
        try:
            active = [w for w in _watch_manager.list_watches(session_id) if w.active]
        except Exception:  # noqa: BLE001
            return []
        out = [
            f"- {w.id}: {w.condition} (every {int(w.interval_s)}s, {w.verifier.get('type', 'llm')})"
            for w in active[:_MAX_WATCHES]
        ]
        if len(active) > _MAX_WATCHES:
            out.append(f"- …and {len(active) - _MAX_WATCHES} more")
        return out

    def _schedules(self, session_id: str) -> list[str]:
        from tools.lg_tools import _scheduler_backend

        if _scheduler_backend is None:
            return []
        try:
            jobs = [j for j in _scheduler_backend.list_jobs() if getattr(j, "context_id", None) == session_id]
        except Exception:  # noqa: BLE001
            return []
        jobs.sort(key=lambda j: getattr(j, "next_fire", "") or "")
        out = []
        for j in jobs[:_MAX_SCHEDULES]:
            prompt = (getattr(j, "prompt", "") or "").strip().replace("\n", " ")
            if len(prompt) > _PROMPT_CAP:
                prompt = prompt[:_PROMPT_CAP] + "…"
            out.append(f"- {j.id}: fires {getattr(j, 'next_fire', '?')} → {prompt}")
        if len(jobs) > _MAX_SCHEDULES:
            out.append(f"- …and {len(jobs) - _MAX_SCHEDULES} more")
        return out
