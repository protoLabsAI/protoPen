"""GoalController — /goal control-message parsing + the goal decision loop.

Both responsibilities are pure of any graph calls so they're unit-testable:

1. ``parse_control`` — interpret a ``/goal`` message (set / status / clear) and
   mutate the store. Returns a reply string when the message *was* a command (the
   caller short-circuits the turn), else ``None``.
2. ``evaluate`` — run after a turn ends. Runs the goal's verifier and returns a
   ``Decision``: continue with a continuation prompt, or finish (achieved /
   exhausted / unachievable).

The server's chat-stream path owns the actual re-invocation loop; this class only
decides what should happen next.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

from graph.goals.store import GoalStore
from graph.goals.types import GoalState
from graph.goals.verifiers import VerifyContext, run_verifier

log = logging.getLogger(__name__)

CLEAR_ALIASES = {"clear", "stop", "off", "reset", "none", "cancel"}

_GOAL_PLAN_RE = re.compile(r"<goal_plan>(.*?)</goal_plan>", re.IGNORECASE | re.DOTALL)
_GIVEUP_RE = re.compile(r"<goal_unachievable(?:\s+reason=\"([^\"]*)\")?\s*/?>", re.IGNORECASE)


@dataclass
class Decision:
    action: str  # "continue" | "done"
    state: GoalState | None = None
    message: str | None = None  # continuation prompt (action == "continue")
    note: str = ""  # human-readable status note


class GoalController:
    def __init__(self, config, store: GoalStore | None = None):
        self._config = config
        self._store = store or GoalStore()

    @property
    def store(self) -> GoalStore:
        return self._store

    def active_goal(self, session_id: str) -> GoalState | None:
        state = self._store.get(session_id)
        return state if state and state.active else None

    # ── control messages ───────────────────────────────────────────────────

    async def parse_control(self, message: str, session_id: str) -> str | None:
        if not isinstance(message, str):
            return None
        stripped = message.strip()
        low = stripped.lower()
        if not (stripped == "/goal" or low.startswith("/goal ") or low.startswith("/goal\n")):
            return None
        rest = stripped[len("/goal") :].strip()

        # /goal  → status
        if not rest:
            state = self._store.get(session_id)
            return state.status_line() if state else "No active goal for this session."

        # /goal clear|stop|...  → clear
        if rest.lower() in CLEAR_ALIASES:
            existed = self._store.clear(session_id)
            return "Goal cleared." if existed else "No active goal to clear."

        # /goal {json}  or  /goal <free text>  → set
        spec, condition, max_iters = self._parse_set(rest)
        if condition is None:
            return (
                "Could not parse goal. Use `/goal <text>` (fuzzy, LLM-judged) or "
                '`/goal {"condition": "...", "verifier": {"type": "findings", '
                '"severity": "critical", "min": 1}}`.'
            )
        state = GoalState(
            session_id=session_id,
            condition=condition,
            verifier=spec,
            max_iterations=max_iters or getattr(self._config, "goals_max_iterations", 10),
        )
        self._store.set(state)
        return f"Goal set. {state.status_line()}"

    def program_set(self, session_id: str, condition: str, verifier: dict | None = None) -> GoalState:
        """Set a goal programmatically — the agent's ``set_goal`` tool path.

        Mirrors the ``/goal <text>`` set branch (same defaults + config iteration
        cap) but takes an explicit verifier spec instead of parsing a message.
        """
        spec = dict(verifier) if verifier else {"type": "llm"}
        if "type" not in spec:
            spec["type"] = "llm"
        state = GoalState(
            session_id=session_id,
            condition=condition,
            verifier=spec,
            max_iterations=getattr(self._config, "goals_max_iterations", 10),
        )
        self._store.set(state)
        return state

    def _parse_set(self, rest: str):
        """Return (verifier_spec, condition, max_iterations|None)."""
        if rest.lstrip().startswith("{"):
            try:
                data = json.loads(rest)
            except json.JSONDecodeError:
                return ({}, None, None)
            condition = data.get("condition")
            if not condition:
                return ({}, None, None)
            verifier = data.get("verifier") or {"type": "llm"}
            if "type" not in verifier:
                verifier["type"] = "llm"
            return (verifier, condition, data.get("max_iterations"))
        # plain text → fuzzy goal judged by the llm verifier
        return ({"type": "llm"}, rest, None)

    # ── evaluation ─────────────────────────────────────────────────────────

    async def evaluate(self, session_id: str, *, last_text: str, tool_summary: str = "") -> Decision | None:
        state = self.active_goal(session_id)
        if state is None:
            return None

        # 1. Verifier first — ground truth overrides the model's self-assessment.
        ctx = VerifyContext(
            config=self._config,
            condition=state.condition,
            last_text=last_text or "",
            tool_summary=tool_summary or "",
        )
        result = await run_verifier(state.verifier, ctx)

        if result.met:
            return self._finish(state, "achieved", result.reason or "verifier passed", evidence=result.evidence)

        # 2. Not met — honour an explicit give-up from the agent.
        giveup = _GIVEUP_RE.search(last_text or "")
        if giveup:
            reason = (giveup.group(1) or "agent flagged the goal unachievable").strip()
            return self._finish(state, "unachievable", reason)

        # 3. Not met — refresh checklist, track progress, decide continue vs stop.
        plan = _GOAL_PLAN_RE.search(last_text or "")
        if plan:
            state.checklist = plan.group(1).strip()

        signature_unchanged = result.reason == state.last_reason and result.evidence == state.last_evidence
        state.no_progress_streak = (state.no_progress_streak + 1) if signature_unchanged else 0
        state.last_reason = result.reason
        state.last_evidence = result.evidence
        state.iteration += 1

        limit = getattr(self._config, "goals_no_progress_limit", 4)
        if state.iteration >= state.max_iterations:
            return self._finish(
                state, "exhausted", f"ran out of iteration budget ({state.max_iterations})", evidence=result.evidence
            )
        if state.no_progress_streak >= limit:
            return self._finish(
                state,
                "unachievable",
                f"no progress after {state.no_progress_streak} attempts: {result.reason}",
                evidence=result.evidence,
            )

        self._store.set(state)
        return Decision(
            action="continue",
            state=state,
            message=self._continuation(state, result),
            note=f"goal not met (iteration {state.iteration}/{state.max_iterations}): {result.reason}",
        )

    def _finish(self, state: GoalState, status: str, reason: str, *, evidence: str = "") -> Decision:
        from time import time

        state.status = status
        state.last_reason = reason
        if evidence:
            state.last_evidence = evidence
        state.finished_at = time()
        self._store.set(state)
        glyph = {"achieved": "✓", "exhausted": "⏳", "unachievable": "✗"}.get(status, "•")
        return Decision(action="done", state=state, note=f"{glyph} goal {status}: {reason}")

    def _continuation(self, state: GoalState, result) -> str:
        evidence = (result.evidence or "").strip()
        evidence_block = f"\nEvidence:\n{evidence}\n" if evidence else "\n"
        plan_block = state.checklist.strip() or "(no plan yet — create one)"
        vtype = state.verifier.get("type", "llm")
        return (
            f"[goal continuation {state.iteration}/{state.max_iterations}]\n"
            f"The goal is NOT yet met.\n"
            f"Verifier ({vtype}): {result.reason}"
            f"{evidence_block}\n"
            f"Current plan:\n{plan_block}\n\n"
            f'Keep working toward the goal: "{state.condition}".\n'
            f"Maintain a running checklist inside a <goal_plan>...</goal_plan> block "
            f"(update it every turn). If you determine the goal is impossible or out "
            f'of scope, emit <goal_unachievable reason="..."/> and stop. '
            f"Otherwise take the next concrete step now."
        )
