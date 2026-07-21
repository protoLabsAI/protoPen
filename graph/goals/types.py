"""Goal-mode types — a goal is a condition + a verifier the agent loops toward.

When goal mode is active, after each turn a verifier decides whether the goal is
met; if not, the agent is re-invoked with a continuation prompt until it's met,
the iteration budget runs out, or the goal is flagged unachievable.

protoPen's verifiers are backed by the **engagement** (findings) or an LLM judge —
never shell execution (see ``graph/goals/verifiers.py``), keeping goal mode within
the tight no-code-exec profile.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from time import time


def coerce_str_list(value) -> list[str]:
    """Normalize a contract list field (``constraints`` / ``boundaries``) to a
    ``list[str]``: passes a list through (stringified, blanks dropped), splits a
    scalar string on newlines/semicolons, and maps None → []."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [s.strip() for s in str(value).replace(";", "\n").splitlines() if s.strip()]


# Terminal statuses (the loop stops):
#   achieved      — verifier confirmed completion
#   exhausted     — ran out of iteration budget without meeting the goal
#   unachievable  — no-progress streak, or the agent flagged it impossible
TERMINAL_STATUSES = ("achieved", "exhausted", "unachievable")


@dataclass
class VerifyResult:
    """Outcome of running a goal's verifier once."""

    met: bool
    reason: str = ""
    evidence: str = ""


@dataclass
class GoalState:
    """Persisted per-session goal record.

    ``verifier`` is a spec dict whose ``type`` selects an entry in
    ``graph/goals/verifiers.VERIFIERS`` and whose other keys are that verifier's
    parameters (e.g. ``{"type": "findings", "severity": "critical", "min": 1}``).
    ``checklist`` holds the model-authored ``<goal_plan>`` text, carried across
    iterations so the agent keeps a running plan.
    """

    session_id: str
    condition: str
    verifier: dict = field(default_factory=lambda: {"type": "llm"})
    # Optional completion contract (ADR 0073) — DIRECTIVE ONLY. These shape the
    # continuation prompt each drive turn; the deterministic verifier stays the sole
    # arbiter of DONE. All default-empty, so a goal without a contract behaves exactly
    # as before. For a pentest goal: constraints/boundaries = engagement scope ("stay
    # on these hosts", "don't touch out-of-scope"); stop_when = "STOP and ask before
    # exploitation".
    outcome: str = ""  # what "done" should concretely look like
    constraints: list[str] = field(default_factory=list)  # must-hold conditions while working
    boundaries: list[str] = field(default_factory=list)  # hard "do NOT" limits
    stop_when: str = ""  # a condition that should halt and hand back to the operator
    status: str = "active"
    # "drive" (default) — the agent's turns move the metric, so a not-met goal
    # re-invokes the loop. "monitor" (ADR 0030) — an external process moves it
    # over time, so a not-met check just waits for the next evaluation instead of
    # storming the loop. Ends only on achieved / cleared.
    mode: str = "drive"
    checklist: str = ""
    iteration: int = 0
    max_iterations: int = 10
    no_progress_streak: int = 0
    # Per-goal patience (ADR 0030 D4): stop after this many no-progress checks.
    # None → fall back to the config default (goals_no_progress_limit).
    no_progress_limit: int | None = None
    last_reason: str = ""
    last_evidence: str = ""
    started_at: float = field(default_factory=time)
    finished_at: float | None = None

    @property
    def active(self) -> bool:
        return self.status == "active"

    @property
    def has_contract(self) -> bool:
        """True when any completion-contract field is set (ADR 0073)."""
        return bool(self.outcome or self.constraints or self.boundaries or self.stop_when)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "GoalState":
        # Tolerate unknown/missing keys so older files load forward-compatibly.
        known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    def status_line(self) -> str:
        """One-line human summary for /goal status + continuation footers."""
        vt = self.verifier.get("type", "llm")
        if self.mode == "monitor":
            # Iteration count is meaningless for a monitor goal (it doesn't drive).
            base = f"goal [{self.status}] monitor via {vt}: {self.condition!r}"
        else:
            base = (
                f"goal [{self.status}] via {vt}: {self.condition!r} (iteration {self.iteration}/{self.max_iterations})"
            )
        if self.last_reason:
            base += f" — {self.last_reason}"
        return base
