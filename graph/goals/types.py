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
    status: str = "active"
    checklist: str = ""
    iteration: int = 0
    max_iterations: int = 10
    no_progress_streak: int = 0
    last_reason: str = ""
    last_evidence: str = ""
    started_at: float = field(default_factory=time)
    finished_at: float | None = None

    @property
    def active(self) -> bool:
        return self.status == "active"

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
        base = f"goal [{self.status}] via {vt}: {self.condition!r} (iteration {self.iteration}/{self.max_iterations})"
        if self.last_reason:
            base += f" — {self.last_reason}"
        return base
