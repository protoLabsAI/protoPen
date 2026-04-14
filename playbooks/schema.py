"""Playbook schema — data classes for playbook definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PlaybookStep:
    """A single step in a playbook — maps to one tool action."""

    name: str
    tool: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    condition: str | None = None  # Jinja2-like condition
    on_fail: str = "stop"  # stop | continue | skip_remaining
    timeout: int = 300
    phase: str | None = None  # "red" or "blue" — enables ATT&CK normalization
    status: StepStatus = StepStatus.PENDING
    output: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "tool": self.tool,
            "action": self.action,
            "params": self.params,
            "status": self.status.value,
            "output": self.output[:500] if self.output else "",
            "error": self.error[:500] if self.error else "",
        }


@dataclass
class Playbook:
    """A playbook — an ordered sequence of tool steps."""

    name: str
    description: str = ""
    steps: list[PlaybookStep] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    @property
    def completed(self) -> bool:
        return all(s.status in (StepStatus.COMPLETED, StepStatus.SKIPPED) for s in self.steps)

    @property
    def failed(self) -> bool:
        return any(s.status == StepStatus.FAILED for s in self.steps)

    @property
    def progress(self) -> str:
        done = sum(1 for s in self.steps if s.status in (StepStatus.COMPLETED, StepStatus.SKIPPED))
        return f"{done}/{len(self.steps)}"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "progress": self.progress,
            "completed": self.completed,
            "failed": self.failed,
            "steps": [s.to_dict() for s in self.steps],
        }
