"""Playbook runner — execute playbook steps sequentially via tool dispatch."""
from __future__ import annotations

import logging
from typing import Any, Callable, Awaitable

from playbooks.schema import Playbook, PlaybookStep, StepStatus

logger = logging.getLogger(__name__)

# Type for tool dispatch: (tool_name, action, params) -> output string
ToolDispatcher = Callable[[str, str, dict[str, Any]], Awaitable[str]]


async def run_playbook(
    playbook: Playbook,
    dispatch: ToolDispatcher,
    *,
    on_step_complete: Callable[[PlaybookStep], None] | None = None,
) -> Playbook:
    """Execute all steps in a playbook sequentially.

    Args:
        playbook: The playbook to execute.
        dispatch: Async callable (tool_name, action, params) -> output.
        on_step_complete: Optional callback fired after each step.

    Returns:
        The playbook with updated step statuses and outputs.
    """
    for step in playbook.steps:
        # Evaluate condition if present
        if step.condition and not _evaluate_condition(step.condition, playbook):
            step.status = StepStatus.SKIPPED
            logger.info("Skipped step '%s' — condition not met", step.name)
            if on_step_complete:
                on_step_complete(step)
            continue

        step.status = StepStatus.RUNNING
        logger.info(
            "Running step '%s' — %s.%s", step.name, step.tool, step.action,
        )

        try:
            output = await dispatch(step.tool, step.action, step.params)
            step.output = output
            step.status = StepStatus.COMPLETED
            logger.info("Step '%s' completed", step.name)
        except Exception as e:
            step.error = str(e)
            step.status = StepStatus.FAILED
            logger.error("Step '%s' failed: %s", step.name, e)

            if step.on_fail == "stop":
                if on_step_complete:
                    on_step_complete(step)
                break
            elif step.on_fail == "skip_remaining":
                if on_step_complete:
                    on_step_complete(step)
                for remaining in playbook.steps[playbook.steps.index(step) + 1:]:
                    remaining.status = StepStatus.SKIPPED
                break

        if on_step_complete:
            on_step_complete(step)

    return playbook


def _evaluate_condition(condition: str, playbook: Playbook) -> bool:
    """Simple condition evaluation — check if a named step completed."""
    # Format: "step_name.completed" or "step_name.failed"
    parts = condition.split(".")
    if len(parts) != 2:
        return True  # Unknown format — proceed

    step_name, attr = parts
    for step in playbook.steps:
        if step.name == step_name:
            if attr == "completed":
                return step.status == StepStatus.COMPLETED
            elif attr == "failed":
                return step.status == StepStatus.FAILED
            elif attr == "skipped":
                return step.status == StepStatus.SKIPPED
    return True  # Step not found — proceed
