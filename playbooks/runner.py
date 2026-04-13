"""Playbook runner — execute playbook steps sequentially via tool dispatch."""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Awaitable

from playbooks.schema import Playbook, PlaybookStep, StepStatus
from tools.parsers.attack_normalizer import normalize_step

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
            resolved_params = _resolve_step_refs(step.params, playbook)
            output = await dispatch(step.tool, step.action, resolved_params)
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


_STEP_REF_RE = re.compile(r"\$\{steps\.([a-zA-Z0-9_]+)\.output\}")


def _resolve_step_refs(
    params: dict[str, Any], playbook: Playbook,
) -> dict[str, Any]:
    """Resolve ${steps.<name>.output} references in step params.

    Looks up the named step in the playbook and substitutes its output.
    If the step hasn't run or doesn't exist, the reference is left as-is.
    If the step failed (empty output), resolves to empty string.

    When a referenced step has ``phase`` set ("red" or "blue"), the raw
    output is normalized to ATT&CK-aligned JSON before substitution so
    that purple_team.coverage_matrix / exercise_report can consume it.

    When a single param contains multiple step refs that all resolve to
    normalized arrays, the arrays are merged into one JSON array.
    Non-string param values are passed through unchanged.
    """
    step_map = {s.name: s for s in playbook.steps}
    resolved = {}

    for key, value in params.items():
        if not isinstance(value, str) or "${steps." not in value:
            resolved[key] = value
            continue

        ref_names = _STEP_REF_RE.findall(value)

        # Multi-ref merge: if there are 2+ refs and ALL resolve to
        # phase-tagged steps, merge their normalized arrays.
        if len(ref_names) >= 2:
            all_phased = all(
                ref in step_map and step_map[ref].phase
                for ref in ref_names
            )
            if all_phased:
                merged: list[dict] = []
                for ref in ref_names:
                    step = step_map[ref]
                    if step.output:
                        merged.extend(normalize_step(
                            step.tool, step.action, step.output, step.phase,
                        ))
                resolved[key] = json.dumps(merged)
                continue

        # Single ref or mixed: standard per-ref substitution
        def _replace(match: re.Match) -> str:
            step_name = match.group(1)
            step = step_map.get(step_name)
            if step is None:
                return match.group(0)  # leave unresolved
            if step.phase and step.output:
                return json.dumps(normalize_step(
                    step.tool, step.action, step.output, step.phase,
                ))
            return step.output  # "" if failed/not run

        resolved[key] = _STEP_REF_RE.sub(_replace, value)

    return resolved


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
