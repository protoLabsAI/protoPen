"""Tests for the declarative workflow engine + registry (ADR 0002)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from graph.workflows.engine import (
    execute_workflow,
    render_template,
    resolve_inputs,
    validate_recipe,
)
from graph.workflows.registry import WorkflowRegistry

VALID = {
    "name": "demo",
    "inputs": [{"name": "topic", "required": True}, {"name": "depth", "default": "deep"}],
    "steps": [
        {"id": "gather", "subagent": "researcher", "prompt": "research {{inputs.topic}} ({{inputs.depth}})"},
        {
            "id": "brief",
            "subagent": "researcher",
            "depends_on": ["gather"],
            "prompt": "write up:\n{{steps.gather.output}}",
        },
    ],
    "output": "{{steps.brief.output}}",
}


def test_validate_accepts_valid_recipe():
    assert validate_recipe(VALID, known_subagents={"researcher"}) == []


def test_validate_catches_structural_errors():
    assert "missing 'name'" in validate_recipe({"steps": [{"id": "a", "subagent": "researcher", "prompt": "x"}]})
    assert any("non-empty list" in e for e in validate_recipe({"name": "x"}))
    dup = {
        "name": "x",
        "steps": [
            {"id": "a", "subagent": "researcher", "prompt": "p"},
            {"id": "a", "subagent": "researcher", "prompt": "p"},
        ],
    }
    assert any("duplicate step id" in e for e in validate_recipe(dup))


def test_validate_catches_dep_and_cycle_and_subagent():
    bad_dep = {"name": "x", "steps": [{"id": "a", "subagent": "researcher", "prompt": "p", "depends_on": ["z"]}]}
    assert any("unknown step 'z'" in e for e in validate_recipe(bad_dep))
    cycle = {
        "name": "x",
        "steps": [
            {"id": "a", "subagent": "researcher", "prompt": "p", "depends_on": ["b"]},
            {"id": "b", "subagent": "researcher", "prompt": "p", "depends_on": ["a"]},
        ],
    }
    assert any("cycle" in e for e in validate_recipe(cycle))
    unknown_sub = {"name": "x", "steps": [{"id": "a", "subagent": "nope", "prompt": "p"}]}
    assert any("unknown subagent" in e for e in validate_recipe(unknown_sub, known_subagents={"researcher"}))


def test_validate_catches_bad_template_refs():
    bad = {
        "name": "x",
        "inputs": [{"name": "topic"}],
        "steps": [{"id": "a", "subagent": "researcher", "prompt": "{{inputs.missing}} {{steps.ghost.output}}"}],
    }
    errs = validate_recipe(bad)
    assert any("unknown input" in e for e in errs)
    assert any("unknown step" in e for e in errs)


def test_render_template_substitutes():
    out = render_template("hi {{inputs.topic}} / {{steps.s.output}}", {"topic": "x"}, {"s": "RESULT"})
    assert out == "hi x / RESULT"


def test_resolve_inputs_defaults_and_missing():
    resolved, missing = resolve_inputs(VALID, {"topic": "ai"})
    assert resolved["topic"] == "ai" and resolved["depth"] == "deep" and missing == []
    _, missing2 = resolve_inputs(VALID, {})
    assert missing2 == ["topic"]


def test_execute_threads_outputs_sequentially():
    calls = []

    async def run_step(subagent, prompt, sid):
        calls.append((sid, prompt))
        return f"<{sid}-out>"

    res = asyncio.run(execute_workflow(VALID, {"topic": "ai", "depth": "deep"}, run_step=run_step))
    brief_prompt = dict((sid, p) for sid, p in calls)["brief"]
    assert "<gather-out>" in brief_prompt  # gather's output threaded into brief
    assert res["output"] == "<brief-out>"
    assert res["failed"] == []


def test_execute_runs_independent_steps_in_parallel():
    running = 0
    max_seen = 0

    async def run_step(subagent, prompt, sid):
        nonlocal running, max_seen
        running += 1
        max_seen = max(max_seen, running)
        await asyncio.sleep(0.02)
        running -= 1
        return sid

    fanout = {
        "name": "f",
        "steps": [
            {"id": "a", "subagent": "researcher", "prompt": "p"},
            {"id": "b", "subagent": "researcher", "prompt": "p"},
            {"id": "c", "subagent": "researcher", "prompt": "p"},
        ],
    }
    asyncio.run(execute_workflow(fanout, {}, run_step=run_step, max_concurrency=4))
    assert max_seen >= 2  # independent steps overlapped


def test_execute_records_failure_inline_and_continues():
    async def run_step(subagent, prompt, sid):
        if sid == "gather":
            raise RuntimeError("boom")
        return f"saw:{prompt}"

    res = asyncio.run(execute_workflow(VALID, {"topic": "ai"}, run_step=run_step))
    assert "gather" in res["failed"]
    assert "Error: step 'gather'" in res["steps"]["brief"]  # brief saw gather's error text


def test_registry_loads_recipes_from_dir(tmp_path):
    (tmp_path / "a.yaml").write_text("name: a\nsteps:\n  - id: s\n    subagent: x\n    prompt: hi\n")
    (tmp_path / "notrecipe.yaml").write_text("just: a mapping\n")  # no name → skipped
    reg = WorkflowRegistry([str(tmp_path)])
    assert reg.names() == ["a"]
    assert reg.get("a")["steps"][0]["id"] == "s"
    assert reg.get("missing") is None


def test_bundled_threat_brief_recipe_is_valid():
    """The shipped workflows/threat-brief.yaml must validate against the real
    subagent registry — guards against recipe/subagent drift."""
    from graph.subagents.config import SUBAGENT_REGISTRY

    reg = WorkflowRegistry([str(Path(__file__).resolve().parent.parent / "workflows")])
    recipe = reg.get("threat-brief")
    assert recipe is not None, "bundled threat-brief.yaml not loaded"
    assert validate_recipe(recipe, known_subagents=set(SUBAGENT_REGISTRY)) == []
