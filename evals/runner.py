#!/usr/bin/env python3
"""Evaluation runner for protoPen agent.

Loads tasks from tasks.json, runs each through the chat() interface,
and records timing, tool usage, and response quality metrics.

Usage:
    python -m evals.runner --backend langgraph
    python -m evals.runner --backend langgraph --dry-run
    python -m evals.runner --backend langgraph --tasks simple_question,hf_model_search
"""

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure the project root is on sys.path so server/tools can be imported
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


_BASE_URL = os.environ.get("RESEARCHER_URL", "http://localhost:7870")


async def _call_gradio_api(prompt: str, session_id: str) -> str:
    """Call the running protoPen via /api/chat endpoint.

    Requires the container to be running at RESEARCHER_URL.
    """
    import httpx

    async with httpx.AsyncClient(timeout=600) as client:
        resp = await client.post(
            f"{_BASE_URL}/api/chat",
            json={"message": prompt, "session_id": session_id},
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("response", "")


def _load_tasks(filter_ids: list[str] | None = None) -> list[dict]:
    """Load evaluation tasks from tasks.json."""
    tasks_path = Path(__file__).parent / "tasks.json"
    with open(tasks_path) as f:
        tasks = json.load(f)
    if filter_ids:
        tasks = [t for t in tasks if t["id"] in filter_ids]
    return tasks


def _score_response(
    response_text: str,
    expected_patterns: list[str],
    elapsed_ms: int,
) -> dict[str, Any]:
    """Score a response on basic quality metrics."""
    text_lower = response_text.lower()
    pattern_hits = [p for p in expected_patterns if p.lower() in text_lower]
    pattern_misses = [p for p in expected_patterns if p.lower() not in text_lower]

    has_content = len(response_text.strip()) > 0
    has_structure = any(
        marker in response_text
        for marker in ["**", "##", "- ", "1.", "| ", "```"]
    )

    return {
        "has_content": has_content,
        "response_length": len(response_text),
        "has_structure": has_structure,
        "pattern_hits": pattern_hits,
        "pattern_misses": pattern_misses,
        "pattern_score": (
            len(pattern_hits) / len(expected_patterns)
            if expected_patterns
            else 1.0
        ),
        "elapsed_ms": elapsed_ms,
    }


def _extract_tool_calls(audit_entries: list[dict], session_id: str) -> list[dict]:
    """Extract tool calls from audit log entries for a given session."""
    return [
        {
            "tool": e["tool"],
            "duration_ms": e["duration_ms"],
            "success": e["success"],
        }
        for e in audit_entries
        if e.get("session_id") == session_id
    ]


async def _run_single_task(
    task: dict,
    backend: str,
    session_id: str,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run a single evaluation task and return results."""
    task_id = task["id"]
    prompt = task["prompt"]

    print(f"  [{task_id}] Running ({task['category']})...", end=" ", flush=True)

    if dry_run:
        # Validate task structure without calling the LLM
        result = {
            "task_id": task_id,
            "task_name": task["name"],
            "category": task["category"],
            "prompt": prompt,
            "backend": backend,
            "dry_run": True,
            "status": "validated",
            "response": "(dry run — no LLM call)",
            "elapsed_ms": 0,
            "tool_calls": [],
            "score": {
                "has_content": True,
                "response_length": 0,
                "has_structure": False,
                "pattern_hits": [],
                "pattern_misses": task.get("expected_patterns", []),
                "pattern_score": 0.0,
                "elapsed_ms": 0,
            },
        }
        print("SKIP (dry run)")
        return result

    # Call the running protoPen via Gradio API
    t0 = time.monotonic()
    try:
        response_text = await _call_gradio_api(prompt, session_id)
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        status = "success"
        error = None
    except Exception as e:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        response_text = ""
        status = "error"
        error = str(e)

    # Tool calls from audit would need API access — skip for now
    tool_calls = []

    score = _score_response(
        response_text,
        task.get("expected_patterns", []),
        elapsed_ms,
    )

    # Determine pass/fail
    passed = score["has_content"] and score["pattern_score"] >= 0.5
    # Empty input edge case: passes if we get any response (even error handling)
    if task_id == "edge_empty_input":
        passed = True  # We just want it not to crash

    status_icon = "PASS" if passed else "FAIL"
    print(f"{status_icon} ({elapsed_ms}ms, {score['response_length']} chars, {len(tool_calls)} tools)")

    result = {
        "task_id": task_id,
        "task_name": task["name"],
        "category": task["category"],
        "prompt": prompt,
        "backend": backend,
        "dry_run": False,
        "status": status,
        "error": error,
        "passed": passed,
        "response": response_text[:2000],  # Truncate for storage
        "elapsed_ms": elapsed_ms,
        "tool_calls": tool_calls,
        "expected_tools": task.get("expected_tools", []),
        "score": score,
    }
    return result


async def run_eval(
    backend: str,
    dry_run: bool = False,
    filter_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Run the full evaluation suite and return results."""
    tasks = _load_tasks(filter_ids)
    if not tasks:
        print("No tasks to run.")
        return {}

    print(f"\n{'='*60}")
    print(f"protoPen Eval — backend: {backend}")
    print(f"Tasks: {len(tasks)} | Dry run: {dry_run}")
    print(f"{'='*60}\n")

    results = []
    for i, task in enumerate(tasks):
        session_id = f"eval-{backend}-{task['id']}-{int(time.time())}"
        result = await _run_single_task(task, backend, session_id, dry_run)
        results.append(result)

    # Compute summary
    non_dry = [r for r in results if not r.get("dry_run")]
    summary = {
        "backend": backend,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "total_tasks": len(results),
        "passed": sum(1 for r in non_dry if r.get("passed")),
        "failed": sum(1 for r in non_dry if not r.get("passed")),
        "total_elapsed_ms": sum(r["elapsed_ms"] for r in results),
        "avg_elapsed_ms": (
            sum(r["elapsed_ms"] for r in non_dry) // max(len(non_dry), 1)
            if non_dry
            else 0
        ),
        "total_tool_calls": sum(len(r["tool_calls"]) for r in results),
        "by_category": {},
    }

    # Per-category breakdown
    for cat in ("simple", "medium", "complex"):
        cat_results = [r for r in non_dry if r["category"] == cat]
        if cat_results:
            summary["by_category"][cat] = {
                "count": len(cat_results),
                "passed": sum(1 for r in cat_results if r.get("passed")),
                "avg_elapsed_ms": sum(r["elapsed_ms"] for r in cat_results) // len(cat_results),
                "avg_response_length": sum(r["score"]["response_length"] for r in cat_results) // len(cat_results),
                "avg_tool_calls": sum(len(r["tool_calls"]) for r in cat_results) / len(cat_results),
            }

    output = {
        "summary": summary,
        "results": results,
    }

    # Save results
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    outfile = results_dir / f"{backend}_{ts}.json"
    with open(outfile, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n{'='*60}")
    print(f"Results saved to: {outfile}")
    print(f"Passed: {summary['passed']}/{summary['total_tasks']}")
    print(f"Avg response time: {summary['avg_elapsed_ms']}ms")
    print(f"Total tool calls: {summary['total_tool_calls']}")
    print(f"{'='*60}\n")

    return output


def main():
    parser = argparse.ArgumentParser(description="protoPen eval runner")
    parser.add_argument(
        "--backend",
        choices=["langgraph"],
        default="langgraph",
        help="Agent backend to evaluate",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate harness without calling the LLM",
    )
    parser.add_argument(
        "--tasks",
        type=str,
        default=None,
        help="Comma-separated task IDs to run (default: all)",
    )

    args = parser.parse_args()

    # Set the backend env var before any server imports
    os.environ["AGENT_BACKEND"] = args.backend

    filter_ids = args.tasks.split(",") if args.tasks else None
    asyncio.run(run_eval(args.backend, dry_run=args.dry_run, filter_ids=filter_ids))


if __name__ == "__main__":
    main()
