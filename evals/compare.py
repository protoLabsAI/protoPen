#!/usr/bin/env python3
"""Compare two protoPen eval result files and produce a markdown report.

Usage:
    python -m evals.compare results/nanobot_20260323_120000.json results/langgraph_20260323_120500.json
    python -m evals.compare results/nanobot_*.json results/langgraph_*.json --output report.md
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _load_results(path: str) -> dict[str, Any]:
    """Load a results JSON file."""
    with open(path) as f:
        return json.load(f)


def _pct_change(old: float, new: float) -> str:
    """Format percentage change between two values."""
    if old == 0:
        return "N/A"
    change = ((new - old) / old) * 100
    sign = "+" if change > 0 else ""
    return f"{sign}{change:.1f}%"


def _winner_label(val_a: float, val_b: float, lower_is_better: bool = True) -> str:
    """Return which side wins for a metric."""
    if val_a == val_b:
        return "tie"
    if lower_is_better:
        return "A" if val_a < val_b else "B"
    return "A" if val_a > val_b else "B"


def generate_report(
    results_a: dict[str, Any],
    results_b: dict[str, Any],
) -> str:
    """Generate a markdown comparison report from two result sets."""
    sum_a = results_a["summary"]
    sum_b = results_b["summary"]
    name_a = sum_a["backend"]
    name_b = sum_b["backend"]

    lines = []
    lines.append("# protoPen Eval Comparison")
    lines.append("")
    lines.append(f"**Backend A:** `{name_a}` (run: {sum_a['timestamp'][:19]})")
    lines.append(f"**Backend B:** `{name_b}` (run: {sum_b['timestamp'][:19]})")
    lines.append("")

    # --- Overall summary ---
    lines.append("## Overall Summary")
    lines.append("")
    lines.append(f"| Metric | {name_a} | {name_b} | Winner |")
    lines.append("|--------|---------|---------|--------|")

    pass_a = sum_a.get("passed", 0)
    pass_b = sum_b.get("passed", 0)
    total_a = sum_a.get("total_tasks", 0)
    total_b = sum_b.get("total_tasks", 0)
    lines.append(
        f"| Pass rate | {pass_a}/{total_a} | {pass_b}/{total_b} "
        f"| {_winner_label(pass_a, pass_b, lower_is_better=False)} |"
    )

    avg_a = sum_a.get("avg_elapsed_ms", 0)
    avg_b = sum_b.get("avg_elapsed_ms", 0)
    lines.append(
        f"| Avg response time | {avg_a}ms | {avg_b}ms "
        f"| {_winner_label(avg_a, avg_b, lower_is_better=True)} |"
    )

    total_ms_a = sum_a.get("total_elapsed_ms", 0)
    total_ms_b = sum_b.get("total_elapsed_ms", 0)
    lines.append(
        f"| Total wall time | {total_ms_a}ms | {total_ms_b}ms "
        f"| {_winner_label(total_ms_a, total_ms_b, lower_is_better=True)} |"
    )

    tools_a = sum_a.get("total_tool_calls", 0)
    tools_b = sum_b.get("total_tool_calls", 0)
    lines.append(
        f"| Total tool calls | {tools_a} | {tools_b} | - |"
    )
    lines.append("")

    # --- Per-category breakdown ---
    lines.append("## Performance by Category")
    lines.append("")

    categories = sorted(
        set(list(sum_a.get("by_category", {}).keys()) + list(sum_b.get("by_category", {}).keys()))
    )

    for cat in categories:
        cat_a = sum_a.get("by_category", {}).get(cat, {})
        cat_b = sum_b.get("by_category", {}).get(cat, {})
        lines.append(f"### {cat.capitalize()}")
        lines.append("")
        lines.append(f"| Metric | {name_a} | {name_b} | Winner |")
        lines.append("|--------|---------|---------|--------|")

        ca_pass = cat_a.get("passed", 0)
        cb_pass = cat_b.get("passed", 0)
        ca_count = cat_a.get("count", 0)
        cb_count = cat_b.get("count", 0)
        lines.append(f"| Passed | {ca_pass}/{ca_count} | {cb_pass}/{cb_count} "
                      f"| {_winner_label(ca_pass, cb_pass, lower_is_better=False)} |")

        ca_ms = cat_a.get("avg_elapsed_ms", 0)
        cb_ms = cat_b.get("avg_elapsed_ms", 0)
        lines.append(f"| Avg time | {ca_ms}ms | {cb_ms}ms "
                      f"| {_winner_label(ca_ms, cb_ms, lower_is_better=True)} |")

        ca_len = cat_a.get("avg_response_length", 0)
        cb_len = cat_b.get("avg_response_length", 0)
        lines.append(f"| Avg response length | {ca_len} | {cb_len} "
                      f"| {_winner_label(ca_len, cb_len, lower_is_better=False)} |")

        ca_tools = cat_a.get("avg_tool_calls", 0)
        cb_tools = cat_b.get("avg_tool_calls", 0)
        lines.append(f"| Avg tool calls | {ca_tools:.1f} | {cb_tools:.1f} | - |")
        lines.append("")

    # --- Per-task detail ---
    lines.append("## Per-Task Results")
    lines.append("")
    lines.append(f"| Task | Category | {name_a} | {name_b} | Time A | Time B |")
    lines.append("|------|----------|---------|---------|--------|--------|")

    # Index results by task_id
    by_id_a = {r["task_id"]: r for r in results_a.get("results", [])}
    by_id_b = {r["task_id"]: r for r in results_b.get("results", [])}
    all_ids = sorted(set(list(by_id_a.keys()) + list(by_id_b.keys())))

    for tid in all_ids:
        ra = by_id_a.get(tid, {})
        rb = by_id_b.get(tid, {})
        cat = ra.get("category", rb.get("category", "?"))
        pass_a_str = "PASS" if ra.get("passed") else ("SKIP" if ra.get("dry_run") else "FAIL")
        pass_b_str = "PASS" if rb.get("passed") else ("SKIP" if rb.get("dry_run") else "FAIL")
        time_a = f"{ra.get('elapsed_ms', 0)}ms"
        time_b = f"{rb.get('elapsed_ms', 0)}ms"
        lines.append(f"| {tid} | {cat} | {pass_a_str} | {pass_b_str} | {time_a} | {time_b} |")

    lines.append("")

    # --- Tool call efficiency ---
    lines.append("## Tool Call Efficiency")
    lines.append("")
    lines.append(f"| Task | Expected Tools | {name_a} calls | {name_b} calls |")
    lines.append("|------|---------------|---------------|---------------|")

    for tid in all_ids:
        ra = by_id_a.get(tid, {})
        rb = by_id_b.get(tid, {})
        expected = ra.get("expected_tools", rb.get("expected_tools", []))
        expected_str = ", ".join(expected) if expected else "(none)"
        calls_a = len(ra.get("tool_calls", []))
        calls_b = len(rb.get("tool_calls", []))
        tools_used_a = ", ".join(sorted(set(t["tool"] for t in ra.get("tool_calls", [])))) or "-"
        tools_used_b = ", ".join(sorted(set(t["tool"] for t in rb.get("tool_calls", [])))) or "-"
        lines.append(f"| {tid} | {expected_str} | {calls_a} ({tools_used_a}) | {calls_b} ({tools_used_b}) |")

    lines.append("")

    # --- Recommendation ---
    lines.append("## Recommendation")
    lines.append("")

    # Simple scoring: +1 for each category win
    score_a = 0
    score_b = 0

    # Pass rate
    if pass_a > pass_b:
        score_a += 2
    elif pass_b > pass_a:
        score_b += 2

    # Speed
    if avg_a < avg_b:
        score_a += 1
    elif avg_b < avg_a:
        score_b += 1

    # Response quality (avg length across all tasks)
    all_len_a = [r["score"]["response_length"] for r in results_a.get("results", []) if not r.get("dry_run")]
    all_len_b = [r["score"]["response_length"] for r in results_b.get("results", []) if not r.get("dry_run")]
    avg_len_a = sum(all_len_a) / max(len(all_len_a), 1)
    avg_len_b = sum(all_len_b) / max(len(all_len_b), 1)
    if avg_len_a > avg_len_b:
        score_a += 1
    elif avg_len_b > avg_len_a:
        score_b += 1

    if score_a > score_b:
        winner = name_a
        loser = name_b
    elif score_b > score_a:
        winner = name_b
        loser = name_a
    else:
        winner = None
        loser = None

    if winner:
        lines.append(
            f"**`{winner}`** is the recommended backend based on this evaluation "
            f"(score: {max(score_a, score_b)} vs {min(score_a, score_b)})."
        )
        lines.append("")
        lines.append("Factors considered:")
        lines.append(f"- Pass rate: {pass_a}/{total_a} ({name_a}) vs {pass_b}/{total_b} ({name_b})")
        lines.append(f"- Avg response time: {avg_a}ms ({name_a}) vs {avg_b}ms ({name_b})")
        lines.append(f"- Avg response length: {avg_len_a:.0f} ({name_a}) vs {avg_len_b:.0f} ({name_b})")
    else:
        lines.append(
            "**Tie.** Both backends performed equivalently on this evaluation. "
            "Consider running with more tasks or on real workloads to differentiate."
        )
    lines.append("")

    lines.append("---")
    lines.append("*Generated by protoPen eval harness*")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Compare two protoPen eval result files")
    parser.add_argument("file_a", help="Path to first results JSON (backend A)")
    parser.add_argument("file_b", help="Path to second results JSON (backend B)")
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output path for markdown report (default: stdout)",
    )

    args = parser.parse_args()

    results_a = _load_results(args.file_a)
    results_b = _load_results(args.file_b)

    report = generate_report(results_a, results_b)

    if args.output:
        Path(args.output).write_text(report)
        print(f"Report written to: {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
