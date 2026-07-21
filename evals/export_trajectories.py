#!/usr/bin/env python3
"""Export agent trajectories from Langfuse into SFT-ready JSONL (#289 items 2-4).

protoPen persists each model call as a Langfuse ``llm-call`` generation whose
``input`` is the full, **untruncated** ChatML conversation the model saw
(system -> user -> assistant[tool_calls] -> tool[observation] -> ...) and whose
``output`` is the assistant turn it produced (content + the actual emitted
``tool_calls``; see ``tracing.trace_llm_call`` / ``graph/middleware/audit.py``).

The richest single view of a session is therefore one generation's ``input``
plus its ``output`` — we never merge across generations, so a session that mixed
a lead agent and subagents can't corrupt a trajectory (each generation's input is
an internally-consistent conversation). We pick the generation with the longest
input as the spine and append its output as the final assistant turn.

Crucially, the tool *observations* recovered this way are untruncated: the
``tool:<name>`` spans are capped at 200 chars (``audit.py`` pre-truncates before
tracing), but the ToolMessage content fed into the *next* model call is full, and
that is what the spine's ``input`` carries. So we read observation text from the
generation inputs, and use the tool spans only for success labels.

Usage:
    python -m evals.export_trajectories --min-score 0.8 --out traj.jsonl
    python -m evals.export_trajectories --since 7d --out recent.jsonl
    python -m evals.export_trajectories --session-id eval-langgraph-cve_analysis-1712345678
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

# Ensure the project root is importable when run as a script.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

_DEFAULT_TASKS = _PROJECT_ROOT / "evals" / "tasks.json"


# --------------------------------------------------------------------------- #
# Small coercion helpers (Langfuse returns pydantic objects; io may be JSON str)
# --------------------------------------------------------------------------- #
def _coerce_json(v: Any) -> Any:
    """Parse a JSON string into an object; pass through anything already parsed."""
    if isinstance(v, str):
        s = v.strip()
        if s[:1] in ("[", "{"):
            try:
                return json.loads(s)
            except (ValueError, TypeError):
                return v
    return v


def _messages_from_input(inp: Any) -> list[dict]:
    """Extract the list of ChatML message dicts from a generation's ``input``."""
    inp = _coerce_json(inp)
    if isinstance(inp, list):
        return [m for m in inp if isinstance(m, dict)]
    if isinstance(inp, dict) and isinstance(inp.get("messages"), list):
        return [m for m in inp["messages"] if isinstance(m, dict)]
    return []


def _final_assistant(output: Any) -> dict:
    """Turn a generation ``output`` into a trailing assistant message.

    ``output`` is ``{"content", "tool_calls"}`` for a tool-calling turn or a plain
    string for a content-only turn (see ``tracing.trace_llm_call``).
    """
    output = _coerce_json(output)
    if isinstance(output, dict):
        msg: dict = {"role": "assistant", "content": output.get("content", "")}
        tcs = output.get("tool_calls")
        if tcs:
            msg["tool_calls"] = tcs
        return msg
    if isinstance(output, str):
        return {"role": "assistant", "content": output}
    return {"role": "assistant", "content": "" if output is None else output}


def _text_of(content: Any) -> str:
    """Flatten message content (str or list of content blocks) to plain text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for b in content:
            if isinstance(b, dict) and isinstance(b.get("text"), str):
                parts.append(b["text"])
            elif isinstance(b, str):
                parts.append(b)
        return "\n".join(parts)
    return "" if content is None else str(content)


def _ts_num(obs: Any) -> float:
    """Sortable numeric start-time for an observation (0.0 if unknown)."""
    st = getattr(obs, "start_time", None)
    try:
        return st.timestamp()
    except (AttributeError, TypeError, ValueError, OSError):
        return 0.0


def _ts_str(dt: Any) -> Optional[str]:
    try:
        return dt.isoformat()
    except (AttributeError, TypeError, ValueError):
        return dt if isinstance(dt, str) else None


# --------------------------------------------------------------------------- #
# Observation classification + labeling
# --------------------------------------------------------------------------- #
def _is_generation(o: Any) -> bool:
    return (getattr(o, "type", "") or "").upper() == "GENERATION" or getattr(o, "name", "") == "llm-call"


def _is_tool(o: Any) -> bool:
    name = getattr(o, "name", "") or ""
    return (getattr(o, "type", "") or "").upper() == "TOOL" or name.startswith("tool:")


def _tool_info(o: Any) -> dict:
    md = getattr(o, "metadata", None) or {}
    if isinstance(md, dict) and "success" in md:
        success = bool(md["success"])
    else:
        success = (getattr(o, "level", "") or "").upper() != "ERROR"
    name = getattr(o, "name", "") or ""
    if name.startswith("tool:"):
        name = name[len("tool:") :]
    return {"name": name, "success": success}


def _trace_scores(trace: Any) -> dict:
    """Collect ``{name: value}`` from a trace's Langfuse scores (best-effort)."""
    out: dict = {}
    for s in getattr(trace, "scores", None) or []:
        name = getattr(s, "name", None)
        val = getattr(s, "value", None)
        if name is not None and val is not None:
            out[name] = val
    return out


def _pattern_score(text: str, patterns: list[str]) -> float:
    if not patterns:
        return 1.0
    lowered = text.lower()
    hits = sum(1 for p in patterns if p.lower() in lowered)
    return hits / len(patterns)


def _task_id_from_session(session_id: Optional[str]) -> Optional[str]:
    """Recover the eval task id from a runner session id.

    The eval runner names sessions ``eval-<backend>-<task_id>-<unix_ts>``
    (see ``evals/runner.py``); non-eval sessions return ``None``.
    """
    if not session_id or not session_id.startswith("eval-"):
        return None
    parts = session_id.split("-")
    if len(parts) < 4:
        return None
    if parts[-1].isdigit():
        return "-".join(parts[2:-1]) or None
    return "-".join(parts[2:]) or None


# --------------------------------------------------------------------------- #
# Trajectory reconstruction
# --------------------------------------------------------------------------- #
def build_trajectory(
    trace: Any,
    observations: list,
    tasks_by_id: dict | None = None,
    score_name: Optional[str] = None,
) -> Optional[dict]:
    """Stitch a trace's observations into one labeled ChatML trajectory record.

    Returns ``None`` when the trace has no model-call generations to mine.
    """
    tasks_by_id = tasks_by_id or {}
    gens = [o for o in observations if _is_generation(o)]
    if not gens:
        return None
    tools = [o for o in observations if _is_tool(o)]

    # Spine = the generation whose input is the most complete conversation.
    # Within a single agent loop, input length grows monotonically, so this is
    # the last turn; across a lead+subagent mix it is the deeper coherent loop.
    spine = max(gens, key=lambda o: (len(_messages_from_input(getattr(o, "input", None))), _ts_num(o)))
    messages = list(_messages_from_input(getattr(spine, "input", None)))
    final = _final_assistant(getattr(spine, "output", None))
    messages.append(final)

    session_id = getattr(trace, "session_id", None)
    task_id = _task_id_from_session(session_id)
    task = tasks_by_id.get(task_id) if task_id else None

    final_text = _text_of(final.get("content"))
    tool_infos = [_tool_info(o) for o in tools]
    tools_ok = all(ti["success"] for ti in tool_infos) if tool_infos else True

    called = {tc.get("name") for m in messages if m.get("role") == "assistant" for tc in (m.get("tool_calls") or [])}
    called |= {ti["name"] for ti in tool_infos}
    tools_called = sorted(called - {None, ""})
    expected_tools = list(task.get("expected_tools", [])) if task else []
    coverage = len([t for t in expected_tools if t in tools_called]) / len(expected_tools) if expected_tools else 1.0

    lf_scores = _trace_scores(trace)
    pattern = _pattern_score(final_text, task.get("expected_patterns", [])) if task else None

    # Score used for --min-score filtering: an explicit Langfuse score wins;
    # else the task's expected-pattern coverage; else a pass/fail fallback.
    if score_name and score_name in lf_scores:
        score = float(lf_scores[score_name])
    elif pattern is not None:
        score = pattern
    else:
        score = 1.0 if (final_text.strip() and tools_ok) else 0.0

    num_tool_calls = sum(len(m.get("tool_calls") or []) for m in messages if m.get("role") == "assistant")

    return {
        "session_id": session_id,
        "trace_id": getattr(trace, "id", None),
        "task_id": task_id,
        "score": round(float(score), 4),
        "messages": messages,
        "labels": {
            "pattern_score": None if pattern is None else round(pattern, 4),
            "tools_ok": tools_ok,
            "tools_called": tools_called,
            "expected_tools": expected_tools,
            "expected_tools_coverage": round(coverage, 4),
            "num_messages": len(messages),
            "num_tool_calls": num_tool_calls,
            "langfuse_scores": lf_scores,
            "timestamp": _ts_str(getattr(trace, "timestamp", None)),
        },
    }


# --------------------------------------------------------------------------- #
# Langfuse read (paginated)
# --------------------------------------------------------------------------- #
def iter_traces(
    api: Any,
    since: Optional[datetime] = None,
    session_id: Optional[str] = None,
    tags: Optional[list[str]] = None,
    limit: Optional[int] = None,
    page_size: int = 50,
) -> Iterator[Any]:
    """Yield traces from ``api.trace.list`` (page-based pagination)."""
    page = 1
    yielded = 0
    while True:
        resp = api.trace.list(
            page=page,
            limit=page_size,
            from_timestamp=since,
            session_id=session_id,
            tags=tags,
        )
        data = getattr(resp, "data", None) or []
        for tr in data:
            yield tr
            yielded += 1
            if limit and yielded >= limit:
                return
        meta = getattr(resp, "meta", None)
        total_pages = getattr(meta, "total_pages", None) if meta else None
        if not data or (total_pages is not None and page >= total_pages):
            return
        page += 1


def fetch_observations(api: Any, trace_id: str, page_size: int = 100) -> list:
    """Fetch every observation for a trace (cursor-based pagination)."""
    out: list = []
    cursor: Optional[str] = None
    while True:
        resp = api.observations.get_many(trace_id=trace_id, cursor=cursor, limit=page_size)
        data = getattr(resp, "data", None) or []
        out.extend(data)
        meta = getattr(resp, "meta", None)
        next_cursor = getattr(meta, "cursor", None) if meta else None
        if not data or not next_cursor or next_cursor == cursor:
            break
        cursor = next_cursor
    return out


def export(
    api: Any,
    since: Optional[datetime] = None,
    session_id: Optional[str] = None,
    tags: Optional[list[str]] = None,
    min_score: float = 0.0,
    limit: Optional[int] = None,
    tasks_by_id: dict | None = None,
    score_name: Optional[str] = None,
) -> Iterator[dict]:
    """Yield labeled trajectory records passing the ``min_score`` gate."""
    for trace in iter_traces(api, since=since, session_id=session_id, tags=tags, limit=limit):
        obs = fetch_observations(api, getattr(trace, "id", None))
        rec = build_trajectory(trace, obs, tasks_by_id=tasks_by_id, score_name=score_name)
        if rec is None or rec["score"] < min_score:
            continue
        yield rec


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _parse_since(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip()
    m = re.fullmatch(r"(\d+)\s*([smhdw])", s)
    if m:
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]
        return datetime.now(timezone.utc) - timedelta(seconds=int(m.group(1)) * mult)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        raise SystemExit(f"--since: cannot parse '{s}' (use e.g. 7d, 24h, or ISO 2026-07-01)")


def _load_tasks(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    with open(p) as f:
        tasks = json.load(f)
    return {t["id"]: t for t in tasks if isinstance(t, dict) and "id" in t}


def _build_api_client() -> Any:
    pk = os.environ.get("LANGFUSE_PUBLIC_KEY")
    sk = os.environ.get("LANGFUSE_SECRET_KEY")
    host = os.environ.get("LANGFUSE_HOST") or os.environ.get("LANGFUSE_URL", "http://localhost:3001")
    if not pk or not sk:
        raise SystemExit("LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY not set — cannot read traces.")
    from langfuse import Langfuse

    return Langfuse(public_key=pk, secret_key=sk, host=host).api


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Export protoPen agent trajectories from Langfuse to SFT JSONL")
    ap.add_argument("--since", default=None, help="Only traces since: 7d / 24h / 30m or ISO timestamp")
    ap.add_argument("--min-score", type=float, default=0.0, help="Drop trajectories scoring below this (0..1)")
    ap.add_argument("--out", default="-", help="Output JSONL path ('-' for stdout)")
    ap.add_argument("--session-id", default=None, help="Restrict to a single session id")
    ap.add_argument("--tag", default="protopen", help="Trace tag filter (default: protopen; '' to disable)")
    ap.add_argument("--limit", type=int, default=None, help="Max traces to scan")
    ap.add_argument("--score-name", default=None, help="Prefer this Langfuse score name for filtering")
    ap.add_argument("--tasks-file", default=str(_DEFAULT_TASKS), help="tasks.json for outcome labeling")
    args = ap.parse_args(argv)

    since = _parse_since(args.since)
    tasks_by_id = _load_tasks(args.tasks_file)
    tags = [args.tag] if args.tag else None
    api = _build_api_client()

    records = export(
        api,
        since=since,
        session_id=args.session_id,
        tags=tags,
        min_score=args.min_score,
        limit=args.limit,
        tasks_by_id=tasks_by_id,
        score_name=args.score_name,
    )

    out_is_stdout = args.out in ("-", "/dev/stdout")
    fh = sys.stdout if out_is_stdout else open(args.out, "w")
    n = 0
    try:
        for rec in records:
            fh.write(json.dumps(rec, default=str) + "\n")
            n += 1
    finally:
        if not out_is_stdout:
            fh.close()

    print(f"[export] wrote {n} trajectories (min_score={args.min_score}) -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
