#!/usr/bin/env python3
"""Ban the hang-prone ``asyncio.wait_for(proc.communicate())`` idiom.

Why this is its own checker and not a ruff rule: ruff has no custom-rule plugin
system, and its flake8-async ruleset has nothing for this two-call relationship
(a ``wait_for`` whose first argument is a ``.communicate()`` call). So we walk the
AST ourselves.

The bug: ``await asyncio.wait_for(proc.communicate(), timeout=t)`` cancels
``communicate()`` on timeout. Cancelling it while the child is still alive can
hang *inside* ``wait_for`` — so a ``proc.kill()`` placed in the ``except`` branch
never runs and the caller (the whole agent turn) wedges instead of timing out.

Use the kill-first idiom instead — either ``BasePentestTool._run`` (tools/base.py)
or, inline:

    comm = asyncio.ensure_future(proc.communicate())
    done, _ = await asyncio.wait({comm}, timeout=t)
    if comm not in done:
        proc.kill()                 # close the child's pipes FIRST
        try:
            await comm              # communicate() now drains at EOF + reaps
        except Exception:
            pass
        ...                         # handle timeout
    else:
        stdout, stderr = comm.result()

Killing the child closes its stdout, so the already-running ``communicate()``
returns naturally — no cancellation, no hang.

Note ``await asyncio.wait_for(proc.wait(), timeout=t)`` is FINE and not flagged:
``proc.wait()`` has no pipes to drain, so its cancellation can't hang.

This is a ratchet: a checked-in baseline (subprocess_timeout_baseline.txt, next
to this script) records the pre-existing hand-rolled call sites that are pending
migration. ``--check`` fails only on violations NOT in the baseline — so new code
is blocked immediately, while the known legacy sites are tracked and shrink as
they migrate (delete their line from the baseline when you fix one). Regenerate
the baseline with ``--update-baseline`` (only when intentionally adding known
debt — normally you delete entries, never add).

Run:  python scripts/check_subprocess_timeout.py            # report all hits
      python scripts/check_subprocess_timeout.py --check    # exit 1 on non-baselined hits
      python scripts/check_subprocess_timeout.py --update-baseline
Suppress a single line with a trailing ``# noqa: subprocess-timeout`` comment.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".ruff_cache", ".pytest_cache"}
SUPPRESS = "noqa: subprocess-timeout"
BASELINE_PATH = Path(__file__).resolve().parent / "subprocess_timeout_baseline.txt"


def _is_wait_for(func: ast.expr) -> bool:
    """True for ``asyncio.wait_for`` or a bare ``wait_for`` call target."""
    if isinstance(func, ast.Attribute):
        return func.attr == "wait_for"
    return isinstance(func, ast.Name) and func.id == "wait_for"


def _is_communicate_call(node: ast.expr) -> bool:
    """True for ``<anything>.communicate(...)``."""
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "communicate"


def _suppressed(line: str) -> bool:
    return SUPPRESS in line


def find_violations(path: Path) -> list[tuple[int, str]]:
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return []  # py_compile / ruff already cover syntax
    lines = src.splitlines()
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_wait_for(node.func):
            continue
        if not node.args or not _is_communicate_call(node.args[0]):
            continue
        lineno = node.lineno
        if 1 <= lineno <= len(lines) and _suppressed(lines[lineno - 1]):
            continue
        snippet = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else ""
        hits.append((lineno, snippet))
    return hits


def _key(relpath: str, snippet: str) -> str:
    """Baseline identity: relative path + the source line, line-number independent."""
    return f"{relpath}::{snippet}"


def load_baseline() -> set[str]:
    if not BASELINE_PATH.exists():
        return set()
    out: set[str] = set()
    for line in BASELINE_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.add(line)
    return out


def iter_python_files(root: Path):
    for path in root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.resolve() == Path(__file__).resolve():
            continue
        yield path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit non-zero if any NON-baselined violation is found")
    parser.add_argument(
        "--update-baseline", action="store_true", help="rewrite the baseline file from current violations"
    )
    parser.add_argument("paths", nargs="*", help="files/dirs to scan (default: repo root)")
    args = parser.parse_args()

    roots = [Path(p) for p in args.paths] or [REPO_ROOT]
    files: list[Path] = []
    for root in roots:
        if root.is_file() and root.suffix == ".py":
            files.append(root)
        elif root.is_dir():
            files.extend(iter_python_files(root))

    found: list[tuple[str, int, str]] = []  # (relpath, lineno, snippet)
    for path in sorted(set(files)):
        rel = str(path.relative_to(REPO_ROOT)) if path.is_relative_to(REPO_ROOT) else str(path)
        for lineno, snippet in find_violations(path):
            found.append((rel, lineno, snippet))

    if args.update_baseline:
        keys = sorted({_key(rel, snippet) for rel, _, snippet in found})
        header = (
            "# Baseline of pre-existing hang-prone wait_for(...communicate()) call sites.\n"
            "# Pending migration to the kill-first idiom. DELETE a line when you fix it;\n"
            "# never add new ones. See scripts/check_subprocess_timeout.py.\n"
        )
        BASELINE_PATH.write_text(header + "\n".join(keys) + ("\n" if keys else ""), encoding="utf-8")
        print(
            f"Wrote {len(keys)} baseline entr{'y' if len(keys) == 1 else 'ies'} to "
            f"{BASELINE_PATH.relative_to(REPO_ROOT)}"
        )
        return 0

    baseline = load_baseline()
    new_hits = [(rel, ln, sn) for rel, ln, sn in found if _key(rel, sn) not in baseline]
    baselined = len(found) - len(new_hits)

    for rel, lineno, snippet in new_hits:
        print(f"{rel}:{lineno}: wait_for(...communicate()) is hang-prone — use the kill-first idiom")
        print(f"    {snippet}")

    if new_hits:
        print(
            f"\n{len(new_hits)} NEW hang-prone subprocess-timeout call(s) "
            f"({baselined} known/baselined). Use the kill-first idiom — see "
            f"scripts/check_subprocess_timeout.py."
        )
        return 1 if args.check else 0

    msg = "OK — no new hang-prone wait_for(...communicate()) calls."
    if baselined:
        msg += f" ({baselined} legacy site(s) still baselined, pending migration.)"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
