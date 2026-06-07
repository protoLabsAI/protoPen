#!/usr/bin/env python3
"""Guard against OpenAPI spec drift: the committed spec vs. the live app.

``scripts/gen_api_docs.py --check`` only checks the *page* against the committed
``docs/public/openapi.json`` — it can't catch a route that exists in the app but
was never dumped into that spec (exactly how ``GET /api/tools`` and the
engagement-control POST silently went undocumented). This closes that gap: it
dumps the spec from the live app and diffs the **route surface** (path + method
+ summary) against the committed spec.

Usage::

    python scripts/check_openapi_spec.py            # CI: dump + diff, exit 1 on drift
    python scripts/check_openapi_spec.py --live x.json   # diff a pre-dumped spec

On drift it prints the added/removed/changed routes and the one-liner to fix it
(regenerate the spec + page). It compares only the route surface, not schema
minutiae, so it stays robust to incidental serializer differences.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMITTED = REPO_ROOT / "docs" / "public" / "openapi.json"


def _route_surface(spec: dict) -> dict[str, str]:
    """Map ``"METHOD /path"`` → summary for every operation in the spec."""
    surface: dict[str, str] = {}
    for path, ops in (spec.get("paths") or {}).items():
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            surface[f"{method.upper()} {path}"] = op.get("summary", "")
    return surface


def _dump_live_spec(out: Path) -> None:
    """Dump the live app's OpenAPI spec via ``python -m server --dump-openapi``.

    The server hard-defaults a few workspace paths under ``/sandbox``; create it
    best-effort (root or sudo) so ``build_app`` can initialize on a CI runner.
    A dummy ``OPENAI_API_KEY`` satisfies the model-client constructor (no calls
    are made — the app dumps the spec and exits)."""
    import os

    env = {**os.environ, "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", "dummy-for-spec-dump")}
    for d in ("/sandbox/knowledge", "/sandbox/workflows", "/sandbox/skills", "/sandbox/goals"):
        try:
            Path(d).mkdir(parents=True, exist_ok=True)
        except OSError:
            subprocess.run(["sudo", "mkdir", "-p", d], check=False)
            subprocess.run(["sudo", "chmod", "-R", "777", "/sandbox"], check=False)
    subprocess.run(
        [sys.executable, "-m", "server", "--dump-openapi", str(out)],
        check=True,
        cwd=REPO_ROOT,
        env=env,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", help="path to a pre-dumped live spec (else dump it now)")
    args = ap.parse_args()

    if not COMMITTED.exists():
        print(f"ERROR: committed spec missing at {COMMITTED}", file=sys.stderr)
        return 1
    committed = _route_surface(json.loads(COMMITTED.read_text()))

    if args.live:
        live_path = Path(args.live)
    else:
        tmp = Path(tempfile.gettempdir()) / "protopen-live-openapi.json"
        _dump_live_spec(tmp)
        live_path = tmp
    live = _route_surface(json.loads(live_path.read_text()))

    added = sorted(set(live) - set(committed))  # in app, not committed
    removed = sorted(set(committed) - set(live))  # in committed, not in app
    changed = sorted(r for r in set(live) & set(committed) if live[r] != committed[r])

    if not (added or removed or changed):
        print(f"OpenAPI spec in sync with the live app ({len(live)} routes).")
        return 0

    print("OpenAPI spec drift — the committed spec does not match the live app:\n")
    for r in added:
        print(f"  + {r}   (in app, missing from committed spec)")
    for r in removed:
        print(f"  - {r}   (in committed spec, gone from app)")
    for r in changed:
        print(f"  ~ {r}   (summary changed)")
    print(
        "\nFix: regenerate the spec + page from the live app:\n"
        "  python -m server --dump-openapi docs/public/openapi.json\n"
        "  python scripts/gen_api_docs.py",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
