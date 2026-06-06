#!/usr/bin/env python3
"""Scaffold a new protoPen agent tool.

protoPen tools are two pieces: an implementation class in ``tools/<name>.py``
(a ``Tool`` subclass) and a thin LangChain ``@tool`` wrapper registered in
``tools/lg_tools.py``. This script writes the impl stub and prints the exact,
paste-ready wiring for ``lg_tools.py`` — tailored to the tool's category, since
the two registries wire singletons differently:

  • security  → eager module-level singleton, listed in ``get_security_tools``
  • pentest   → lazy singleton (bound to the target store for findings
                ingestion) via ``_init_pentest_singletons``, listed in
                ``get_pentest_tools``

It deliberately does NOT edit the 3600-line ``lg_tools.py`` for you — the wiring
is small, and pasting it keeps you in control of ordering/category placement.
See docs/reference/adding-a-tool.md for the full walkthrough.

Usage:
    python scripts/new_tool.py <tool_name> [--category {security,pentest}]
                               [--desc "one-line description"]

Example:
    python scripts/new_tool.py dns_takeover --category pentest \\
        --desc "Detect dangling DNS records vulnerable to subdomain takeover"
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_TOOLS_DIR = _REPO_ROOT / "tools"


def _camel(snake: str) -> str:
    """dns_takeover -> DnsTakeover (the impl class is <Camel>Tool)."""
    return "".join(part.capitalize() for part in snake.split("_"))


_IMPL_TEMPLATE = '''"""{desc}"""

from __future__ import annotations

import json
from typing import Any

from tools._tool_base import Tool


class {cls}(Tool):
    """{desc}"""

    def __init__(self) -> None:
        # Bound by lg_tools (pentest tools) so _run output lands in the target
        # store via tools.parsers.ingest_output. Harmless for security tools.
        self._target_store: Any | None = None

    @property
    def name(self) -> str:
        return "{name}"

    @property
    def description(self) -> str:
        return "{desc}"

    @property
    def parameters(self) -> dict:
        return {{
            "type": "object",
            "properties": {{
                "action": {{
                    "type": "string",
                    "description": "Action to perform",
                    "enum": ["example"],
                }},
                "target": {{"type": "string", "description": "Target (host / domain / URL)"}},
            }},
            "required": ["action"],
        }}

    async def execute(self, action: str = "", target: str = "", **kwargs: Any) -> str:
        if action == "example":
            # TODO: real work. For CLI-backed tools, see tools/base.py::BasePentestTool._run
            # (kill-first subprocess + parser ingestion) — many pentest tools use it.
            return json.dumps({{"tool": self.name, "action": action, "target": target, "result": "TODO"}})
        return f"Unknown action: {{action}}. Available: example"
'''


def _wiring_security(name: str, cls: str, desc: str) -> str:
    return f"""\
# 1) Import (with the other `from tools.…` imports near the top):
from tools.{name} import {cls}

# 2) Eager singleton (next to the other `_… = …Tool()` security singletons):
_{name} = {cls}()

# 3) @tool wrapper (the docstring IS the LLM-facing description — keep it tight,
#    and list each action as a bullet):
@tool
async def {name}(action: str, target: str = "") -> str:
    \"\"\"{desc}

    - example: TODO describe this action
    \"\"\"
    return await _{name}.execute(action=action, target=target)

# 4) Register in get_security_tools() — add to the `tools = [ … ]` list:
        {name},
"""


def _wiring_pentest(name: str, cls: str, desc: str) -> str:
    return f"""\
# 1) Import (with the other `from tools.…` imports near the top):
from tools.{name} import {cls}

# 2) Lazy singleton declaration (next to the other `_…: …Tool | None = None`):
_{name}: {cls} | None = None

# 3) Wire into _init_pentest_singletons():
#    a. add `_{name}` to that function's `global …` statement
#    b. construct + bind the target store:
    _{name} = {cls}()
    _{name}._target_store = _target_store

# 4) @tool wrapper (docstring IS the LLM-facing description; one bullet per action):
@tool
async def {name}(action: str, target: str = "") -> str:
    \"\"\"{desc}

    - example: TODO describe this action
    \"\"\"
    _init_pentest_singletons()
    return await _{name}.execute(action=action, target=target)

# 5) Register in get_pentest_tools() — add to the `tools = [ … ]` list under a
#    suitable phase/category comment:
        {name},
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scaffold a new protoPen tool (impl stub + lg_tools.py wiring).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("name", help="snake_case tool name, e.g. dns_takeover")
    parser.add_argument(
        "--category",
        choices=["security", "pentest"],
        default="pentest",
        help="security = always-on/eager; pentest = lazy + target-store bound (default)",
    )
    parser.add_argument("--desc", default="", help="one-line description (LLM-facing)")
    args = parser.parse_args()

    name = args.name.strip()
    if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
        print(f"error: tool name must be snake_case (got {name!r})", file=sys.stderr)
        return 2

    cls = f"{_camel(name)}Tool"
    desc = args.desc.strip() or f"TODO: one-line description of the {name} tool."
    impl_path = _TOOLS_DIR / f"{name}.py"

    if impl_path.exists():
        print(f"error: {impl_path.relative_to(_REPO_ROOT)} already exists — pick another name", file=sys.stderr)
        return 1

    impl_path.write_text(_IMPL_TEMPLATE.format(cls=cls, name=name, desc=desc))
    wiring = (_wiring_security if args.category == "security" else _wiring_pentest)(name, cls, desc)

    print(f"\n✓ created tools/{name}.py  (class {cls}, category: {args.category})\n")
    print("Next — paste this into tools/lg_tools.py:\n")
    print(wiring)
    print("Then verify:  python -c \"from tools.lg_tools import get_combined_tools; "
          f"print('{name}' in [t.name for t in get_combined_tools()])\"")
    print("Full guide:   docs/reference/adding-a-tool.md\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
