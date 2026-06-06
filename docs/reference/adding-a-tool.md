---
outline: deep
---

# Adding a Tool

A protoPen agent tool is two pieces:

1. **Implementation** — `tools/<name>.py`, a `Tool` subclass (`tools/_tool_base.py`)
   with `name`, `description`, `parameters`, and an `async execute(**kwargs)`.
2. **Registration** — a thin LangChain `@tool` wrapper in `tools/lg_tools.py`,
   added to one of the registry functions the agent loads.

The fastest path is the scaffold, which writes the impl stub and prints the exact
wiring to paste:

```bash
python scripts/new_tool.py dns_takeover --category pentest \
    --desc "Detect dangling DNS records vulnerable to subdomain takeover"
```

## The two categories

The registry wires singletons differently depending on the tool's category — the
scaffold's `--category` flag picks the right wiring:

| Category | Singleton | Registry fn | Use for |
|---|---|---|---|
| `security` | eager (`_foo = FooTool()`) | `get_security_tools()` | always-on, no engagement gating (feeds, search, memory) |
| `pentest` (default) | lazy + target-store bound (`_init_pentest_singletons()`) | `get_pentest_tools()` | recon/exploit tools whose output should ingest into the target store |

`get_combined_tools()` = `get_security_tools()` + `get_pentest_tools()` and is what
the graph loads (`graph/agent.py`).

## 1. The implementation (`tools/<name>.py`)

```python
"""Detect dangling DNS records vulnerable to subdomain takeover."""

from __future__ import annotations

import json
from typing import Any

from tools._tool_base import Tool


class DnsTakeoverTool(Tool):
    def __init__(self) -> None:
        self._target_store: Any | None = None  # bound by lg_tools for pentest tools

    @property
    def name(self) -> str:
        return "dns_takeover"

    @property
    def description(self) -> str:
        return "Detect dangling DNS records vulnerable to subdomain takeover."

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["scan"], "description": "Action to perform"},
                "target": {"type": "string", "description": "Domain to check"},
            },
            "required": ["action"],
        }

    async def execute(self, action: str = "", target: str = "", **kwargs: Any) -> str:
        ...
```

For CLI-backed tools, subclass behaviour from `tools/base.py::BasePentestTool` —
its `_run(...)` handles the **kill-first subprocess timeout idiom** (see
`scripts/check_subprocess_timeout.py`) and routes output through
`tools.parsers.ingest_output` so findings land in the target store. Many pentest
tools use it.

## 2. The wrapper (`tools/lg_tools.py`)

The scaffold prints these blocks for your category. For `pentest`:

```python
# import (top of file)
from tools.dns_takeover import DnsTakeoverTool

# lazy singleton declaration
_dns_takeover: DnsTakeoverTool | None = None

# inside _init_pentest_singletons(): add to its `global …` line, then
_dns_takeover = DnsTakeoverTool()
_dns_takeover._target_store = _target_store

# the LangChain wrapper — its DOCSTRING is the LLM-facing description.
# List one bullet per action.
@tool
async def dns_takeover(action: str, target: str = "") -> str:
    """Detect dangling DNS records vulnerable to subdomain takeover.

    - scan: Resolve each record and flag CNAMEs pointing at unclaimed services
    """
    _init_pentest_singletons()
    return await _dns_takeover.execute(action=action, target=target)

# register in get_pentest_tools(): add `dns_takeover,` to the `tools = [ … ]` list
```

::: tip The docstring matters
LangChain builds the tool schema the model sees from the **`@tool` function's
docstring and signature** — not the impl's `description`/`parameters`. Keep the
wrapper docstring tight and action-bulleted; that's what the agent reads.
:::

## 3. Verify

```bash
# the tool is loaded:
python -c "from tools.lg_tools import get_combined_tools; \
print('dns_takeover' in [t.name for t in get_combined_tools()])"

# full app still boots + the suite is green:
python -m server --dump-openapi /tmp/spec.json
python -m pytest -q
```

Then add a row to [Tools](./tools.md) so the reference stays complete.
