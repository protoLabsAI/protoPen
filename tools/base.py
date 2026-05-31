"""Base class for pentest tool wrappers.

Provides subprocess execution, timeout handling, and a standard interface
for action-based tools that delegate to CLI binaries.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class BasePentestTool:
    """Base class for pentest tools with action→command dispatch.

    Subclasses set ``name``, ``description``, and ``ACTIONS`` as class
    attributes, then implement ``execute()`` to route actions.
    """

    name: str = ""
    description: str = ""
    ACTIONS: dict[str, dict[str, Any]] = {}

    def __init__(self) -> None:
        self._target_store: Any | None = None

    # ── helpers ──────────────────────────────────────────────────────────

    def _unknown_action(self, action: str) -> str:
        available = ", ".join(sorted(self.ACTIONS.keys()))
        return f"Unknown action: {action}. Available: {available}"

    async def _run(
        self,
        *,
        action: str,
        cmd: list[str],
        timeout: int,
        target_hint: str = "",
        env: dict[str, str] | None = None,
    ) -> str:
        """Run *cmd* as an async subprocess with *timeout* seconds.

        Pass *env* to override specific environment variables; the current
        process environment is used as the base when *env* is provided.
        """
        import os

        logger.info(
            "[%s] %s → %s (timeout=%ds)",
            self.name,
            action,
            target_hint or "n/a",
            timeout,
        )
        merged_env: dict[str, str] | None = None
        if env is not None:
            merged_env = os.environ.copy()
            merged_env.update(env)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=merged_env,
            )
        except FileNotFoundError:
            binary = cmd[0] if cmd else "unknown"
            logger.warning("[%s] %s: binary '%s' not found", self.name, action, binary)
            return json.dumps({"error": f"{binary} not found", "tool": self.name, "action": action})
        # Kill-first timeout idiom (NOT wait_for(communicate())): on timeout we
        # kill the child so its pipes close, then drain the already-running
        # communicate() at EOF. Letting wait_for cancel communicate() while the
        # child is still alive can hang inside wait_for — the kill never runs and
        # the whole agent turn wedges. See scripts/check_subprocess_timeout.py.
        comm = asyncio.ensure_future(proc.communicate())
        done, _pending = await asyncio.wait({comm}, timeout=timeout)
        if comm not in done:
            proc.kill()
            try:
                await comm  # drains + reaps now that stdout is closed
            except Exception:
                pass
            return f"Command timed out after {timeout}s: {' '.join(cmd[:4])}..."
        stdout, stderr = comm.result()

        output = stdout.decode(errors="replace")
        if stderr:
            err_text = stderr.decode(errors="replace").strip()
            if err_text:
                output += f"\n[stderr] {err_text}"
        output = output.strip()

        # Route the output through the matching parser so findings land in the
        # target store. No-op when no parser is registered or no store is set;
        # ingest_output never raises. (Imported here to avoid an import cycle.)
        from tools.parsers import ingest_output

        ingest_output(self.name, action, output, self._target_store)
        return output

    async def execute(self, action: str, **kwargs: Any) -> str:
        """Subclass entry point — override in each tool."""
        raise NotImplementedError
