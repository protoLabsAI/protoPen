"""Base class for pentest tool wrappers.

Provides subprocess execution, timeout handling, and a standard interface
for action-based tools that delegate to CLI binaries.
"""
from __future__ import annotations

import asyncio
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
    ) -> str:
        """Run *cmd* as an async subprocess with *timeout* seconds."""
        logger.info(
            "[%s] %s → %s (timeout=%ds)",
            self.name, action, target_hint or "n/a", timeout,
        )
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return f"Command timed out after {timeout}s: {' '.join(cmd[:4])}..."

        output = stdout.decode(errors="replace")
        if stderr:
            err_text = stderr.decode(errors="replace").strip()
            if err_text:
                output += f"\n[stderr] {err_text}"
        return output.strip()

    async def execute(self, action: str, **kwargs: Any) -> str:
        """Subclass entry point — override in each tool."""
        raise NotImplementedError
