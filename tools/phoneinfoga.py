"""PhoneInfoga — OSINT reconnaissance on a phone number.

PhoneInfoga is a Go binary (not a Python dep), so protoPen runs it as an isolated
CLI: install it on the host and point ``PHONEINFOGA_BIN`` at the binary (or have
it on PATH). See start.sh (native) / Dockerfile (container) for the install.

The default *local* scanner is keyless — it derives country, carrier hints, and
line type from the number's format and offline metadata. Remote scanners
(numverify, googlesearch, …) only run when their API keys are configured, so this
tool stays useful with zero setup and richer with keys.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any

from tools._tool_base import Tool
from tools.parsers import ingest_output

logger = logging.getLogger(__name__)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class PhoneInfogaTool(Tool):
    """PhoneInfoga — profile a phone number (passive OSINT)."""

    def __init__(self, workspace: str = "/tmp/protopen"):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None

    @property
    def name(self) -> str:
        return "phoneinfoga"

    @property
    def description(self) -> str:
        return (
            "PhoneInfoga OSINT phone-number reconnaissance — given a number in "
            "international format (e.g. '+14155552671'), returns country, carrier, "
            "and line type, plus an OSINT footprint (search-engine dorks and "
            "reputation links). Passive — formats/metadata + public sources only; "
            "no calls or messages are sent."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform (default scan)",
                    "enum": ["scan"],
                },
                "number": {
                    "type": "string",
                    "description": "Phone number in international format, e.g. '+14155552671'",
                },
                "timeout": {"type": "integer", "description": "Overall wall-clock cap in seconds (default 60)"},
            },
            "required": ["number"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action") or "scan"
        if action != "scan":
            return f"Unknown action: {action}. Available: ['scan']"
        number = (kwargs.get("number") or "").strip()
        if not number:
            return "phoneinfoga error: 'number' is required"
        try:
            result = await self.scan(number, timeout=int(kwargs.get("timeout", 60)))
            ingest_output("phoneinfoga", "scan", result, self._target_store)
            return result
        except Exception as exc:
            return f"phoneinfoga error (scan): {exc}"

    def _resolve_bin(self) -> str | None:
        """Locate the phoneinfoga binary; None if not installed."""
        env = os.environ.get("PHONEINFOGA_BIN")
        if env:
            return env if Path(env).exists() else None
        return shutil.which("phoneinfoga")

    async def scan(self, number: str, timeout: int = 60) -> str:
        binpath = self._resolve_bin()
        if not binpath:
            return (
                "phoneinfoga is not installed. It's a Go binary — install it and set "
                "PHONEINFOGA_BIN to the path: `go install "
                "github.com/sundowndev/phoneinfoga/v2@latest` (binary lands in "
                "~/go/bin/phoneinfoga). start.sh does this automatically on the Deck."
            )
        raw = await self._run(binpath, "scan", "-n", number, timeout=timeout)
        return self._summarize(number, raw)

    async def _run(self, *args: str, timeout: int = 60) -> str:
        """Run phoneinfoga; stdout only. Kill-first-on-timeout idiom (see maigret):
        cancelling communicate() while the child is alive can wedge the turn, so we
        kill the child (closing its stdout) and let the running communicate() drain
        to EOF, instead of letting wait_for cancel it."""
        # Redacted: argv carries the target phone number (PII) — log the binary +
        # arg count only, never the value.
        logger.info("Running %s (%d args)", Path(args[0]).name if args else "?", max(0, len(args) - 1))
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            cwd=str(self._workspace),
        )
        comm = asyncio.ensure_future(proc.communicate())
        done, _pending = await asyncio.wait({comm}, timeout=timeout)
        if comm not in done:
            proc.kill()
            try:
                await comm
            except Exception:
                pass
            return f"[timeout] phoneinfoga exceeded {timeout}s."
        stdout, _ = comm.result()
        return _ANSI.sub("", stdout.decode(errors="replace")).strip()

    @staticmethod
    def _summarize(number: str, raw: str) -> str:
        """PhoneInfoga's scan output is already compact (number details + scanner
        results). Strip noise lines and prepend a header."""
        if raw.startswith("[timeout]"):
            return raw
        kept = [ln.rstrip() for ln in raw.splitlines() if ln.strip() and not ln.strip().startswith(("⠋", "⠙", "⠹"))]
        body = "\n".join(kept).strip()
        header = f"phoneinfoga: scan of {number}"
        if not body:
            return f"{header} — no results (check the number format, e.g. '+14155552671')."
        return f"{header}\n\n{body}"
