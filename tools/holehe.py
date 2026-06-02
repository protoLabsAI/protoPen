"""holehe — OSINT: which sites have an account registered to an email address.

holehe pins its own dependency set (httpx, trio, …), so — like maigret — protoPen
runs it as an isolated CLI: install it in its own venv and point ``HOLEHE_BIN`` at
the binary (or have it on PATH). See start.sh (native) / Dockerfile (container).

It checks 120+ sites via their password-reset / registration flows and reports
where the email is **used** — without sending anything to the address. The email
pivot that complements maigret (username) and phoneinfoga (number).
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


class HoleheTool(Tool):
    """holehe — find sites where an email is registered (passive OSINT)."""

    def __init__(self, workspace: str = "/tmp/protopen"):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None

    @property
    def name(self) -> str:
        return "holehe"

    @property
    def description(self) -> str:
        return (
            "holehe OSINT email reconnaissance — given an email address, checks "
            "120+ sites (Twitter, Instagram, Spotify, Amazon, …) for an account "
            "registered to it and reports where it's used. Passive — queries public "
            "registration/reset flows; never sends mail to the address or logs in."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform (default search)",
                    "enum": ["search"],
                },
                "email": {"type": "string", "description": "Email address to investigate"},
                "only_used": {
                    "type": "boolean",
                    "description": "Report only sites where the email is registered (default true)",
                },
                "timeout": {"type": "integer", "description": "Overall wall-clock cap in seconds (default 120)"},
            },
            "required": ["email"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action") or "search"
        if action != "search":
            return f"Unknown action: {action}. Available: ['search']"
        email = (kwargs.get("email") or "").strip()
        if not email or "@" not in email:
            return "holehe error: a valid 'email' is required"
        try:
            result = await self.search(
                email,
                only_used=bool(kwargs.get("only_used", True)),
                timeout=int(kwargs.get("timeout", 120)),
            )
            ingest_output("holehe", "search", result, self._target_store)
            return result
        except Exception as exc:
            return f"holehe error (search): {exc}"

    def _resolve_bin(self) -> str | None:
        """Locate the isolated holehe binary; None if not installed."""
        env = os.environ.get("HOLEHE_BIN")
        if env:
            return env if Path(env).exists() else None
        return shutil.which("holehe")

    async def search(self, email: str, only_used: bool = True, timeout: int = 120) -> str:
        binpath = self._resolve_bin()
        if not binpath:
            return (
                "holehe is not installed. Install it in an isolated venv (it pins "
                "httpx/trio): `python3 -m venv ~/.holehe-venv && "
                "~/.holehe-venv/bin/pip install holehe`, then set HOLEHE_BIN to the "
                "binary path (start.sh does this automatically on the Deck)."
            )
        args = [binpath, email, "--no-color", "--no-clear"]
        if only_used:
            args.append("--only-used")
        raw = await self._run(*args, timeout=timeout)
        return self._summarize(email, raw)

    async def _run(self, *args: str, timeout: int = 120) -> str:
        """Run holehe; stdout only. Kill-first-on-timeout idiom (see maigret)."""
        # Redacted: argv carries the target email (PII) — log the binary + arg
        # count only, never the value.
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
            return f"[timeout] holehe exceeded {timeout}s."
        stdout, _ = comm.result()
        return _ANSI.sub("", stdout.decode(errors="replace")).strip()

    @staticmethod
    def _summarize(email: str, raw: str) -> str:
        """Keep the [+] used-account lines; count them in the header."""
        if raw.startswith("[timeout]"):
            return raw
        used = [ln.rstrip() for ln in raw.splitlines() if ln.strip().startswith("[+]")]
        header = f"holehe: {len(used)} site(s) with an account for {email}"
        if not used:
            # No [+] lines — either truly none, or --only-used suppressed everything.
            return f"{header} — none found among the checked sites."
        return f"{header}\n\n" + "\n".join(used)
