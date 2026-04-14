"""Service enumeration — enum4linux, rpcclient, smbclient structured wrappers."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from tools.parsers import ingest_output
from tools._tool_base import Tool

logger = logging.getLogger(__name__)


class ServiceEnumTool(Tool):
    """Service enumeration — enum4linux, SMB, RPC wrappers."""

    def __init__(self, workspace: str = "/tmp/protopen"):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None

    @property
    def name(self) -> str:
        return "service_enum"

    @property
    def description(self) -> str:
        return (
            "Service enumeration tools. enum4linux for Windows/Samba hosts, "
            "smbclient for share listing, rpcclient for RPC info."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": [
                        "enum4linux_full",
                        "smb_shares",
                        "smb_list",
                        "rpc_info",
                        "rpc_users",
                    ],
                },
                "target": {"type": "string", "description": "Target IP or hostname"},
                "share": {"type": "string", "description": "SMB share name (for smb_list)"},
                "username": {"type": "string", "description": "Username for auth"},
                "password": {"type": "string", "description": "Password for auth"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 120)"},
            },
            "required": ["action", "target"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        target = kwargs.get("target", "")
        user = kwargs.get("username", "")
        pw = kwargs.get("password", "")
        share = kwargs.get("share", "")
        timeout = kwargs.get("timeout", 120)

        dispatch = {
            "enum4linux_full": lambda: self.enum4linux_full(target, timeout),
            "smb_shares": lambda: self.smb_shares(target, user, pw, timeout),
            "smb_list": lambda: self.smb_list(target, share, user, pw, timeout),
            "rpc_info": lambda: self.rpc_info(target, timeout),
            "rpc_users": lambda: self.rpc_users(target, timeout),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            result = await fn()
            ingest_output("service_enum", action, result, self._target_store)
            return result
        except Exception as exc:
            return f"service_enum error ({action}): {exc}"

    async def _run(self, *args: str, timeout: int = 120) -> str:
        logger.info("Running: %s", " ".join(args))
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return f"Command timed out after {timeout}s: {' '.join(args)}"
        output = stdout.decode(errors="replace")
        if stderr:
            output += f"\n[stderr] {stderr.decode(errors='replace')}"
        return output.strip()

    async def enum4linux_full(self, target: str, timeout: int = 120) -> str:
        return await self._run("enum4linux", "-a", target, timeout=timeout)

    async def smb_shares(self, target: str, username: str = "", password: str = "", timeout: int = 60) -> str:
        args = ["smbclient", "-L", target, "-N"]
        if username:
            args.extend(["-U", f"{username}%{password}"])
        return await self._run(*args, timeout=timeout)

    async def smb_list(self, target: str, share: str, username: str = "", password: str = "", timeout: int = 60) -> str:
        path = f"//{target}/{share}"
        args = ["smbclient", path, "-N", "-c", "ls"]
        if username:
            args.extend(["-U", f"{username}%{password}"])
        return await self._run(*args, timeout=timeout)

    async def rpc_info(self, target: str, timeout: int = 60) -> str:
        return await self._run(
            "rpcclient",
            "-U",
            "",
            "-N",
            target,
            "-c",
            "srvinfo",
            timeout=timeout,
        )

    async def rpc_users(self, target: str, timeout: int = 60) -> str:
        return await self._run(
            "rpcclient",
            "-U",
            "",
            "-N",
            target,
            "-c",
            "enumdomusers",
            timeout=timeout,
        )
