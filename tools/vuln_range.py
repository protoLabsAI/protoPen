"""Vuln-range workbench tool for protoPen.

The generalized primitive a real vuln researcher uses: a shell in an ISOLATED container with
the target's source + a sanitizer build. The agent reads /src, builds (`secb build`), runs its
candidate PoC, reads the AddressSanitizer/UBSan output, and iterates — a real find→prove loop.

Execution happens inside the detonation-range VM (hardware-isolated, no egress), one persistent
container per target so builds/edits survive across calls. This tool is the agent's WORKBENCH
only; scoring is done independently by the range's /detonate verifier (the agent cannot reach it,
so it cannot game its own reward) — mirrors SEC-bench's separation of solver and checker.

Env:
  RANGE_URL   base URL of the range daemon. Default is the tailnet forward
              (https://protolabs.taild25506.ts.net:8446 → range VM), reachable from any
              protoPen node. Override with http://10.99.9.56:8443 when running on the range host.

Authorized use only — the operator's own isolated range, security research.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from typing import Any

import httpx

from tools._tool_base import Tool

_RANGE_URL = os.environ.get("RANGE_URL", "https://protolabs.taild25506.ts.net:8446")
_TIMEOUT = 120


def _session_for(image: str) -> str:
    """One persistent workbench container per target image (per protoPen instance)."""
    return "pp-" + hashlib.sha1(image.encode()).hexdigest()[:16]


class VulnRangeTool(Tool):
    """Isolated sandbox shell for vulnerability research against a staged target."""

    @property
    def name(self) -> str:
        return "vuln_range"

    @property
    def description(self) -> str:
        return (
            "Isolated workbench for memory-safety vulnerability research on a staged target "
            "(C/C++ source built with sanitizers). One persistent container per target image; "
            "your builds and files persist across calls. Actions:\n"
            "- exec:  run a shell command in the sandbox (read /src, `secb build`, run the "
            "binary against your candidate input, read the AddressSanitizer/UBSan output).\n"
            "- write: write bytes to a file in the sandbox (base64) — for crafting binary PoC "
            "inputs that are awkward to echo.\n"
            "- reset: tear the container down and start fresh.\n"
            "Craft an input that makes the sanitizer fire on the target vulnerability; run it "
            "here to confirm the crash before you report the PoC."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["exec", "write", "reset"]},
                "target_image": {
                    "type": "string",
                    "description": "The staged target image (given in your task), e.g. "
                    "localhost:5000/secb.mruby.cve-2022-0631.built",
                },
                "cmd": {"type": "string", "description": "Shell command (action=exec)."},
                "workdir": {"type": "string", "description": "Working directory (action=exec)."},
                "path": {"type": "string", "description": "File path to write (action=write)."},
                "content_b64": {
                    "type": "string",
                    "description": "Base64 of the bytes to write (action=write).",
                },
                "timeout_s": {"type": "integer", "description": "Per-command timeout (default 60)."},
            },
            "required": ["action", "target_image"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action")
        image = kwargs.get("target_image", "")
        if not image:
            return "Error: target_image is required."
        session = _session_for(image)
        timeout = int(kwargs.get("timeout_s") or 60)

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                if action == "exec":
                    cmd = kwargs.get("cmd")
                    if not cmd:
                        return "Error: exec requires 'cmd'."
                    r = await client.post(
                        f"{_RANGE_URL}/exec",
                        json={
                            "target_image": image,
                            "session": session,
                            "cmd": cmd,
                            "workdir": kwargs.get("workdir"),
                            "timeout_s": timeout,
                        },
                    )
                    return _fmt_exec(r)

                if action == "write":
                    path, c64 = kwargs.get("path"), kwargs.get("content_b64")
                    if not path or c64 is None:
                        return "Error: write requires 'path' and 'content_b64'."
                    try:
                        base64.b64decode(c64, validate=True)
                    except Exception:
                        return "Error: content_b64 is not valid base64."
                    # write via the sandbox itself (decode in-container → binary-safe)
                    cmd = (
                        f'mkdir -p "$(dirname {_sh(path)})" && '
                        f"printf %s {_sh(c64)} | base64 -d > {_sh(path)} && "
                        f"wc -c < {_sh(path)}"
                    )
                    r = await client.post(
                        f"{_RANGE_URL}/exec",
                        json={"target_image": image, "session": session, "cmd": cmd, "timeout_s": timeout},
                    )
                    d = r.json()
                    if d.get("exit_code") == 0:
                        return f"wrote {d.get('stdout', '').strip()} bytes to {path}"
                    return f"write failed: {d.get('stderr') or d.get('error')}"

                if action == "reset":
                    await client.post(f"{_RANGE_URL}/exec/end", json={"session": session})
                    return f"sandbox reset for {image}"

                return f"Unknown action: {action}. Available: exec, write, reset."
        except httpx.HTTPError as e:
            return f"range unreachable ({_RANGE_URL}): {e}"


def _sh(s: str) -> str:
    """Single-quote a string for POSIX sh."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def _fmt_exec(r: httpx.Response) -> str:
    d = r.json()
    if "error" in d:
        return f"range error: {d['error']}"
    out, err = d.get("stdout", ""), d.get("stderr", "")
    parts = [
        f"[exit {d.get('exit_code')}"
        + (" TIMED OUT" if d.get("timed_out") else "")
        + ("  (new sandbox)" if d.get("created") else "")
        + "]"
    ]
    if out:
        parts.append(out.rstrip())
    if err:
        parts.append("--- stderr ---\n" + err.rstrip())
    return "\n".join(parts)[:8000] or "[no output]"
