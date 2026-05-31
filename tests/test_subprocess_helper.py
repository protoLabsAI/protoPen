"""communicate_or_kill — the shared hang-proof subprocess timeout helper."""

from __future__ import annotations

import asyncio
import sys

from tools._subprocess import communicate_or_kill


def test_timeout_returns_none_and_kills_child(tmp_path):
    """A child that outlives the timeout must not wedge the caller: the helper
    returns None within the cap and the child is killed (regression for the
    wait_for(communicate()) cancel-hang)."""
    sleeper = [sys.executable, "-c", "import time; time.sleep(120)"]

    async def go():
        proc = await asyncio.create_subprocess_exec(
            *sleeper,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Outer guard trips (and fails the test) if the helper itself hangs.
        result = await asyncio.wait_for(communicate_or_kill(proc, timeout=1), timeout=15)
        return result, proc

    result, proc = asyncio.run(go())
    assert result is None
    assert proc.returncode is not None  # reaped, not a zombie


def test_success_returns_stdout_stderr():
    prog = [sys.executable, "-c", "import sys; sys.stdout.write('out'); sys.stderr.write('err')"]

    async def go():
        proc = await asyncio.create_subprocess_exec(
            *prog,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return await communicate_or_kill(proc, timeout=15)

    result = asyncio.run(go())
    assert result is not None
    stdout, stderr = result
    assert stdout == b"out"
    assert stderr == b"err"


def test_input_is_forwarded():
    cat = [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read().upper())"]

    async def go():
        proc = await asyncio.create_subprocess_exec(
            *cat,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return await communicate_or_kill(proc, timeout=15, input=b"hello")

    result = asyncio.run(go())
    assert result is not None
    stdout, _ = result
    assert stdout == b"HELLO"
