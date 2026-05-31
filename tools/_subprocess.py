"""Hang-proof subprocess timeout helper shared by the tool wrappers.

Every tool that shells out needs the same thing: run a child with a wall-clock
cap that ALWAYS returns, even if the child wedges. The obvious idiom —
``asyncio.wait_for(proc.communicate(), timeout)`` — is a trap: on timeout
``wait_for`` cancels ``communicate()``, and cancelling it while the child is
still alive can hang *inside* ``wait_for``, so a ``proc.kill()`` in an
``except`` branch never runs and the whole agent turn freezes.

``communicate_or_kill`` uses the kill-first idiom instead: race ``communicate()``
against the timeout with ``asyncio.wait`` (no cancellation); on timeout kill the
child FIRST so its pipes close, then ``await`` the already-running
``communicate()`` to drain at EOF and reap it. No cancellation, no hang, no
zombie.

Banned pattern is enforced by scripts/check_subprocess_timeout.py; this helper
is the sanctioned replacement.
"""

from __future__ import annotations

import asyncio


async def communicate_or_kill(
    proc: asyncio.subprocess.Process,
    timeout: float,
    *,
    input: bytes | None = None,
) -> tuple[bytes, bytes] | None:
    """Run ``proc.communicate(input)`` with a hang-proof wall-clock timeout.

    Returns ``(stdout, stderr)`` on success, or ``None`` if the call timed out —
    in which case the child has been killed and reaped. Callers decide what a
    timeout means (their own message / return shape).
    """
    comm = asyncio.ensure_future(proc.communicate(input))
    done, _pending = await asyncio.wait({comm}, timeout=timeout)
    if comm not in done:
        proc.kill()
        try:
            await comm  # drains to EOF + reaps now that the child's stdout is closed
        except Exception:
            pass
        return None
    return comm.result()
