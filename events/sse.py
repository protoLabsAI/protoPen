"""SSE framing for the server→client event stream (ADR 0003)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from typing import Any


async def sse_event_stream(
    subscribe: Callable[[], AsyncIterator[dict[str, Any]]],
    *,
    keepalive_s: float = 15.0,
) -> AsyncIterator[str]:
    """Frame bus events as SSE text for the ``/api/events`` response.

    Emits a ``: connected`` comment up front (so the client's ``onopen`` fires),
    then one ``event:``/``data:`` frame per published event, with periodic
    ``: keepalive`` comments to hold the connection open through idle stretches.
    """
    yield ": connected\n\n"
    agen = subscribe()
    try:
        while True:
            try:
                evt = await asyncio.wait_for(agen.__anext__(), timeout=keepalive_s)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue
            except StopAsyncIteration:
                break
            yield f"event: {evt['event']}\ndata: {json.dumps(evt['data'])}\n\n"
    finally:
        await agen.aclose()
