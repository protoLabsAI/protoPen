"""Provider-stream reconnect helper (graph/llm.py) — port protoAgent #1728.

A rate-limited/flaky gateway can drop the SSE body mid-read (httpcore.ReadError /
httpx.TransportError). ``ChatOpenAI(max_retries)`` only covers request *start*, so
``_stream_with_reconnect`` restarts the model stream when it drops BEFORE emitting
any content, and re-raises once a token has streamed (a fresh stream would dup it).
"""

from __future__ import annotations

import httpcore
import httpx
import pytest

from graph.llm import _stream_with_reconnect


async def _collect(agen):
    return [x async for x in agen]


async def _noop_sleep(_delay):
    return None


@pytest.mark.asyncio
async def test_reconnects_when_drop_before_any_content():
    attempts = {"n": 0}

    async def make_stream():
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise httpx.ReadError("gateway closed the stream")
            yield  # pragma: no cover — unreachable, marks this an async generator
        for tok in ("a", "b", "c"):
            yield tok

    out = await _collect(_stream_with_reconnect(make_stream, max_retries=2, sleep=_noop_sleep))
    assert out == ["a", "b", "c"]
    assert attempts["n"] == 2  # first stream dropped at the top → reconnected once


@pytest.mark.asyncio
async def test_does_not_reconnect_after_a_token_streamed():
    """Once content has emitted, a fresh stream would duplicate it — so re-raise."""
    attempts = {"n": 0}

    async def make_stream():
        attempts["n"] += 1
        yield "partial"
        raise httpcore.ReadError("dropped mid-body after emitting")

    with pytest.raises(httpcore.ReadError):
        await _collect(_stream_with_reconnect(make_stream, max_retries=3, sleep=_noop_sleep))
    assert attempts["n"] == 1  # no reconnect — the emitted token must not be replayed


@pytest.mark.asyncio
async def test_gives_up_after_exhausting_retries():
    attempts = {"n": 0}

    async def make_stream():
        attempts["n"] += 1
        raise httpx.ConnectError("gateway unreachable")
        yield  # pragma: no cover

    with pytest.raises(httpx.ConnectError):
        await _collect(_stream_with_reconnect(make_stream, max_retries=2, sleep=_noop_sleep))
    assert attempts["n"] == 3  # max_retries=2 → 1 initial + 2 reconnects, then give up


@pytest.mark.asyncio
async def test_non_retryable_error_propagates_immediately():
    attempts = {"n": 0}

    async def make_stream():
        attempts["n"] += 1
        raise ValueError("a real bug, not a transport blip")
        yield  # pragma: no cover

    with pytest.raises(ValueError):
        await _collect(_stream_with_reconnect(make_stream, max_retries=3, sleep=_noop_sleep))
    assert attempts["n"] == 1  # not a transport error → no reconnect
