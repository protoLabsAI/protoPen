"""Tests for the in-process event bus + /api/events SSE framing (ADR 0003)."""

from __future__ import annotations

import asyncio

from events.bus import EventBus


def test_publish_fans_out_to_all_subscribers():
    async def run():
        bus = EventBus()
        a = bus.subscribe()
        b = bus.subscribe()
        ta = asyncio.ensure_future(a.__anext__())
        tb = asyncio.ensure_future(b.__anext__())
        await asyncio.sleep(0)  # let the generators register their queues
        bus.publish("hello", {"n": 1})
        ra, rb = await asyncio.wait_for(asyncio.gather(ta, tb), timeout=1)
        await a.aclose()
        await b.aclose()
        return ra, rb

    ra, rb = asyncio.run(run())
    assert ra == {"event": "hello", "data": {"n": 1}}
    assert rb == {"event": "hello", "data": {"n": 1}}


def test_publish_defaults_empty_data():
    async def run():
        bus = EventBus()
        sub = bus.subscribe()
        t = asyncio.ensure_future(sub.__anext__())
        await asyncio.sleep(0)
        bus.publish("ping")
        evt = await asyncio.wait_for(t, timeout=1)
        await sub.aclose()
        return evt

    assert asyncio.run(run()) == {"event": "ping", "data": {}}


def test_drop_oldest_on_overflow():
    async def run():
        bus = EventBus(max_queue=2)
        sub = bus.subscribe()
        t = asyncio.ensure_future(sub.__anext__())
        await asyncio.sleep(0)
        bus.publish("e", {"i": 0})  # satisfies the pending __anext__ immediately
        first = await asyncio.wait_for(t, timeout=1)
        for i in range(1, 5):  # fill (cap 2) then overflow
            bus.publish("e", {"i": i})
        drained = [await asyncio.wait_for(sub.__anext__(), timeout=1) for _ in range(2)]
        await sub.aclose()
        return first, drained

    first, drained = asyncio.run(run())
    assert first == {"event": "e", "data": {"i": 0}}
    assert [d["data"]["i"] for d in drained] == [3, 4]  # oldest dropped, newest survive


def test_unsubscribe_on_close():
    async def run():
        bus = EventBus()
        sub = bus.subscribe()
        t = asyncio.ensure_future(sub.__anext__())
        await asyncio.sleep(0)
        assert bus.subscriber_count() == 1
        bus.publish("x")
        await asyncio.wait_for(t, timeout=1)
        await sub.aclose()
        return bus.subscriber_count()

    assert asyncio.run(run()) == 0


def test_sse_stream_frames_connected_then_event():
    """sse_event_stream emits a `: connected` comment, then event/data frames."""
    from events.sse import sse_event_stream

    async def run():
        bus = EventBus()
        agen = sse_event_stream(bus.subscribe, keepalive_s=5.0)
        first = await agen.__anext__()  # the `: connected` preamble
        # The next frame pulls from the bus — wait until it has subscribed.
        nxt = asyncio.ensure_future(agen.__anext__())
        for _ in range(100):
            if bus.subscriber_count() >= 1:
                break
            await asyncio.sleep(0.01)
        bus.publish("activity.message", {"text": "hi"})
        frame = await asyncio.wait_for(nxt, timeout=1)
        await agen.aclose()
        return first, frame

    first, frame = asyncio.run(run())
    assert first == ": connected\n\n"
    assert frame == 'event: activity.message\ndata: {"text": "hi"}\n\n'
