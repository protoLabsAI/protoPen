from __future__ import annotations

import asyncio

from operator_api.agent_runtime import AgentRegistry


async def _ok() -> str:
    return "result-text"


async def _boom() -> str:
    raise RuntimeError("kaboom")


async def _long() -> str:
    await asyncio.sleep(10)
    return "never"


def test_launch_completes_with_output() -> None:
    async def scenario():
        reg = AgentRegistry()
        rid = reg.launch(_ok, agent_type="researcher", description="scan")
        await reg._runs[rid].task
        return reg.get(rid)

    snap = asyncio.run(scenario())
    assert snap["status"] == "done"
    assert snap["output"] == "result-text"
    assert snap["duration_ms"] >= 0


def test_launch_captures_error() -> None:
    async def scenario():
        reg = AgentRegistry()
        rid = reg.launch(_boom, agent_type="x", description="d")
        await reg._runs[rid].task
        return reg.get(rid)

    snap = asyncio.run(scenario())
    assert snap["status"] == "error"
    assert "kaboom" in snap["error"]


def test_cancel_running_marks_cancelled() -> None:
    async def scenario():
        reg = AgentRegistry()
        rid = reg.launch(_long, agent_type="x", description="d")
        await asyncio.sleep(0)  # let the task start
        cancelled = reg.cancel(rid)
        try:
            await reg._runs[rid].task
        except asyncio.CancelledError:
            pass
        return cancelled, reg.get(rid)

    cancelled, snap = asyncio.run(scenario())
    assert cancelled is True
    assert snap["status"] == "cancelled"


def test_cancel_unknown_or_finished_returns_false() -> None:
    async def scenario():
        reg = AgentRegistry()
        unknown = reg.cancel("nope")
        rid = reg.launch(_ok, agent_type="x", description="d")
        await reg._runs[rid].task
        return unknown, reg.cancel(rid)

    unknown, finished = asyncio.run(scenario())
    assert unknown is False
    assert finished is False  # already done


def test_snapshot_is_newest_first() -> None:
    async def scenario():
        reg = AgentRegistry()
        r1 = reg.launch(_ok, agent_type="a", description="1")
        r2 = reg.launch(_ok, agent_type="b", description="2")
        await reg._runs[r1].task
        await reg._runs[r2].task
        return r1, r2, [s["id"] for s in reg.snapshot()]

    r1, r2, ids = asyncio.run(scenario())
    assert ids[0] == r2
    assert ids[1] == r1


def test_get_unknown_returns_none() -> None:
    assert AgentRegistry().get("missing") is None


def test_prune_caps_finished_history() -> None:
    async def scenario():
        reg = AgentRegistry(max_history=3)
        ids = []
        for i in range(5):
            rid = reg.launch(_ok, agent_type="x", description=str(i))
            await reg._runs[rid].task
            ids.append(rid)
        return ids, [s["id"] for s in reg.snapshot()]

    ids, snap_ids = asyncio.run(scenario())
    assert len(snap_ids) <= 3
    assert ids[0] not in snap_ids  # oldest finished run evicted
