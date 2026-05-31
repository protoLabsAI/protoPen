"""Tests for the checkpoint pruner (per-thread cap + age TTL)."""

from __future__ import annotations

import asyncio
import sqlite3
import time

from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import END, START, MessagesState, StateGraph

from graph.checkpoint_prune import prune_checkpoints, uuidv6_unix_seconds
from graph.checkpointer import build_sqlite_checkpointer


def _graph(saver):
    g = StateGraph(MessagesState)
    g.add_node("n", lambda s: {"messages": [AIMessage(content="ok")]})
    g.add_edge(START, "n")
    g.add_edge("n", END)
    return g.compile(checkpointer=saver)


def _count(db, table, thread_id=None):
    conn = sqlite3.connect(db)
    try:
        if thread_id:
            return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE thread_id=?", (thread_id,)).fetchone()[0]
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def _seed(db, threads=("A", "B"), turns=3):
    async def main():
        app = _graph(build_sqlite_checkpointer(db))
        for t in threads:
            for i in range(turns):
                await app.ainvoke(
                    {"messages": [HumanMessage(content=f"{t}{i}")]},
                    {"configurable": {"thread_id": t}},
                )

    asyncio.run(main())


def test_uuidv6_timestamp_decode_is_sane(tmp_path):
    # A real checkpoint id (LangGraph generates v6) should decode to ~now.
    db = str(tmp_path / "c.db")
    _seed(db, threads=("A",), turns=1)
    conn = sqlite3.connect(db)
    cid = conn.execute("SELECT checkpoint_id FROM checkpoints LIMIT 1").fetchone()[0]
    conn.close()
    ts = uuidv6_unix_seconds(cid)
    assert ts is not None and abs(ts - time.time()) < 30
    assert uuidv6_unix_seconds("not-a-uuid") is None


def test_per_thread_cap_keeps_latest(tmp_path):
    db = str(tmp_path / "c.db")
    _seed(db, threads=("A", "B"), turns=3)  # ~9 checkpoints/thread
    before = _count(db, "checkpoints", "A")
    assert before > 2
    res = prune_checkpoints(db, keep_per_thread=2, max_age_seconds=None)
    assert _count(db, "checkpoints", "A") == 2
    assert _count(db, "checkpoints", "B") == 2
    assert res["checkpoints_deleted"] == (before - 2) * 2  # both threads trimmed


def test_age_ttl_drops_old_threads(tmp_path):
    db = str(tmp_path / "c.db")
    _seed(db, threads=("A",), turns=2)
    # now far in the future → every thread is "old" → TTL'd whole.
    res = prune_checkpoints(db, keep_per_thread=5, max_age_seconds=1, now=time.time() + 10_000)
    assert res["threads_deleted"] == 1
    assert _count(db, "checkpoints") == 0


def test_pruned_thread_can_still_resume(tmp_path):
    """Keeping the latest checkpoint must preserve resume — history continues."""
    db = str(tmp_path / "c.db")
    _seed(db, threads=("A",), turns=3)
    prune_checkpoints(db, keep_per_thread=1, max_age_seconds=None)

    async def resume_len():
        app = _graph(build_sqlite_checkpointer(db))
        cfg = {"configurable": {"thread_id": "A"}}
        before = await app.aget_state(cfg)
        await app.ainvoke({"messages": [HumanMessage(content="more")]}, cfg)
        after = await app.aget_state(cfg)
        return len(before.values["messages"]), len(after.values["messages"])

    b, a = asyncio.run(resume_len())
    assert b >= 1 and a > b  # state survived the prune and kept accumulating
