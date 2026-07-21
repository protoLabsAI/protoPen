"""Chat-stream robustness (server/chat.py) — port protoAgent #1410 + #1394.

- Per-thread_id lock serializes concurrent same-session A2A turns so they can't
  lost-update each other's checkpointer history.
- Empty-answer fallback: a turn that streams no text surfaces the last tool output
  (or a placeholder) instead of a silent blank bubble.
- Subagent stream isolation: model-stream chunks tagged with parent_task_id (a
  subagent run) never reach the lead answer.
"""

from __future__ import annotations

import asyncio

import pytest

from runtime.state import STATE
from server.chat import _EMPTY_ANSWER_PLACEHOLDER, _chat_langgraph_stream, _thread_lock


# --- #1410: per-thread lock -------------------------------------------------


def test_thread_lock_same_id_shared_distinct_id_separate():
    a1 = _thread_lock("a2a:s1")
    a2 = _thread_lock("a2a:s1")
    b = _thread_lock("a2a:s2")
    assert a1 is a2  # same thread → same lock
    assert a1 is not b  # different threads never contend


def test_thread_lock_serializes_same_thread():
    """Two coroutines on the same thread_id run mutually exclusive; the second only
    enters after the first releases."""
    order: list[str] = []

    async def worker(tag: str, hold: float):
        async with _thread_lock("a2a:same"):
            order.append(f"{tag}-enter")
            await asyncio.sleep(hold)
            order.append(f"{tag}-exit")

    async def scenario():
        await asyncio.gather(worker("A", 0.02), worker("B", 0.0))

    asyncio.run(scenario())
    # Whichever wins, one fully completes before the other enters (no interleave).
    assert order in (
        ["A-enter", "A-exit", "B-enter", "B-exit"],
        ["B-enter", "B-exit", "A-enter", "A-exit"],
    )


# --- driving _chat_langgraph_stream with a fake graph -----------------------


class _Chunk:
    def __init__(self, content: str):
        self.content = content


class _FakeGraph:
    """A stand-in for STATE.graph whose astream_events replays crafted events."""

    def __init__(self, events: list[dict]):
        self._events = events

    async def astream_events(self, *_a, **_k):
        for e in self._events:
            yield e


def _model_stream(content: str, *, parent_task_id: str | None = None) -> dict:
    md = {"parent_task_id": parent_task_id} if parent_task_id else {}
    return {"event": "on_chat_model_stream", "name": "model", "metadata": md, "data": {"chunk": _Chunk(content)}}


def _tool_end(output: str) -> dict:
    return {"event": "on_tool_end", "name": "some_tool", "run_id": "r1", "data": {"output": output}}


def _drive(events: list[dict], monkeypatch) -> list[tuple]:
    monkeypatch.setattr(STATE, "goal_controller", None, raising=False)
    monkeypatch.setattr(STATE, "graph", _FakeGraph(events), raising=False)

    async def run():
        return [frame async for frame in _chat_langgraph_stream("hi", "sX", interactive=False)]

    return asyncio.run(run())


def test_empty_answer_falls_back_to_last_tool_output(monkeypatch):
    """No text streamed, but a tool ran → the done frame carries the tool output."""
    frames = _drive([_tool_end("scan found 2 open ports")], monkeypatch)
    done = [p for k, p in frames if k == "done"]
    assert done == ["scan found 2 open ports"]
    assert not any(k == "text" for k, _ in frames)  # nothing textual streamed


def test_empty_answer_uses_placeholder_when_nothing(monkeypatch):
    """No text and no tool output → a placeholder, not a blank bubble."""
    frames = _drive([], monkeypatch)
    assert [p for k, p in frames if k == "done"] == [_EMPTY_ANSWER_PLACEHOLDER]


def test_subagent_tokens_suppressed_from_lead_stream(monkeypatch):
    """A model chunk tagged parent_task_id (a subagent) never reaches the lead answer;
    the lead's own token does (port #1394)."""
    frames = _drive(
        [
            _model_stream("SUBAGENT-INTERNAL", parent_task_id="task-7"),
            _model_stream("lead answer"),
        ],
        monkeypatch,
    )
    text = "".join(p for k, p in frames if k == "text")
    assert text == "lead answer"  # subagent token filtered out
    assert "SUBAGENT-INTERNAL" not in text
    assert [p for k, p in frames if k == "done"] == ["lead answer"]
