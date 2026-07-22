"""Live-render of self-initiated (resumed) turns — protopen-1hw.11.

A scheduler wake / wait-resume / background push-resume is delivered through the
scheduler's ``/a2a`` loopback, which stamps ``origin="scheduler"`` on the message.
The A2A terminal hook uses that to push a ``chat.resumed`` event for a chat session
(so the console appends the turn live), while leaving the durable Activity thread on
``activity.message`` and NOT re-publishing a normal caller-streamed chat turn.

Covers both halves of the seam:
  - ``a2a_executor._extract_origin`` reads the message ``origin`` metadata.
  - ``server.app._terminal_event`` routes a TurnOutcome to the right live event.
"""

from __future__ import annotations

from types import SimpleNamespace

from a2a_executor import TurnOutcome, _extract_origin
from events import ACTIVITY_CONTEXT
from server.app import _terminal_event


def _outcome(*, context_id: str, text: str = "the agent woke up and did a thing", origin: str = "") -> TurnOutcome:
    return TurnOutcome(
        task_id="t1",
        context_id=context_id,
        state="completed",
        text=text,
        origin=origin,
    )


# ── _extract_origin ──────────────────────────────────────────────────────────


def test_extract_origin_reads_scheduler_metadata():
    # _request_metadata merges context.metadata (a dict) — the scheduler loopback's
    # message metadata surfaces here.
    ctx = SimpleNamespace(message=None, metadata={"origin": "scheduler", "scheduler_job_id": "j1"})
    assert _extract_origin(ctx) == "scheduler"


def test_extract_origin_absent_is_empty():
    ctx = SimpleNamespace(message=None, metadata={})
    assert _extract_origin(ctx) == ""


def test_extract_origin_non_string_is_empty():
    ctx = SimpleNamespace(message=None, metadata={"origin": 7})
    assert _extract_origin(ctx) == ""


def test_turn_outcome_origin_defaults_empty():
    assert _outcome(context_id="chat-1").origin == ""


# ── _terminal_event routing ──────────────────────────────────────────────────


def test_activity_turn_publishes_activity_message():
    ev = _terminal_event(_outcome(context_id=ACTIVITY_CONTEXT))
    assert ev is not None
    name, data = ev
    assert name == "activity.message"
    assert data["role"] == "assistant"
    assert data["context_id"] == ACTIVITY_CONTEXT


def test_self_initiated_chat_turn_publishes_chat_resumed():
    ev = _terminal_event(_outcome(context_id="chat-abc", origin="scheduler"))
    assert ev is not None
    name, data = ev
    assert name == "chat.resumed"
    assert data["session_id"] == "chat-abc"
    assert data["role"] == "assistant"
    assert "woke up" in data["text"]


def test_normal_caller_chat_turn_publishes_nothing():
    # origin="" → the browser is streaming this turn itself; re-publishing would
    # double-render it.
    assert _terminal_event(_outcome(context_id="chat-abc", origin="")) is None


def test_empty_text_publishes_nothing():
    assert _terminal_event(_outcome(context_id=ACTIVITY_CONTEXT, text="   ")) is None
    assert _terminal_event(_outcome(context_id="chat-abc", origin="scheduler", text="")) is None


def test_scheduler_origin_on_activity_thread_stays_activity_message():
    # A plain scheduled task with no wait-context fires with context_id=ACTIVITY
    # AND origin="scheduler"; the Activity branch wins (it's still the Activity feed).
    ev = _terminal_event(_outcome(context_id=ACTIVITY_CONTEXT, origin="scheduler"))
    assert ev is not None and ev[0] == "activity.message"
