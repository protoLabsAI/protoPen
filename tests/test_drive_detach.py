"""Detaching a goal drive — the headless half of drive-in-a-chat-tab (P2).

A drive is an active goal bound to a chat session. Its iterations are pumped by
whoever holds the stream, so closing the console tab would strand the goal.
``detach_drive`` hands it to the scheduler as a one-shot continuation job on the
same session, which fires back through the A2A loopback with ``origin="scheduler"``
→ the finished turn pushes over ``chat.resumed`` for a re-attaching console.

Covered here with a fake scheduler (the real one is exercised in
tests/test_scheduler.py) plus the real GoalController/GoalStore.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace as NS

from fastapi import FastAPI
from fastapi.testclient import TestClient

from graph.goals.controller import GoalController
from graph.goals.store import GoalStore
from operator_api.drives import DETACH_PROMPT, cancel_detach, detach_drive, job_id_for
from operator_api.routes import register_operator_routes


class FakeJob:
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def as_dict(self):
        return dict(self.__dict__)


class FakeScheduler:
    """Mirrors LocalScheduler's contract: duplicate ids are rejected, so a repeat
    detach MUST cancel first or it would raise."""

    def __init__(self):
        self.jobs: dict[str, FakeJob] = {}
        self.canceled: list[str] = []

    def add_job(self, prompt, schedule, *, job_id=None, context_id=None):
        if job_id in self.jobs:
            raise ValueError(f"job id {job_id!r} already exists")
        job = FakeJob(id=job_id, prompt=prompt, schedule=schedule, context_id=context_id)
        self.jobs[job_id] = job
        return job

    def cancel_job(self, job_id):
        self.canceled.append(job_id)
        return self.jobs.pop(job_id, None) is not None


def _ctrl(tmp_path):
    return GoalController(NS(goals_max_iterations=10), GoalStore(str(tmp_path)))


def test_detach_schedules_a_continuation_on_the_same_session(tmp_path):
    ctrl = _ctrl(tmp_path)
    asyncio.run(ctrl.parse_control("/goal find a critical vuln", "chat-1"))
    sched = FakeScheduler()

    result = detach_drive(ctrl, sched, "chat-1")

    assert result["detached"] is True
    assert result["condition"] == "find a critical vuln"
    job = sched.jobs[job_id_for("chat-1")]
    # The session id rides as the context so the resumed turn lands on THIS thread.
    assert job.context_id == "chat-1"
    assert job.prompt == DETACH_PROMPT
    # One-shot ISO schedule in the near future (not a cron) — fires once, then dies.
    fires_at = datetime.fromisoformat(job.schedule)
    assert 0 < (fires_at - datetime.now(UTC)).total_seconds() <= 60


def test_detach_leaves_the_goal_set(tmp_path):
    # Detach is not clear: the goal must survive so the woken turn drives it.
    ctrl = _ctrl(tmp_path)
    asyncio.run(ctrl.parse_control("/goal keep going", "chat-1"))
    detach_drive(ctrl, FakeScheduler(), "chat-1")
    assert ctrl.active_goal("chat-1") is not None


def test_detach_twice_replaces_the_pending_job(tmp_path):
    ctrl = _ctrl(tmp_path)
    asyncio.run(ctrl.parse_control("/goal keep going", "chat-1"))
    sched = FakeScheduler()

    detach_drive(ctrl, sched, "chat-1")
    detach_drive(ctrl, sched, "chat-1")  # would raise on a duplicate id without the cancel

    assert len(sched.jobs) == 1
    assert sched.canceled.count(job_id_for("chat-1")) == 2


def test_detach_without_an_active_goal_is_a_no_op(tmp_path):
    sched = FakeScheduler()
    result = detach_drive(_ctrl(tmp_path), sched, "chat-plain")
    assert result["detached"] is False
    assert "no active goal" in result["reason"]
    assert sched.jobs == {}


def test_detach_of_a_finished_goal_is_a_no_op(tmp_path):
    ctrl = _ctrl(tmp_path)
    asyncio.run(ctrl.parse_control("/goal done thing", "chat-1"))
    state = ctrl.store.get("chat-1")
    state.status = "achieved"
    ctrl.store.set(state)

    assert detach_drive(ctrl, FakeScheduler(), "chat-1")["detached"] is False


def test_cancel_detach_drops_the_pending_job(tmp_path):
    # Clearing a goal must take its continuation job with it — otherwise the job
    # outlives the goal and wakes the agent to "continue" nothing.
    ctrl = _ctrl(tmp_path)
    asyncio.run(ctrl.parse_control("/goal keep going", "chat-1"))
    sched = FakeScheduler()
    detach_drive(ctrl, sched, "chat-1")

    assert cancel_detach(sched, "chat-1") is True
    assert sched.jobs == {}
    assert cancel_detach(sched, "chat-1") is False  # idempotent


def test_cancel_detach_tolerates_no_scheduler():
    assert cancel_detach(None, "chat-1") is False


def test_job_id_is_deterministic_and_filesystem_safe():
    assert job_id_for("chat-1") == job_id_for("chat-1")
    assert job_id_for("../../etc/passwd") == "goal-drive-.._.._etc_passwd"


# ── the console-facing routes ────────────────────────────────────────────────


async def _unused(*_a, **_k):  # pragma: no cover - placeholder callable
    return ""


def _client(**callbacks):
    app = FastAPI()
    register_operator_routes(
        app,
        runtime_status=lambda: {},
        subagent_list=lambda: [],
        subagent_run=_unused,
        subagent_batch=_unused,
        **callbacks,
    )
    return TestClient(app)


def test_detach_route_returns_the_handler_payload():
    client = _client(goal_detach=lambda sid: {"detached": True, "condition": f"goal on {sid}"})
    resp = client.post("/api/goal/chat-1/detach")
    assert resp.status_code == 200
    assert resp.json() == {"detached": True, "condition": "goal on chat-1"}


def test_detach_route_409s_when_goal_mode_is_unavailable():
    # No handler wired (goal mode off) → a clear 409, not a 500 or a silent lie.
    assert _client().post("/api/goal/chat-1/detach").status_code == 409


def test_chat_history_route_returns_the_transcript():
    async def history(session_id: str):
        return {
            "session_id": session_id,
            "messages": [
                {"role": "user", "content": "find a critical vuln"},
                {"role": "assistant", "content": "scanning…"},
            ],
        }

    resp = _client(chat_history=history).get("/api/chat/chat-1/history")
    assert resp.status_code == 200
    body = resp.json()
    assert body["session_id"] == "chat-1"
    assert [m["role"] for m in body["messages"]] == ["user", "assistant"]


def test_chat_history_route_is_empty_without_a_checkpointer():
    # Attaching to a session with no readable transcript is not an error — the
    # live turns are the point; the tab just opens empty.
    resp = _client().get("/api/chat/chat-1/history")
    assert resp.status_code == 200
    assert resp.json()["messages"] == []
