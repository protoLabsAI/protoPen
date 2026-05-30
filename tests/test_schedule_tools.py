"""Agent-facing scheduler tools (schedule_task / list_schedules / cancel_schedule)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from tools.lg_tools import (
    cancel_schedule,
    get_security_tools,
    list_schedules,
    schedule_task,
    set_scheduler,
)


class _FakeScheduler:
    name = "local"

    def __init__(self):
        self.jobs = []

    def add_job(self, prompt, schedule, *, job_id=None):
        job = SimpleNamespace(
            id=job_id or "job-1", prompt=prompt, schedule=schedule, next_fire="2030-01-01T09:00:00+00:00"
        )
        self.jobs.append(job)
        return job

    def list_jobs(self):
        return list(self.jobs)

    def cancel_job(self, job_id):
        before = len(self.jobs)
        self.jobs = [j for j in self.jobs if j.id != job_id]
        return len(self.jobs) < before


def _call(tool, **kwargs):
    """Invoke a @tool's underlying callable — robust across langchain versions
    (StructuredTool exposes the original via .coroutine / .func; otherwise it's
    a plain function)."""
    fn = getattr(tool, "coroutine", None) or getattr(tool, "func", None) or tool
    res = fn(**kwargs)
    return asyncio.run(res) if asyncio.iscoroutine(res) else res


def _tool_name(tool) -> str:
    return getattr(tool, "name", getattr(tool, "__name__", ""))


def test_schedule_task_creates_job():
    set_scheduler(_FakeScheduler())
    try:
        out = _call(schedule_task, prompt="scan", when="0 9 * * *")
        assert out.startswith("Scheduled job job-1 next at 2030-01-01T09:00:00")
    finally:
        set_scheduler(None)


def test_list_and_cancel():
    set_scheduler(_FakeScheduler())
    try:
        assert _call(list_schedules) == "No scheduled jobs."
        _call(schedule_task, prompt="sweep the LAN", when="0 9 * * *", job_id="j7")
        listing = _call(list_schedules)
        assert "j7" in listing and "sweep the LAN" in listing
        assert _call(cancel_schedule, job_id="j7") == "Canceled j7."
        assert _call(cancel_schedule, job_id="nope").startswith("Error:")
    finally:
        set_scheduler(None)


def test_malformed_schedule_returns_error():
    class _Raises(_FakeScheduler):
        def add_job(self, *a, **k):
            raise ValueError("invalid schedule")

    set_scheduler(_Raises())
    try:
        assert _call(schedule_task, prompt="x", when="bad") == "Error: invalid schedule"
    finally:
        set_scheduler(None)


def test_tools_report_when_scheduler_unavailable():
    set_scheduler(None)
    assert "not available" in _call(schedule_task, prompt="x", when="0 9 * * *")
    assert "not available" in _call(list_schedules)
    assert "not available" in _call(cancel_schedule, job_id="x")


def test_tools_registered_in_security_tools():
    names = {_tool_name(t) for t in get_security_tools(None)}
    assert {"schedule_task", "list_schedules", "cancel_schedule"} <= names
