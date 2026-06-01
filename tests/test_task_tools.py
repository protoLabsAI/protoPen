"""Agent-facing task-tracker tools (create_task / list_tasks / update_task /
close_task) — thin async wrappers over BeadsService."""

from __future__ import annotations

import asyncio

from tools.lg_tools import (
    close_task,
    create_task,
    get_security_tools,
    list_tasks,
    set_beads,
    update_task,
)


class _FakeBeads:
    """Stand-in for BeadsService — records calls, returns issue dicts."""

    def __init__(self):
        self.created: list[dict] = []
        self.updates: list[tuple] = []
        self.closed: list[tuple] = []
        self.issues: list[dict] = []

    def create(self, project_path, issue):
        out = {"id": "protopen-1", "title": issue["title"], "status": "open", "priority": issue.get("priority", 2)}
        self.created.append(issue)
        return out

    def list(self, project_path):
        return list(self.issues)

    def update(self, project_path, issue_id, update):
        self.updates.append((issue_id, update))
        return {"id": issue_id, "status": update.get("status", "open"), "priority": update.get("priority", 2)}

    def close(self, project_path, issue_id, reason=None):
        self.closed.append((issue_id, reason))
        return {"id": issue_id, "status": "closed"}


def _call(tool, **kwargs):
    fn = getattr(tool, "coroutine", None) or getattr(tool, "func", None) or tool
    res = fn(**kwargs)
    return asyncio.run(res) if asyncio.iscoroutine(res) else res


def _tool_name(tool) -> str:
    return getattr(tool, "name", getattr(tool, "__name__", ""))


def test_create_task_passes_fields_and_reports_id():
    fake = _FakeBeads()
    set_beads(fake, "/proj")
    try:
        out = _call(create_task, title="monitor 10.0.0.0/24", description="watch for new hosts", priority=1)
        assert "protopen-1" in out
        assert fake.created[0]["title"] == "monitor 10.0.0.0/24"
        assert fake.created[0]["priority"] == 1
        assert fake.created[0]["type"] == "task"
    finally:
        set_beads(None, "")


def test_create_task_requires_title():
    set_beads(_FakeBeads(), "/proj")
    try:
        assert _call(create_task, title="   ").startswith("Error:")
    finally:
        set_beads(None, "")


def test_list_tasks_filters_by_status():
    fake = _FakeBeads()
    fake.issues = [
        {"id": "a", "status": "open", "priority": 2, "title": "x"},
        {"id": "b", "status": "in_progress", "priority": 1, "title": "y"},
    ]
    set_beads(fake, "/proj")
    try:
        all_out = _call(list_tasks)
        assert "a" in all_out and "b" in all_out
        filtered = _call(list_tasks, status="in_progress")
        assert "b" in filtered and "a" not in filtered
        assert "No tasks" in _call(list_tasks, status="closed")
    finally:
        set_beads(None, "")


def test_update_task_requires_a_field():
    fake = _FakeBeads()
    set_beads(fake, "/proj")
    try:
        assert _call(update_task, task_id="protopen-1").startswith("Error: nothing to update")
        out = _call(update_task, task_id="protopen-1", status="in_progress")
        assert fake.updates[0] == ("protopen-1", {"status": "in_progress"})
        assert "in_progress" in out
    finally:
        set_beads(None, "")


def test_close_task():
    fake = _FakeBeads()
    set_beads(fake, "/proj")
    try:
        out = _call(close_task, task_id="protopen-1", reason="done")
        assert fake.closed == [("protopen-1", "done")]
        assert "Closed task protopen-1" in out
    finally:
        set_beads(None, "")


def test_tools_report_when_tracker_unavailable():
    set_beads(None, "")
    assert "not available" in _call(create_task, title="x")
    assert "not available" in _call(list_tasks)
    assert "not available" in _call(update_task, task_id="x", status="open")
    assert "not available" in _call(close_task, task_id="x")


def test_tools_registered_in_security_tools():
    names = {_tool_name(t) for t in get_security_tools(None)}
    assert {"create_task", "list_tasks", "update_task", "close_task"} <= names
