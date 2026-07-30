"""Tests for the read-only A2A task view behind /api/tasks (#339).

The endpoint exists because during the #337 runaway ~2,000 turns were executing
while every operator surface read empty. So the properties that matter here are
the ones that keep it honest when things are broken: the state histogram must
cover the whole store (not just the page), and an unreadable store must degrade
to `available: False` rather than a 500.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from operator_api import tasks as tasks_mod


def _store(tmp_path, rows):
    """Build a stand-in a2a-tasks.db with the SDK's column shape."""
    path = tmp_path / "a2a-tasks.db"
    db = sqlite3.connect(str(path))
    db.execute(
        "CREATE TABLE tasks (id TEXT PRIMARY KEY, context_id TEXT, kind TEXT, owner TEXT,"
        " last_updated TEXT, status TEXT, artifacts TEXT, history TEXT,"
        " protocol_version TEXT, metadata TEXT)"
    )
    for task_id, ctx, state, ts in rows:
        db.execute(
            "INSERT INTO tasks (id, context_id, status, last_updated) VALUES (?, ?, ?, ?)",
            (task_id, ctx, json.dumps({"state": state, "timestamp": ts}), ts),
        )
    db.commit()
    db.close()
    return str(path)


@pytest.fixture
def store(tmp_path, monkeypatch):
    def _make(rows):
        path = _store(tmp_path, rows)
        monkeypatch.setattr(tasks_mod, "_db_path", lambda: path)
        return path

    return _make


def test_lists_newest_first_with_state_counts(store) -> None:
    store(
        [
            ("old", "system:activity", "TASK_STATE_COMPLETED", "2026-07-29T10:00:00Z"),
            ("new", "system:activity", "TASK_STATE_WORKING", "2026-07-30T10:00:00Z"),
            ("mid", "chat:1", "TASK_STATE_FAILED", "2026-07-29T20:00:00Z"),
        ]
    )
    out = tasks_mod.list_tasks()
    assert out["available"] is True
    assert [t["id"] for t in out["tasks"]] == ["new", "mid", "old"]
    assert out["counts_by_state"] == {
        "TASK_STATE_WORKING": 1,
        "TASK_STATE_FAILED": 1,
        "TASK_STATE_COMPLETED": 1,
    }


def test_counts_cover_the_whole_store_not_just_the_page(store) -> None:
    """The runaway signature is a *count*; paging must not hide it."""
    store([(f"t{i}", "system:activity", "TASK_STATE_WORKING", f"2026-07-30T10:00:{i:02d}Z") for i in range(50)])
    out = tasks_mod.list_tasks(limit=5)
    assert len(out["tasks"]) == 5  # page respected
    assert out["count"] == 50  # total matching, not the page
    assert out["counts_by_state"]["TASK_STATE_WORKING"] == 50  # the number that matters


def test_state_filter_accepts_bare_and_wire_forms(store) -> None:
    store(
        [
            ("w", "c", "TASK_STATE_WORKING", "2026-07-30T10:00:00Z"),
            ("d", "c", "TASK_STATE_COMPLETED", "2026-07-30T09:00:00Z"),
        ]
    )
    for spelling in ("working", "WORKING", "TASK_STATE_WORKING"):
        out = tasks_mod.list_tasks(state=spelling)
        assert [t["id"] for t in out["tasks"]] == ["w"], spelling
        # Filtered view still reports the full histogram.
        assert out["counts_by_state"]["TASK_STATE_COMPLETED"] == 1


def test_context_id_filter(store) -> None:
    store(
        [
            ("a", "system:activity", "TASK_STATE_WORKING", "2026-07-30T10:00:00Z"),
            ("b", "chat:7", "TASK_STATE_WORKING", "2026-07-30T09:00:00Z"),
        ]
    )
    out = tasks_mod.list_tasks(context_id="chat:7")
    assert [t["id"] for t in out["tasks"]] == ["b"]


def test_missing_store_degrades_instead_of_raising(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(tasks_mod, "_db_path", lambda: str(tmp_path / "nope.db"))
    out = tasks_mod.list_tasks()
    assert out == {"tasks": [], "count": 0, "counts_by_state": {}, "db": str(tmp_path / "nope.db"), "available": False}


def test_unreadable_store_degrades_instead_of_raising(tmp_path, monkeypatch) -> None:
    junk = tmp_path / "a2a-tasks.db"
    junk.write_text("not a database")
    monkeypatch.setattr(tasks_mod, "_db_path", lambda: str(junk))
    out = tasks_mod.list_tasks()
    assert out["available"] is False
    assert out["tasks"] == []


def test_malformed_status_is_reported_not_dropped(store) -> None:
    """A row we can't parse still shows up — silently dropping rows is how a
    forensics surface lies."""
    path = store([("ok", "c", "TASK_STATE_WORKING", "2026-07-30T10:00:00Z")])
    db = sqlite3.connect(path)
    db.execute("INSERT INTO tasks (id, context_id, status, last_updated) VALUES ('bad', 'c', 'garbage', NULL)")
    db.commit()
    db.close()

    out = tasks_mod.list_tasks()
    assert out["count"] == 2
    assert out["counts_by_state"]["UNKNOWN"] == 1
    assert any(t["id"] == "bad" and t["state"] == "UNKNOWN" for t in out["tasks"])


def test_limit_is_capped(store) -> None:
    store([("t", "c", "TASK_STATE_WORKING", "2026-07-30T10:00:00Z")])
    assert tasks_mod.list_tasks(limit=10_000)["tasks"]  # no explosion
    assert tasks_mod.list_tasks(limit=0)["tasks"]  # coerced to a sane floor
