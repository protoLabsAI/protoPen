"""Tests for the local scheduler (sqlite + asyncio)."""

from __future__ import annotations

import asyncio

import pytest

from scheduler import LocalScheduler
from scheduler.interface import is_cron, parse_iso_to_utc


def _sched(tmp_path, agent="protopen-test") -> LocalScheduler:
    return LocalScheduler(agent_name=agent, invoke_url="http://127.0.0.1:7870", db_dir=str(tmp_path))


def test_add_cron_job_computes_next_fire(tmp_path) -> None:
    s = _sched(tmp_path)
    job = s.add_job("run a scan", "0 9 * * 1-5")
    assert job.id
    assert job.schedule == "0 9 * * 1-5"
    assert job.next_fire and "T" in job.next_fire  # ISO timestamp
    assert len(s.list_jobs()) == 1


def test_add_iso_one_shot(tmp_path) -> None:
    s = _sched(tmp_path)
    job = s.add_job("one shot", "2030-01-01T00:00:00+00:00")
    assert job.next_fire.startswith("2030-01-01T00:00:00")


def test_add_job_rejects_malformed_schedule(tmp_path) -> None:
    s = _sched(tmp_path)
    with pytest.raises(ValueError):
        s.add_job("bad", "not a schedule")


def test_cancel_job(tmp_path) -> None:
    s = _sched(tmp_path)
    job = s.add_job("x", "0 9 * * *")
    assert s.cancel_job(job.id) is True
    assert s.list_jobs() == []
    assert s.cancel_job(job.id) is False  # already gone
    assert s.cancel_job("nope") is False


def test_jobs_are_isolated_by_agent_name(tmp_path) -> None:
    a = _sched(tmp_path, agent="agent-a")
    b = _sched(tmp_path, agent="agent-b")
    a.add_job("a-job", "0 9 * * *")
    assert len(a.list_jobs()) == 1
    assert b.list_jobs() == []  # b doesn't see a's job


def test_list_sorted_by_next_fire(tmp_path) -> None:
    s = _sched(tmp_path)
    s.add_job("later", "2031-01-01T00:00:00+00:00")
    s.add_job("sooner", "2030-01-01T00:00:00+00:00")
    jobs = s.list_jobs()
    assert [j.prompt for j in jobs] == ["sooner", "later"]


def test_start_stop_lifecycle(tmp_path) -> None:
    async def scenario():
        s = _sched(tmp_path)
        await s.start()
        running = s._task is not None and not s._task.done()
        await s.stop()
        return running, (s._task is None or s._task.done())

    started, stopped = asyncio.run(scenario())
    assert started is True
    assert stopped is True


class TestHelpers:
    def test_is_cron(self):
        assert is_cron("0 9 * * 1-5") is True
        assert is_cron("2030-01-01T00:00:00+00:00") is False
        assert is_cron("2030-01-01 09:00:00") is False

    def test_parse_iso_naive_treated_as_utc(self):
        dt = parse_iso_to_utc("2030-01-01T00:00:00")
        assert dt.tzinfo is not None
        assert dt.isoformat().startswith("2030-01-01T00:00:00")

    def test_parse_iso_malformed_raises(self):
        with pytest.raises(ValueError):
            parse_iso_to_utc("not-a-date")
