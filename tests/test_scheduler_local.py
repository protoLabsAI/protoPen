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


# ── A2A 1.0 loopback fire shape (regression guard) ───────────────────────────
# The scheduler POSTs scheduled fires back to the agent's own /a2a. After the
# a2a-sdk 1.0 migration the request MUST be 1.0-shaped: an A2A-Version: 1.0
# header (else the SDK answers -32009 VERSION_NOT_SUPPORTED), the proto method
# name "SendMessage" (the 0.3 "message/send" → Method not found), and contextId
# + metadata carried ON the message. This locks that shape so the 0.3 form
# (which silently broke every scheduled fire post-cutover) can't creep back.


class _CapturingClient:
    """Stand-in for httpx.AsyncClient that records the one POST it receives."""

    captured: dict = {}

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, *, headers=None, json=None):
        _CapturingClient.captured = {"url": url, "headers": headers, "json": json}

        class _Resp:
            status_code = 200
            text = ""

        return _Resp()


@pytest.mark.asyncio
async def test_fire_emits_a2a_1_0_wire_shape(tmp_path, monkeypatch):
    import httpx

    from events import ACTIVITY_CONTEXT
    from scheduler.interface import Job

    monkeypatch.setattr(httpx, "AsyncClient", _CapturingClient)
    s = LocalScheduler(
        agent_name="protopen-test", invoke_url="http://127.0.0.1:7870", api_key="k", db_dir=str(tmp_path)
    )
    job = Job(
        id="job-1", prompt="run the morning sweep", schedule="0 9 * * *", next_fire="", agent_name="protopen-test"
    )

    ok = await s._fire(job)
    assert ok is True

    cap = _CapturingClient.captured
    assert cap["url"].endswith("/a2a")
    # Version header + auth.
    assert cap["headers"]["A2A-Version"] == "1.0"
    assert cap["headers"]["X-API-Key"] == "k"
    # Proto RPC method, not the 0.3 "message/send".
    assert cap["json"]["method"] == "SendMessage"
    msg = cap["json"]["params"]["message"]
    # contextId + metadata ride on the message in 1.0 (not at params level).
    assert msg["contextId"] == ACTIVITY_CONTEXT
    assert msg["role"] == "ROLE_USER"
    assert msg["parts"] == [{"text": "run the morning sweep"}]
    assert msg["metadata"]["origin"] == "scheduler"
    assert msg["metadata"]["scheduler_job_id"] == "job-1"
    # No lingering 0.3 shapes.
    assert "kind" not in msg["parts"][0]
    assert "contextId" not in cap["json"]["params"]
    assert "metadata" not in cap["json"]["params"]


# ── owner-lock + startup catch-up resilience (protopen-1hw.2) ────────────────

import logging

import scheduler.local as _local


@pytest.mark.skipif(_local.fcntl is None, reason="POSIX flock unavailable")
def test_owner_lock_blocks_second_poller(tmp_path):
    """A second live instance on the same jobs.db can't also poll (no double-fire)."""

    async def scenario():
        s1 = _sched(tmp_path)
        s2 = _sched(tmp_path)  # same db_dir + agent → same jobs.db + lock file
        try:
            await s1.start()
            await s2.start()
            return (
                s1._task is not None,  # s1 owns the lock and polls
                s2._task is None and s2._lock_retry_task is not None,  # s2 parks on retry
            )
        finally:
            await s1.stop()
            await s2.stop()

    s1_polling, s2_waiting = asyncio.run(scenario())
    assert s1_polling is True
    assert s2_waiting is True


@pytest.mark.skipif(_local.fcntl is None, reason="POSIX flock unavailable")
def test_owner_lock_released_on_stop(tmp_path):
    async def scenario():
        s1 = _sched(tmp_path)
        await s1.start()
        await s1.stop()  # must release the lock
        s2 = _sched(tmp_path)
        acquired = s2._try_acquire_lock()
        s2._release_lock()
        return acquired

    assert asyncio.run(scenario()) is True


@pytest.mark.skipif(_local.fcntl is None, reason="POSIX flock unavailable")
def test_owner_lock_self_heals_after_owner_stops(tmp_path, monkeypatch):
    """The waiting instance starts polling the moment the lock frees — never gives up."""
    monkeypatch.setattr(_local, "_LOCK_RETRY_INTERVAL_S", 0.05)

    async def scenario():
        s1 = _sched(tmp_path)
        s2 = _sched(tmp_path)
        try:
            await s1.start()
            await s2.start()  # parks on the retry loop
            assert s2._task is None
            await s1.stop()  # frees the lock
            await asyncio.sleep(0.25)  # retry loop should acquire + begin polling
            return s2._task is not None and not s2._task.done()
        finally:
            await s2.stop()

    assert asyncio.run(scenario()) is True


@pytest.mark.asyncio
async def test_fire_connect_error_is_concise_and_returns_false(tmp_path, monkeypatch, caplog):
    """Agent-not-up-yet (catch-up before uvicorn) is a concise INFO, not an ERROR traceback."""
    import httpx

    from scheduler.interface import Job

    class _RefusingClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            raise httpx.ConnectError("Connection refused")

    monkeypatch.setattr(httpx, "AsyncClient", _RefusingClient)
    s = _sched(tmp_path)
    job = Job(id="job-x", prompt="ping", schedule="0 9 * * *", next_fire="", agent_name="protopen-test")

    with caplog.at_level(logging.INFO, logger="scheduler.local"):
        ok = await s._fire(job)

    assert ok is False
    assert any("not reachable yet" in r.getMessage() for r in caplog.records)
    assert not any(r.levelno >= logging.ERROR for r in caplog.records)
