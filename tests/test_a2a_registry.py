"""Owned-producer ActiveTaskRegistry (a2a_registry.py) — port protoAgent #1713.

The a2a-sdk 1.1.0 teardown can drop the last strong reference to a still-pending
``producer:<task_id>`` task, letting cyclic GC destroy it ("Task was destroyed but
it is pending!"). ``OwnedProducerActiveTaskRegistry`` retires the producer/consumer
tasks (await briefly, then cancel+await) before removing the ActiveTask, and
``harden_active_task_registry`` installs it in place of the stock registry.
"""

from __future__ import annotations

import asyncio

import pytest
from a2a.server.agent_execution.active_task_registry import ActiveTaskRegistry

from a2a_registry import (
    OwnedProducerActiveTaskRegistry,
    harden_active_task_registry,
)


def test_harden_swaps_in_owned_producer_registry():
    """A handler with a stock registry gets the owned-producer subclass, carrying
    the same agent_executor / task_store / push_sender."""

    class _Handler:
        pass

    executor, store, sender = object(), object(), object()
    handler = _Handler()
    handler._active_task_registry = ActiveTaskRegistry(agent_executor=executor, task_store=store, push_sender=sender)

    assert harden_active_task_registry(handler) is True
    reg = handler._active_task_registry
    assert isinstance(reg, OwnedProducerActiveTaskRegistry)
    assert reg._agent_executor is executor
    assert reg._task_store is store
    assert reg._push_sender is sender


def test_harden_degrades_gracefully_on_moved_internals():
    """If an a2a-sdk upgrade moves _active_task_registry, hardening warns and
    no-ops — never crashes the mount."""

    class _NotAHandler:
        pass

    assert harden_active_task_registry(_NotAHandler()) is False


@pytest.mark.asyncio
async def test_retire_cancels_a_stuck_task_instead_of_leaving_it_pending(monkeypatch):
    """A producer parked forever (the close-join hang) is cancelled and awaited by
    the retire path — not left pending for the GC to destroy."""
    # No real backoff: shrink the grace so the test is fast but still exercises the
    # cancel branch.
    monkeypatch.setattr("a2a_registry.FLUSH_GRACE_S", 0.01)

    async def _hang():
        await asyncio.Event().wait()  # never set → parks forever

    stuck = asyncio.create_task(_hang(), name="producer:stuck")
    await OwnedProducerActiveTaskRegistry._retire(stuck, "task-1")

    assert stuck.done()
    assert stuck.cancelled()  # deterministically retired, not GC'd while pending


@pytest.mark.asyncio
async def test_retire_awaits_a_naturally_finishing_task():
    """A producer that flushes on its own within the grace window is simply awaited."""

    async def _quick():
        return "done"

    task = asyncio.create_task(_quick(), name="producer:quick")
    await OwnedProducerActiveTaskRegistry._retire(task, "task-2")

    assert task.done()
    assert not task.cancelled()
    assert task.result() == "done"


@pytest.mark.asyncio
async def test_retire_surfaces_a_failed_task_without_raising(caplog):
    """A producer that finished with an unhandled error is logged loudly, not
    silently destroyed — and _retire itself does not raise."""

    async def _boom():
        raise RuntimeError("producer blew up at teardown")

    task = asyncio.create_task(_boom(), name="producer:boom")
    # Let it finish so _retire hits the exception-inspection branch.
    await asyncio.sleep(0)
    await OwnedProducerActiveTaskRegistry._retire(task, "task-3")  # must not raise

    assert task.done()
    assert isinstance(task.exception(), RuntimeError)
