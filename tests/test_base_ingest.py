"""BasePentestTool._run routes output through the parser registry."""

from __future__ import annotations

import asyncio

import tools.parsers
from tools.base import BasePentestTool


def test_run_routes_output_through_ingest(monkeypatch):
    calls = []
    monkeypatch.setattr(
        tools.parsers,
        "ingest_output",
        lambda tool, action, raw, store: calls.append((tool, action, raw, store)) or [],
    )

    class _Echo(BasePentestTool):
        name = "echotool"

    tool = _Echo()
    sentinel = object()
    tool._target_store = sentinel

    out = asyncio.run(tool._run(action="probe", cmd=["echo", "hello world"], timeout=5))

    assert "hello world" in out
    assert len(calls) == 1
    tool_name, action, raw, store = calls[0]
    assert tool_name == "echotool"
    assert action == "probe"
    assert "hello world" in raw
    assert store is sentinel


def test_run_ingest_is_noop_without_store():
    """With no store set, ingest_output runs but parses nothing — must not raise."""

    class _Echo(BasePentestTool):
        name = "echotool_nostore"

    tool = _Echo()  # _target_store defaults to None
    out = asyncio.run(tool._run(action="probe", cmd=["echo", "hi"], timeout=5))
    assert "hi" in out
