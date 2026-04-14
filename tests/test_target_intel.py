"""Tests for the TargetIntelTool agent wrapper."""

import asyncio

import pytest

from knowledge.target_store import TargetStore
from tools.target_intel import TargetIntelTool


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


@pytest.fixture
def tool(store):
    return TargetIntelTool(store)


def _run(coro):
    """Helper to run async in sync tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestToolInterface:
    def test_name(self, tool):
        assert tool.name == "target_intel"

    def test_parameters_has_action(self, tool):
        assert "action" in tool.parameters["properties"]

    def test_unknown_action(self, tool):
        result = _run(tool.execute(action="bogus"))
        assert "Unknown action" in result


class TestUpsertHost:
    def test_upsert_via_tool(self, tool):
        result = _run(tool.execute(action="upsert_host", ip="10.0.0.1", hostname="gateway"))
        assert "id" in result.lower() or "10.0.0.1" in result


class TestQueryHosts:
    def test_query_empty(self, tool):
        result = _run(tool.execute(action="query_hosts"))
        assert "no host" in result.lower()


class TestStats:
    def test_stats(self, tool):
        result = _run(tool.execute(action="stats"))
        assert "hosts" in result.lower()
