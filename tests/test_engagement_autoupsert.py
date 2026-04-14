"""Tests for engagement → target_store auto-upsert integration."""

import json
import pytest
from pathlib import Path

from tools.engagement import EngagementManager
from knowledge.target_store import TargetStore


@pytest.fixture
def config():
    with open("config/engagement-config.json") as f:
        return json.load(f)


@pytest.fixture
def store(tmp_path):
    return TargetStore(db_path=str(tmp_path / "targets.db"))


@pytest.fixture
def mgr(config, tmp_path, store):
    config["engagement"]["workspace_dir"] = str(tmp_path)
    mgr = EngagementManager(config)
    mgr.target_store = store
    return mgr


class TestAutoUpsert:
    def test_finding_with_ip_creates_host(self, mgr, store):
        mgr.start("test-engagement", scope="192.168.1.0/24")
        mgr.log_finding(
            severity="high",
            category="open-port",
            title="SSH on 192.168.1.1",
            detail="Port 22 open on 192.168.1.1 running OpenSSH 9.0",
        )
        hosts = store.query_hosts(ip_prefix="192.168.1.1")
        assert len(hosts) == 1

    def test_finding_without_ip_no_crash(self, mgr, store):
        mgr.start("test-engagement")
        mgr.log_finding(
            severity="info",
            category="general",
            title="Observation",
            detail="Nothing to upsert here",
        )
        assert store.get_stats()["hosts"] == 0

    def test_finding_with_mac_creates_host(self, mgr, store):
        mgr.start("test-engagement")
        mgr.log_finding(
            severity="medium",
            category="wifi",
            title="Rogue AP",
            detail="Detected rogue AP with BSSID AA:BB:CC:DD:EE:FF",
        )
        hosts = store.query_hosts()
        assert len(hosts) >= 1

    def test_no_target_store_no_crash(self, config, tmp_path):
        """When target_store is None (not injected), log_finding should still work."""
        config["engagement"]["workspace_dir"] = str(tmp_path)
        mgr = EngagementManager(config)
        # target_store defaults to None
        mgr.start("test-engagement")
        mgr.log_finding(
            severity="info",
            category="test",
            title="Test",
            detail="192.168.1.1 should not crash",
        )
        assert len(mgr.findings) == 1
