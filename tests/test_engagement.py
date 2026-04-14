"""Tests for engagement manager — mode enforcement, logging, reporting."""

import pytest
import json
from pathlib import Path

from tools.engagement import EngagementManager, EngagementMode


@pytest.fixture
def config():
    with open("config/engagement-config.json") as f:
        return json.load(f)


@pytest.fixture
def mgr(config, tmp_path):
    config["engagement"]["workspace_dir"] = str(tmp_path)
    return EngagementManager(config)


class TestModeEnforcement:
    def test_default_mode_is_passive(self, mgr):
        assert mgr.mode == EngagementMode.PASSIVE

    def test_set_mode(self, mgr):
        mgr.set_mode(EngagementMode.ACTIVE)
        assert mgr.mode == EngagementMode.ACTIVE

    def test_passive_allows_scan(self, mgr):
        assert mgr.is_allowed("rf_scan") is True

    def test_passive_blocks_replay(self, mgr):
        assert mgr.is_allowed("rf_replay") is False

    def test_passive_blocks_deauth(self, mgr):
        assert mgr.is_allowed("wifi_deauth") is False

    def test_active_allows_replay(self, mgr):
        mgr.set_mode(EngagementMode.ACTIVE)
        assert mgr.is_allowed("rf_replay") is True

    def test_active_blocks_deauth(self, mgr):
        mgr.set_mode(EngagementMode.ACTIVE)
        assert mgr.is_allowed("wifi_deauth") is False

    def test_redteam_allows_all(self, mgr):
        mgr.set_mode(EngagementMode.REDTEAM)
        assert mgr.is_allowed("wifi_deauth") is True
        assert mgr.is_allowed("wifi_evil_portal") is True
        assert mgr.is_allowed("rf_scan") is True


class TestEngagementLifecycle:
    def test_start_engagement(self, mgr, tmp_path):
        mgr.start("test-engagement", scope="192.168.1.0/24")
        assert mgr.active_engagement is not None
        assert mgr.active_engagement["name"] == "test-engagement"
        ws_path = tmp_path / "test-engagement"
        assert ws_path.exists()
        assert (ws_path / "engagement.json").exists()

    def test_log_finding(self, mgr):
        mgr.start("test", scope="10.0.0.0/8")
        mgr.log_finding("high", "wifi", "Open AP detected", "SSID 'FreeWiFi' no encryption")
        assert len(mgr.findings) == 1
        assert mgr.findings[0]["severity"] == "high"
        assert mgr.findings[0]["category"] == "wifi"

    def test_generate_report(self, mgr):
        mgr.start("test", scope="192.168.1.0/24")
        mgr.log_finding("medium", "network", "Port 22 open", "SSH on 192.168.1.1")
        report = mgr.generate_report()
        assert "test" in report
        assert "Port 22 open" in report

    def test_end_engagement(self, mgr):
        mgr.start("test", scope="10.0.0.0/8")
        mgr.log_finding("low", "rf", "Signal detected", "433MHz OOK")
        mgr.end()
        assert mgr.active_engagement is None
        assert mgr.findings == []

    def test_end_saves_findings(self, mgr, tmp_path):
        mgr.start("test", scope="10.0.0.0/8")
        mgr.log_finding("info", "rf", "Noise", "Nothing interesting")
        mgr.end()
        assert (tmp_path / "test" / "findings.json").exists()


class TestNanobotInterface:
    @pytest.mark.asyncio
    async def test_execute_start(self, mgr):
        result = await mgr.execute(action="start", name="test", scope="10.0.0.0/8")
        assert "test" in result

    @pytest.mark.asyncio
    async def test_execute_set_mode(self, mgr):
        await mgr.execute(action="set_mode", mode="active")
        assert mgr.mode == EngagementMode.ACTIVE

    @pytest.mark.asyncio
    async def test_execute_check_permission(self, mgr):
        result = await mgr.execute(action="check_permission", tool_name="rf_scan")
        assert "Allowed" in result

    @pytest.mark.asyncio
    async def test_execute_unknown(self, mgr):
        result = await mgr.execute(action="nonexistent")
        assert "Unknown action" in result

    def test_has_name(self, mgr):
        assert mgr.name == "engagement"
