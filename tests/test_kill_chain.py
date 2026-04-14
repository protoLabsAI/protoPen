"""Tests for kill chain phase tagging."""

import pytest

from enforcement.phases import KillChainPhase, TOOL_PHASE_MAP, get_tool_phase


class TestKillChainPhase:
    def test_phase_ordering(self):
        assert KillChainPhase.RECON < KillChainPhase.ENUMERATION
        assert KillChainPhase.ENUMERATION < KillChainPhase.VULN_ASSESSMENT
        assert KillChainPhase.VULN_ASSESSMENT < KillChainPhase.EXPLOITATION
        assert KillChainPhase.EXPLOITATION < KillChainPhase.POST_EXPLOITATION
        assert KillChainPhase.POST_EXPLOITATION < KillChainPhase.LATERAL_MOVEMENT
        assert KillChainPhase.LATERAL_MOVEMENT < KillChainPhase.PERSISTENCE
        assert KillChainPhase.PERSISTENCE < KillChainPhase.EXFILTRATION
        assert KillChainPhase.EXFILTRATION < KillChainPhase.CLEANUP

    def test_phase_values(self):
        assert KillChainPhase.RECON.value == 0
        assert KillChainPhase.CLEANUP.value == 8

    def test_phase_from_name(self):
        assert KillChainPhase["EXPLOITATION"] == KillChainPhase.EXPLOITATION


class TestToolPhaseMap:
    def test_nmap_scan_is_recon(self):
        assert TOOL_PHASE_MAP["nmap_scan"] == KillChainPhase.RECON

    def test_nmap_vuln_is_enumeration(self):
        assert TOOL_PHASE_MAP["nmap_vuln_scan"] == KillChainPhase.ENUMERATION

    def test_nikto_is_vuln_assessment(self):
        assert TOOL_PHASE_MAP["nikto_scan"] == KillChainPhase.VULN_ASSESSMENT

    def test_wifi_deauth_is_exploitation(self):
        assert TOOL_PHASE_MAP["wifi_deauth"] == KillChainPhase.EXPLOITATION

    def test_evil_portal_is_exploitation(self):
        assert TOOL_PHASE_MAP["wifi_evil_portal"] == KillChainPhase.EXPLOITATION

    def test_shell_exec_is_exploitation(self):
        assert TOOL_PHASE_MAP["shell_exec"] == KillChainPhase.EXPLOITATION

    def test_rf_scan_is_recon(self):
        assert TOOL_PHASE_MAP["rf_scan"] == KillChainPhase.RECON

    def test_rf_replay_is_exploitation(self):
        assert TOOL_PHASE_MAP["rf_replay"] == KillChainPhase.EXPLOITATION

    def test_hashcat_crack_is_exploitation(self):
        assert TOOL_PHASE_MAP["hashcat_crack"] == KillChainPhase.EXPLOITATION

    def test_all_engagement_config_tools_are_mapped(self):
        """Every tool in engagement-config.json tool_risk must be in TOOL_PHASE_MAP."""
        import json

        with open("config/engagement-config.json") as f:
            config = json.load(f)
        tool_risk = config.get("tool_risk", {})
        for tool_name in tool_risk:
            assert tool_name in TOOL_PHASE_MAP, f"{tool_name} missing from TOOL_PHASE_MAP"


class TestGetToolPhase:
    def test_known_tool(self):
        assert get_tool_phase("nmap_scan") == KillChainPhase.RECON

    def test_unknown_tool_returns_none(self):
        assert get_tool_phase("unknown_tool") is None

    def test_phase_comparison_for_ceiling(self):
        max_phase = KillChainPhase.ENUMERATION
        assert get_tool_phase("nmap_scan") <= max_phase
        assert get_tool_phase("nmap_vuln_scan") <= max_phase
        assert get_tool_phase("wifi_deauth") > max_phase
