"""Tests for sdn_attack — mocked subprocess."""

from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.sdn_attack import SDNAttackTool


@pytest.fixture
def tool():
    return SDNAttackTool()


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "sdn_attack"

    def test_actions_defined(self, tool):
        expected = {
            "sdn_controller_enum",
            "netconf_exploit",
            "network_policy_audit",
            "yang_model_enum",
            "restconf_test",
            "openflow_audit",
        }
        assert set(tool.ACTIONS.keys()) == expected


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


class TestSDNControllerEnum:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_sdn_controller_enum(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"controllers":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("sdn_controller_enum", target="10.0.0.1", port=8181)
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "python3"
        assert "protopen_scripts.sdn_enum" in cmd
        assert "10.0.0.1" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_sdn_controller_enum_custom_port(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"controllers":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("sdn_controller_enum", target="10.0.0.1", port=6633)
        cmd = mock_exec.call_args[0]
        assert "6633" in cmd


class TestNETCONFExploit:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_netconf_exploit(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"vulnerabilities":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute(
            "netconf_exploit",
            target="10.0.0.2",
            netconf_port=830,
            username="admin",
            password="secret",
        )
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.netconf_audit" in cmd
        assert "10.0.0.2" in cmd
        assert "830" in cmd
        assert "admin" in cmd
        assert "secret" in cmd


class TestNetworkPolicyAudit:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_network_policy_audit(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"policy_issues":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute(
            "network_policy_audit",
            target="http://controller:8181",
            api_key="test-key-123",
        )
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.net_policy_audit" in cmd
        assert "http://controller:8181" in cmd
        assert "test-key-123" in cmd


class TestYANGModelEnum:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_yang_model_enum(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"models":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("yang_model_enum", target="10.0.0.3", netconf_port=830)
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.yang_enum" in cmd
        assert "10.0.0.3" in cmd
        assert "830" in cmd


class TestRESTCONFTest:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_restconf_test(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"endpoints":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute(
            "restconf_test",
            target="https://10.0.0.4:8181",
            username="admin",
            password="pass123",
        )
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.restconf_audit" in cmd
        assert "https://10.0.0.4:8181" in cmd
        assert "admin" in cmd
        assert "pass123" in cmd


class TestOpenFlowAudit:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_openflow_audit(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"issues":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("openflow_audit", target="10.0.0.5", openflow_port=6653)
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.openflow_audit" in cmd
        assert "10.0.0.5" in cmd
        assert "6653" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_openflow_audit_custom_port(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"issues":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("openflow_audit", target="10.0.0.5", openflow_port=6633)
        cmd = mock_exec.call_args[0]
        assert "6633" in cmd


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("sdn_controller_enum", target="10.0.0.1")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]


class TestTimeout:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_timeout_returns_message(self, mock_exec, tool):
        import asyncio

        proc = AsyncMock()
        proc.communicate.side_effect = asyncio.TimeoutError
        proc.kill = AsyncMock()
        proc.wait = AsyncMock()
        mock_exec.return_value = proc
        result = await tool.execute("sdn_controller_enum", target="10.0.0.1")
        assert "timed out" in result.lower()
