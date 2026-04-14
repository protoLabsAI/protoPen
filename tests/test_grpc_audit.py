"""Tests for grpc_audit — mocked subprocess."""
from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.grpc_audit import GRPCAuditTool


@pytest.fixture
def tool():
    return GRPCAuditTool()


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "grpc_audit"

    def test_actions_defined(self, tool):
        expected = {
            "grpc_reflection", "grpc_describe", "grpc_call", "grpc_fuzz",
            "grpc_auth_test", "grpc_tls_check", "grpc_web_test", "protoscan",
        }
        assert set(tool.ACTIONS.keys()) == expected


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


class TestReflection:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_grpc_reflection(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"grpc.health.v1.Health\nmy.service.v1.Api\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("grpc_reflection", target="localhost:50051")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "grpcurl"
        assert "-plaintext" in cmd
        assert "list" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_grpc_describe(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"rpc GetUser (.UserReq) returns (.UserResp)\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("grpc_describe", target="localhost:50051", service="my.service.v1.Api")
        cmd = mock_exec.call_args[0]
        assert "describe" in cmd
        assert "my.service.v1.Api" in cmd


class TestCall:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_grpc_call(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"id":"1","name":"admin"}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("grpc_call", target="localhost:50051", method="my.Api/GetUser", data='{"id":"1"}')
        cmd = mock_exec.call_args[0]
        assert "grpcurl" in cmd[0]
        assert "my.Api/GetUser" in cmd


class TestFuzz:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_grpc_fuzz(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"results":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("grpc_fuzz", target="localhost:50051", service="my.Api", count=500)
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "grpc-fuzz"
        assert "500" in cmd


class TestAuth:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_grpc_auth_test(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"id":"1"}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("grpc_auth_test", target="localhost:50051", method="my.Api/GetUser", auth_header="Bearer tok123")
        cmd = mock_exec.call_args[0]
        assert "Authorization: Bearer tok123" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_grpc_tls_check(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"grpc.health.v1.Health\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("grpc_tls_check", target="localhost:50051")
        cmd = mock_exec.call_args[0]
        assert "-plaintext" not in cmd


class TestProtoscan:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_protoscan(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"endpoints":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("protoscan", target="10.0.0.0/24")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "protoscan"


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("grpc_reflection", target="localhost:50051")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
