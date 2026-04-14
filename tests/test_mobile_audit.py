"""Tests for mobile_audit — mocked subprocess."""

from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.mobile_audit import MobileAuditTool


@pytest.fixture
def tool():
    return MobileAuditTool()


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "mobile_audit"

    def test_actions_defined(self, tool):
        expected = {
            "apk_decompile",
            "static_analysis",
            "jadx_decompile",
            "drozer_scan",
            "frida_hook",
            "ssl_pinning_bypass",
            "ipc_audit",
            "keychain_dump",
        }
        assert set(tool.ACTIONS.keys()) == expected


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


class TestApkDecompile:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_apk_decompile(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"I: decompiled successfully", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("apk_decompile", target="/tmp/app.apk")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "apktool"
        assert "/tmp/app.apk" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_apk_decompile_output_dir(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"decompiled", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("apk_decompile", target="/tmp/app.apk", output_dir="/out")
        cmd = mock_exec.call_args[0]
        assert "/out/decompiled" in cmd


class TestStaticAnalysis:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_static_analysis(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"findings":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("static_analysis", target="/tmp/app.apk")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "mobsf-cli"
        assert "/tmp/app.apk" in cmd


class TestJadxDecompile:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_jadx_decompile(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"INFO - decompiled", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("jadx_decompile", target="/tmp/app.apk")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "jadx"
        assert "/tmp/app.apk" in cmd
        assert "--deobf" in cmd


class TestDrozerScan:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_drozer_scan(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"providers":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("drozer_scan", target="10.0.0.1", package_name="com.example.app")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "drozer"
        assert "10.0.0.1" in cmd
        assert any("com.example.app" in c for c in cmd)


class TestFridaHook:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_frida_hook(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"hooks":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute(
            "frida_hook",
            package_name="com.example.app",
            script_path="/tmp/hook.js",
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "frida"
        assert "/tmp/hook.js" in cmd
        assert "com.example.app" in cmd


class TestSslPinningBypass:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_ssl_pinning_bypass(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"SSL pinning disabled", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("ssl_pinning_bypass", package_name="com.example.app")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "objection"
        assert "com.example.app" in cmd
        assert any("sslpinning" in c for c in cmd)


class TestIpcAudit:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_ipc_audit(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"components":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("ipc_audit", target="10.0.0.1", package_name="com.example.app")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "drozer"
        assert "10.0.0.1" in cmd
        assert any("com.example.app" in c for c in cmd)


class TestKeychainDump:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_keychain_dump(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"entries":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("keychain_dump", package_name="com.example.app")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "objection"
        assert "com.example.app" in cmd
        assert any("keystore" in c for c in cmd)


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("apk_decompile", target="/tmp/app.apk")
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
        result = await tool.execute("apk_decompile", target="/tmp/app.apk")
        assert "timed out" in result.lower()
