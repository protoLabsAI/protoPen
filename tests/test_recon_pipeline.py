"""Tests for recon_pipeline — mocked subprocess."""

from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.recon_pipeline import ReconPipelineTool


@pytest.fixture
def tool():
    return ReconPipelineTool()


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "recon_pipeline"

    def test_actions_defined(self, tool):
        expected = {
            "full_pipeline",
            "subdomain_httpx",
            "nuclei_scan",
            "screenshot_capture",
            "asset_correlate",
            "attack_graph_build",
            "tech_detect",
        }
        assert set(tool.ACTIONS.keys()) == expected


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


class TestFullPipeline:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_full_pipeline(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"results":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("full_pipeline", domain="example.com")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "python3"
        assert "protopen_scripts.recon_pipeline" in cmd
        assert "example.com" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_full_pipeline_custom_threads(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"results":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("full_pipeline", domain="example.com", threads=10)
        cmd = mock_exec.call_args[0]
        assert "10" in cmd


class TestSubdomainHttpx:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_subdomain_httpx(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("subdomain_httpx", domain="example.com")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "bash"
        assert "subfinder" in cmd[2]
        assert "example.com" in cmd[2]


class TestNucleiScan:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_nuclei_scan(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("nuclei_scan", target="https://example.com")
        cmd = mock_exec.call_args[0]
        assert "nuclei" in cmd
        assert "https://example.com" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_nuclei_scan_custom_severity(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("nuclei_scan", target="https://example.com", severity="critical")
        cmd = mock_exec.call_args[0]
        assert "critical" in cmd


class TestScreenshotCapture:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_screenshot_capture(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"screenshots":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("screenshot_capture", targets_file="/tmp/targets.txt")
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.screenshot" in cmd
        assert "/tmp/targets.txt" in cmd


class TestAssetCorrelate:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_asset_correlate(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"assets":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("asset_correlate", output_dir="/tmp/recon_out")
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.asset_correlate" in cmd
        assert "/tmp/recon_out" in cmd


class TestAttackGraphBuild:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_attack_graph_build(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"nodes":[],"edges":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("attack_graph_build", domain="example.com", output_dir="/tmp/recon_out")
        cmd = mock_exec.call_args[0]
        assert "protopen_scripts.attack_graph" in cmd
        assert "example.com" in cmd
        assert "/tmp/recon_out" in cmd


class TestTechDetect:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_tech_detect(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("tech_detect", target="https://example.com")
        cmd = mock_exec.call_args[0]
        assert "httpx" in cmd
        assert "https://example.com" in cmd
        assert "-tech-detect" in cmd


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("full_pipeline", domain="example.com")
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
        result = await tool.execute("full_pipeline", domain="example.com")
        assert "timed out" in result.lower()
