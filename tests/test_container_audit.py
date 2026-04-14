"""Tests for container_audit — mocked subprocess."""

from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.container_audit import ContainerAuditTool


@pytest.fixture
def tool():
    return ContainerAuditTool()


# ── Instantiation ────────────────────────────────────────────────────────────


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "container_audit"

    def test_actions_defined(self, tool):
        expected = {
            "kube_hunter",
            "kube_hunter_internal",
            "kube_bench",
            "kube_bench_target",
            "deepce",
            "cdk_evaluate",
            "cdk_exploit",
            "trivy_image",
            "trivy_k8s",
            "trivy_fs",
        }
        assert set(tool.ACTIONS.keys()) == expected


# ── Dispatch ─────────────────────────────────────────────────────────────────


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_dispatch_kube_hunter(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"vulnerabilities":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("kube_hunter", target="10.0.0.1")
        assert "vulnerabilities" in result
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "kube-hunter"
        assert "--remote" in cmd
        assert "10.0.0.1" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_dispatch_kube_hunter_internal(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"vulnerabilities":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("kube_hunter_internal")
        cmd = mock_exec.call_args[0]
        assert "--internal" in cmd


# ── kube-bench ───────────────────────────────────────────────────────────────


class TestKubeBench:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_kube_bench_default(self, mock_exec, tool):
        output = json.dumps({"Controls": [], "Totals": {"total_pass": 50}})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("kube_bench")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "kube-bench"
        assert "--json" in cmd
        data = json.loads(result)
        assert data["Totals"]["total_pass"] == 50

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_kube_bench_target_benchmark(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"Controls":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("kube_bench_target", benchmark="eks-1.1.0")
        cmd = mock_exec.call_args[0]
        assert "eks-1.1.0" in cmd


# ── deepce ───────────────────────────────────────────────────────────────────


class TestDeepce:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_deepce_run(self, mock_exec, tool):
        output = json.dumps(
            {
                "escapes": [{"name": "docker.sock", "severity": "high"}],
                "info": [{"name": "container_runtime", "value": "docker"}],
            }
        )
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("deepce")
        data = json.loads(result)
        assert len(data["escapes"]) == 1
        assert data["escapes"][0]["name"] == "docker.sock"
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "deepce"
        assert "--json" in cmd


# ── CDK ──────────────────────────────────────────────────────────────────────


class TestCDK:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_cdk_evaluate(self, mock_exec, tool):
        output = json.dumps(
            {
                "findings": [{"name": "service-account", "severity": "high"}],
            }
        )
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("cdk_evaluate")
        data = json.loads(result)
        assert data["findings"][0]["name"] == "service-account"

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_cdk_exploit(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"exploit result", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("cdk_exploit", exploit_name="mount-cgroup")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "cdk"
        assert "mount-cgroup" in cmd


# ── Trivy ────────────────────────────────────────────────────────────────────


class TestTrivy:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_trivy_image(self, mock_exec, tool):
        output = json.dumps(
            {
                "Results": [
                    {
                        "Target": "alpine:3.19",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2024-1234",
                                "Severity": "HIGH",
                                "PkgName": "openssl",
                                "InstalledVersion": "3.1.4",
                            },
                        ],
                    }
                ],
            }
        )
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("trivy_image", image="alpine:3.19")
        data = json.loads(result)
        assert data["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] == "CVE-2024-1234"
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "trivy"
        assert "alpine:3.19" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_trivy_image_severity_filter(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"Results":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("trivy_image", image="nginx:latest", severity="CRITICAL")
        cmd = mock_exec.call_args[0]
        assert "CRITICAL" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_trivy_k8s(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"Results":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("trivy_k8s", target="cluster")
        cmd = mock_exec.call_args[0]
        assert "k8s" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_trivy_fs(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"Results":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("trivy_fs", path="/app")
        cmd = mock_exec.call_args[0]
        assert "fs" in cmd
        assert "/app" in cmd


# ── Binary not found ─────────────────────────────────────────────────────────


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("kube_hunter", target="10.0.0.1")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
