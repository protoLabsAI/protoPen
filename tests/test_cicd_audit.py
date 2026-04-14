"""Tests for cicd_audit — mocked subprocess."""

from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.cicd_audit import CICDAuditTool


@pytest.fixture
def tool():
    return CICDAuditTool()


# ── Instantiation ────────────────────────────────────────────────────────────


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "cicd_audit"

    def test_actions_defined(self, tool):
        expected = {
            "trufflehog_scan",
            "trufflehog_filesystem",
            "gitleaks_detect",
            "gitleaks_protect",
            "github_actions_audit",
            "dependency_check",
            "semgrep_ci",
            "checkov_iac",
        }
        assert set(tool.ACTIONS.keys()) == expected


# ── Dispatch ─────────────────────────────────────────────────────────────────


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


# ── truffleHog ───────────────────────────────────────────────────────────────


class TestTrufflehog:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_trufflehog_scan(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"DetectorName":"AWS"}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("trufflehog_scan", repo_url="https://github.com/test/repo")
        assert "AWS" in result
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "trufflehog"
        assert "git" in cmd
        assert "https://github.com/test/repo" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_trufflehog_filesystem(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"DetectorName":"Generic"}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("trufflehog_filesystem", path="/app")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "trufflehog"
        assert "filesystem" in cmd
        assert "/app" in cmd


# ── gitleaks ─────────────────────────────────────────────────────────────────


class TestGitleaks:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_gitleaks_detect(self, mock_exec, tool):
        output = json.dumps([{"RuleID": "aws-access-key", "Secret": "AKIA1234"}])
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("gitleaks_detect", path="/repo")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "gitleaks"
        assert "detect" in cmd
        assert "/repo" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_gitleaks_protect(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"[]", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("gitleaks_protect", path="/repo")
        cmd = mock_exec.call_args[0]
        assert "protect" in cmd
        assert "--staged" in cmd


# ── actionlint ───────────────────────────────────────────────────────────────


class TestActionlint:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_github_actions_audit(self, mock_exec, tool):
        output = json.dumps([{"message": "shell injection", "line": 10}])
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("github_actions_audit", path=".github/workflows/")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "actionlint"


# ── dependency-check ─────────────────────────────────────────────────────────


class TestDependencyCheck:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_dependency_check(self, mock_exec, tool):
        output = json.dumps({"dependencies": []})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("dependency_check", path="/app")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "dependency-check"
        assert "/app" in cmd


# ── semgrep ──────────────────────────────────────────────────────────────────


class TestSemgrep:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_semgrep_ci(self, mock_exec, tool):
        output = json.dumps({"results": []})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("semgrep_ci", path="/app")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "semgrep"
        assert "--json" in cmd


# ── checkov ──────────────────────────────────────────────────────────────────


class TestCheckov:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_checkov_iac(self, mock_exec, tool):
        output = json.dumps({"results": {"failed_checks": [], "passed_checks": []}})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("checkov_iac", path="/infra")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "checkov"
        assert "/infra" in cmd


# ── Binary not found ─────────────────────────────────────────────────────────


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("trufflehog_scan", repo_url="https://github.com/test/repo")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
