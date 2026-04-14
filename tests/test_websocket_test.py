"""Tests for websocket_test — mocked subprocess."""

from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.websocket_test import WebSocketTestTool


@pytest.fixture
def tool():
    return WebSocketTestTool()


# ── Instantiation ────────────────────────────────────────────────────────────


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "websocket_test"

    def test_actions_defined(self, tool):
        expected = {"auth_bypass", "cswsh", "injection"}
        assert set(tool.ACTIONS.keys()) == expected


# ── Dispatch ─────────────────────────────────────────────────────────────────


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_dispatch_auth_bypass(self, mock_exec, tool):
        output = json.dumps(
            {
                "url": "ws://target:8080",
                "tests": [{"test": "no_auth_connect", "vulnerable": True, "severity": "high", "detail": "accepted"}],
            }
        )
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("auth_bypass", url="ws://target:8080")
        data = json.loads(result)
        assert data["tests"][0]["vulnerable"] is True
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "python3"
        assert "ws_auth_bypass.py" in cmd[1]
        assert "ws://target:8080" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_dispatch_auth_bypass_with_token(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"url":"ws://t","tests":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("auth_bypass", url="ws://t", auth_token="secret123")
        cmd = mock_exec.call_args[0]
        assert "secret123" in cmd


# ── CSWSH ────────────────────────────────────────────────────────────────────


class TestCSWSH:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_cswsh_scan(self, mock_exec, tool):
        output = json.dumps(
            {
                "url": "ws://target:8080",
                "legitimate_origin": "https://app.example.com",
                "tests": [
                    {
                        "test": "cswsh",
                        "origin": "https://evil.com",
                        "vulnerable": True,
                        "severity": "high",
                        "detail": "Evil origin accepted",
                    },
                ],
            }
        )
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "cswsh",
            url="ws://target:8080",
            origin="https://app.example.com",
        )
        data = json.loads(result)
        assert data["tests"][0]["vulnerable"] is True
        cmd = mock_exec.call_args[0]
        assert "ws_cswsh.py" in cmd[1]
        assert "https://app.example.com" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_cswsh_not_vulnerable(self, mock_exec, tool):
        output = json.dumps(
            {
                "url": "ws://target:8080",
                "tests": [
                    {
                        "test": "cswsh",
                        "origin": "https://evil.com",
                        "vulnerable": False,
                        "severity": "info",
                        "detail": "Rejected",
                    },
                ],
            }
        )
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("cswsh", url="ws://target:8080")
        data = json.loads(result)
        assert data["tests"][0]["vulnerable"] is False


# ── Injection ────────────────────────────────────────────────────────────────


class TestInjection:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_injection_all_categories(self, mock_exec, tool):
        output = json.dumps(
            {
                "url": "ws://target:8080",
                "tests": [
                    {
                        "test": "injection",
                        "category": "sqli",
                        "payload": "' OR '1'='1",
                        "reflected": True,
                        "error_leak": False,
                        "severity": "high",
                        "response_preview": "' OR '1'='1",
                    },
                ],
            }
        )
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("injection", url="ws://target:8080")
        data = json.loads(result)
        assert data["tests"][0]["reflected"] is True
        cmd = mock_exec.call_args[0]
        assert "ws_injection.py" in cmd[1]

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_injection_specific_category(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"url":"ws://t","tests":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("injection", url="ws://t", categories="xss,sqli")
        cmd = mock_exec.call_args[0]
        assert "xss,sqli" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_injection_error_leak(self, mock_exec, tool):
        output = json.dumps(
            {
                "url": "ws://target:8080",
                "tests": [
                    {
                        "test": "injection",
                        "category": "sqli",
                        "payload": "1; DROP TABLE",
                        "reflected": False,
                        "error_leak": True,
                        "severity": "medium",
                        "response_preview": "SQL syntax error near...",
                    },
                ],
            }
        )
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("injection", url="ws://target:8080")
        data = json.loads(result)
        assert data["tests"][0]["error_leak"] is True


# ── Binary not found ─────────────────────────────────────────────────────────


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_python(self, mock_exec, tool):
        result = await tool.execute("auth_bypass", url="ws://t")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
