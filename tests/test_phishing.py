"""Tests for phishing — mocked subprocess."""
from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.phishing import PhishingTool


@pytest.fixture
def tool():
    return PhishingTool()


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "phishing"

    def test_actions_defined(self, tool):
        expected = {
            "gophish_create_campaign", "gophish_results",
            "evilginx_phishlet", "evilginx_lures",
            "email_header_analyze", "spf_check", "dkim_check",
            "dmarc_check", "smtp_relay_test",
        }
        assert set(tool.ACTIONS.keys()) == expected


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


class TestGoPhish:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_create_campaign(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"id":1,"name":"test"}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("gophish_create_campaign", campaign_name="test", template="tmpl", target="http://gophish", api_key="key123")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "gophish-cli"
        assert "test" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_results(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"results":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("gophish_results", campaign_id="1", api_key="key123")
        cmd = mock_exec.call_args[0]
        assert "results" in cmd


class TestEvilginx:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_phishlet(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Phishlet configured\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("evilginx_phishlet", phishlet="o365", domain="evil.com")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "evilginx"
        assert "o365" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_lures(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Lure created: https://evil.com/abc\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("evilginx_lures", phishlet="o365")
        cmd = mock_exec.call_args[0]
        assert "lures" in cmd


class TestDNS:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_spf_check(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'"v=spf1 include:_spf.google.com ~all"\n', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("spf_check", domain="example.com")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "dig"
        assert "example.com" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_dmarc_check(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'"v=DMARC1; p=reject"\n', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("dmarc_check", domain="example.com")
        cmd = mock_exec.call_args[0]
        assert "_dmarc.example.com" in cmd


class TestSMTP:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_smtp_relay(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"250 Ok: queued\n", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("smtp_relay_test", target="mail.example.com", recipient="user@test.com", sender="attacker@evil.com")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "swaks"
        assert "user@test.com" in cmd


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("spf_check", domain="example.com")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
