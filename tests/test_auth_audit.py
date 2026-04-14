"""Tests for auth_audit — mocked subprocess."""

from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.auth_audit import AuthAuditTool


@pytest.fixture
def tool():
    return AuthAuditTool()


class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "auth_audit"

    def test_actions_defined(self, tool):
        expected = {
            "oauth_redirect_test",
            "oauth_device_code",
            "oidc_discovery",
            "oidc_token_test",
            "saml_decode",
            "saml_inject",
            "jwt_scan",
            "jwt_crack",
            "webauthn_test",
            "session_fixation",
        }
        assert set(tool.ACTIONS.keys()) == expected


class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


class TestOAuth:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_oauth_redirect(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"findings":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute(
            "oauth_redirect_test", target="https://auth.example.com", client_id="app1", redirect_uri="https://evil.com"
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "python3"
        assert "https://auth.example.com" in cmd
        assert "https://evil.com" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_oauth_device_code(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"findings":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("oauth_device_code", target="https://auth.example.com", client_id="app1")
        cmd = mock_exec.call_args[0]
        assert "oauth_device_flow" in " ".join(cmd)


class TestOIDC:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_oidc_discovery(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"issuer":"https://auth.example.com"}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("oidc_discovery", target="https://auth.example.com")
        cmd = mock_exec.call_args[0]
        assert "oidc_discover" in " ".join(cmd)

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_oidc_token(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"findings":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("oidc_token_test", target="https://auth.example.com", token="eyJ...")
        cmd = mock_exec.call_args[0]
        assert "eyJ..." in cmd


class TestSAML:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_saml_decode(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"findings":[{"severity":"high","message":"unsigned"}]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("saml_decode", saml_response="PHNhbWw+...")
        cmd = mock_exec.call_args[0]
        assert "saml_decode" in " ".join(cmd)

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_saml_inject(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"findings":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("saml_inject", target="https://sp.example.com", saml_response="PHNhbWw+...")
        cmd = mock_exec.call_args[0]
        assert "saml_inject" in " ".join(cmd)


class TestJWT:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_jwt_scan(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"findings":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("jwt_scan", token="eyJ...", target="https://api.example.com")
        cmd = mock_exec.call_args[0]
        assert "jwt_tool" in " ".join(cmd)
        assert "eyJ..." in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_jwt_crack(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"findings":[{"message":"secret found: password123"}]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("jwt_crack", token="eyJ...", wordlist="/usr/share/wordlists/rockyou.txt")
        cmd = mock_exec.call_args[0]
        assert "-C" in cmd
        assert "/usr/share/wordlists/rockyou.txt" in cmd


class TestWebAuthn:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_webauthn(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"findings":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("webauthn_test", target="https://app.example.com", rp_id="app.example.com")
        cmd = mock_exec.call_args[0]
        assert "webauthn_test" in " ".join(cmd)
        assert "app.example.com" in cmd


class TestSession:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_session_fixation(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"findings":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("session_fixation", target="https://app.example.com")
        cmd = mock_exec.call_args[0]
        assert "session_test" in " ".join(cmd)


class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("oauth_redirect_test", target="https://auth.example.com")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
