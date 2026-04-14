"""Tests for ad_attack — mocked subprocess."""
from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.ad_attack import ADAttackTool


@pytest.fixture
def tool():
    return ADAttackTool()


# ── Instantiation ────────────────────────────────────────────────────────────

class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "ad_attack"

    def test_actions_defined(self, tool):
        expected = {
            "bloodhound_collect", "bloodhound_edges",
            "certipy_find", "certipy_vuln", "certipy_req",
            "enum4linux_ng", "ldapsearch",
            "kerberoast", "asreproast", "secretsdump",
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
    async def test_dispatch_bloodhound_collect(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Done! 500 users, 100 groups", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "bloodhound_collect", target="10.0.0.1",
            domain="corp.local", username="admin", password="pass",
        )
        assert "users" in result or "Done" in result
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "bloodhound-python"
        assert "-d" in cmd
        assert "corp.local" in cmd
        assert "-ns" in cmd
        assert "10.0.0.1" in cmd
        assert "-c" in cmd
        assert "All" in cmd
        assert "--zip" in cmd


# ── BloodHound ───────────────────────────────────────────────────────────────

class TestBloodHound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_bloodhound_edges(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Collected ACL and Trust data", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "bloodhound_edges", target="10.0.0.1",
            domain="corp.local", username="admin", password="pass",
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "bloodhound-python"
        assert "ACL,Trusts" in cmd


# ── Certipy ──────────────────────────────────────────────────────────────────

class TestCertipy:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_certipy_find(self, mock_exec, tool):
        output = json.dumps({"Certificate Templates": {}})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "certipy_find", target="10.0.0.1",
            domain="corp.local", username="admin", password="pass",
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "certipy"
        assert "find" in cmd
        assert "-json" in cmd
        assert "admin@corp.local" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_certipy_vuln(self, mock_exec, tool):
        output = json.dumps({"Certificate Templates": {}})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "certipy_vuln", target="10.0.0.1",
            domain="corp.local", username="admin", password="pass",
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "certipy"
        assert "-vulnerable" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_certipy_req(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"Certificate retrieved", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "certipy_req", target="10.0.0.1",
            domain="corp.local", username="admin", password="pass",
            ca_name="CORP-CA", template="ESC1-Vuln",
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "certipy"
        assert "req" in cmd
        assert "CORP-CA" in cmd
        assert "ESC1-Vuln" in cmd


# ── enum4linux-ng ────────────────────────────────────────────────────────────

class TestEnum4linux:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_enum4linux_ng(self, mock_exec, tool):
        output = json.dumps({"shares": [], "users": [], "groups": []})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("enum4linux_ng", target="10.0.0.1")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "enum4linux-ng"
        assert "-A" in cmd
        assert "10.0.0.1" in cmd


# ── ldapsearch ───────────────────────────────────────────────────────────────

class TestLdapsearch:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_ldapsearch(self, mock_exec, tool):
        ldif = "dn: CN=admin,DC=corp,DC=local\ncn: admin\n\n"
        proc = AsyncMock()
        proc.communicate.return_value = (ldif.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "ldapsearch", target="10.0.0.1",
            domain="corp.local", username="admin", password="pass",
            base_dn="DC=corp,DC=local",
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "ldapsearch"
        assert "ldap://10.0.0.1" in cmd
        assert "DC=corp,DC=local" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_ldapsearch_custom_filter(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b"", b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute(
            "ldapsearch", target="10.0.0.1",
            domain="corp.local", username="admin", password="pass",
            base_dn="DC=corp,DC=local", filter="(objectClass=user)",
        )
        cmd = mock_exec.call_args[0]
        assert "(objectClass=user)" in cmd


# ── Kerberoast ───────────────────────────────────────────────────────────────

class TestKerberoast:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_kerberoast(self, mock_exec, tool):
        output = "$krb5tgs$23$*svc_sql$CORP.LOCAL$...\n$krb5tgs$23$*svc_web$CORP.LOCAL$..."
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "kerberoast", target="10.0.0.1",
            domain="corp.local", username="admin", password="pass",
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "impacket-GetUserSPNs"
        assert "corp.local/admin:pass" in cmd
        assert "-request" in cmd


# ── AS-REP Roast ─────────────────────────────────────────────────────────────

class TestASREPRoast:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_asreproast(self, mock_exec, tool):
        output = "$krb5asrep$23$user1@CORP.LOCAL:..."
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "asreproast", target="10.0.0.1",
            domain="corp.local", wordlist="/tmp/users.txt",
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "impacket-GetNPUsers"
        assert "corp.local/" in cmd
        assert "-usersfile" in cmd
        assert "/tmp/users.txt" in cmd
        assert "-format" in cmd
        assert "hashcat" in cmd


# ── secretsdump ──────────────────────────────────────────────────────────────

class TestSecretsdump:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_secretsdump(self, mock_exec, tool):
        output = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "secretsdump", target="10.0.0.1",
            domain="corp.local", username="admin", password="pass",
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "impacket-secretsdump"
        assert "corp.local/admin:pass@10.0.0.1" in cmd


# ── Binary not found ─────────────────────────────────────────────────────────

class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute(
            "bloodhound_collect", target="10.0.0.1",
            domain="corp.local", username="admin", password="pass",
        )
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
