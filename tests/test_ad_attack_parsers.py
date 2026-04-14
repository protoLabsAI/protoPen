"""Tests for ad_attack parsers — BloodHound, Certipy, enum4linux-ng, ldapsearch, Impacket."""

from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock

from tools.parsers.ad_attack import (
    parse_bloodhound_collect,
    parse_certipy_find,
    parse_certipy_vuln,
    parse_enum4linux_ng,
    parse_ldapsearch,
    parse_kerberoast,
    parse_asreproast,
    parse_secretsdump,
)


@pytest.fixture
def store():
    return MagicMock()


# ── BloodHound ───────────────────────────────────────────────────────────────


class TestParseBloodhound:
    def test_collect_with_zip(self, store):
        raw = "Done! 500 users, 100 groups collected.\nOutput: 20260413_bloodhound.zip"
        entities = parse_bloodhound_collect(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "ad_finding"
        assert entities[0]["check"] == "bloodhound_collection"
        assert entities[0]["severity"] == "info"
        assert "20260413_bloodhound.zip" in entities[0]["zip_file"]
        assert entities[0]["counts"]["users"] == 500
        assert entities[0]["counts"]["groups"] == 100

    def test_collect_no_counts(self, store):
        raw = "Connection established. Output: data.zip"
        entities = parse_bloodhound_collect(raw, store)
        assert len(entities) == 1
        assert entities[0]["zip_file"] == "data.zip"
        assert entities[0]["counts"] == {}

    def test_collect_no_zip(self, store):
        raw = "Error: connection failed"
        entities = parse_bloodhound_collect(raw, store)
        assert len(entities) == 1
        assert entities[0]["zip_file"] == "unknown"


# ── Certipy find ─────────────────────────────────────────────────────────────


class TestParseCertipyFind:
    def test_templates_found(self, store):
        raw = json.dumps(
            {
                "Certificate Templates": {
                    "User": {
                        "Template Name": "User",
                        "Display Name": "User Certificate",
                        "Enabled": True,
                        "Client Authentication": True,
                        "Enrollee Supplies Subject": False,
                    },
                    "VulnTemplate": {
                        "Template Name": "VulnTemplate",
                        "Display Name": "Vulnerable Template",
                        "Enabled": True,
                        "Client Authentication": True,
                        "Enrollee Supplies Subject": True,
                        "Vulnerabilities": ["ESC1"],
                    },
                }
            }
        )
        entities = parse_certipy_find(raw, store)
        assert len(entities) == 2
        safe = [e for e in entities if e["target"] == "User"][0]
        vuln = [e for e in entities if e["target"] == "VulnTemplate"][0]
        assert safe["severity"] == "info"
        assert safe["vulnerabilities"] == []
        assert vuln["severity"] == "high"
        assert vuln["vulnerabilities"] == ["ESC1"]

    def test_empty_templates(self, store):
        raw = json.dumps({"Certificate Templates": {}})
        assert parse_certipy_find(raw, store) == []

    def test_invalid_json(self, store):
        assert parse_certipy_find("not json", store) == []


# ── Certipy vuln ─────────────────────────────────────────────────────────────


class TestParseCertipyVuln:
    def test_vulnerable_templates(self, store):
        raw = json.dumps(
            {
                "Certificate Templates": {
                    "ESC1-Vuln": {
                        "Template Name": "ESC1-Vuln",
                        "Display Name": "ESC1 Vulnerable",
                        "Vulnerabilities": ["ESC1"],
                        "Enabled": True,
                        "Client Authentication": True,
                        "Enrollee Supplies Subject": True,
                    },
                }
            }
        )
        entities = parse_certipy_vuln(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "critical"
        assert entities[0]["vulnerabilities"] == ["ESC1"]

    def test_no_vulnerable(self, store):
        raw = json.dumps(
            {
                "Certificate Templates": {
                    "Safe": {
                        "Template Name": "Safe",
                        "Vulnerabilities": [],
                    },
                }
            }
        )
        assert parse_certipy_vuln(raw, store) == []

    def test_invalid_json(self, store):
        assert parse_certipy_vuln("not json", store) == []


# ── enum4linux-ng ────────────────────────────────────────────────────────────


class TestParseEnum4linux:
    def test_shares_users_groups(self, store):
        raw = json.dumps(
            {
                "shares": [
                    {"name": "ADMIN$", "comment": "Remote Admin", "access": "NO ACCESS"},
                    {"name": "C$", "comment": "Default share", "access": "NO ACCESS"},
                ],
                "users": [
                    {"username": "Administrator", "name": "Built-in Administrator"},
                ],
                "groups": [
                    {"groupname": "Domain Admins", "members": ["Administrator", "svc_admin"]},
                ],
            }
        )
        entities = parse_enum4linux_ng(raw, store)
        assert len(entities) == 4  # 2 shares + 1 user + 1 group
        shares = [e for e in entities if e["check"] == "smb_share"]
        users = [e for e in entities if e["check"] == "smb_user"]
        groups = [e for e in entities if e["check"] == "smb_group"]
        assert len(shares) == 2
        assert len(users) == 1
        assert len(groups) == 1
        assert groups[0]["members"] == ["Administrator", "svc_admin"]

    def test_empty_results(self, store):
        raw = json.dumps({"shares": [], "users": [], "groups": []})
        assert parse_enum4linux_ng(raw, store) == []

    def test_invalid_json(self, store):
        assert parse_enum4linux_ng("not json", store) == []


# ── ldapsearch ───────────────────────────────────────────────────────────────


class TestParseLdapsearch:
    def test_parse_ldif(self, store):
        raw = (
            "# extended LDIF\n"
            "dn: CN=admin,DC=corp,DC=local\n"
            "cn: admin\n"
            "objectClass: user\n"
            "objectClass: person\n"
            "\n"
            "dn: CN=svc_sql,DC=corp,DC=local\n"
            "cn: svc_sql\n"
            "servicePrincipalName: MSSQLSvc/db01.corp.local\n"
            "\n"
        )
        entities = parse_ldapsearch(raw, store)
        assert len(entities) == 2
        assert entities[0]["target"] == "CN=admin,DC=corp,DC=local"
        assert entities[0]["check"] == "ldap_entry"
        assert entities[0]["attributes"]["cn"] == ["admin"]
        assert entities[0]["attributes"]["objectClass"] == ["user", "person"]
        assert entities[1]["attributes"]["servicePrincipalName"] == ["MSSQLSvc/db01.corp.local"]

    def test_empty_output(self, store):
        assert parse_ldapsearch("", store) == []

    def test_comments_only(self, store):
        raw = "# search result\n# numEntries: 0\n"
        assert parse_ldapsearch(raw, store) == []

    def test_entry_without_trailing_newline(self, store):
        raw = "dn: CN=test,DC=corp,DC=local\ncn: test"
        entities = parse_ldapsearch(raw, store)
        assert len(entities) == 1
        assert entities[0]["target"] == "CN=test,DC=corp,DC=local"


# ── Kerberoast ───────────────────────────────────────────────────────────────


class TestParseKerberoast:
    def test_hashes_found(self, store):
        raw = (
            "ServicePrincipalName  Name    MemberOf\n"
            "MSSQLSvc/db01         svc_sql CN=...\n"
            "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db01*$abc...\n"
            "$krb5tgs$23$*svc_web$CORP.LOCAL$HTTP/web01*$def...\n"
        )
        entities = parse_kerberoast(raw, store)
        assert len(entities) == 1
        assert entities[0]["hash_count"] == 2
        assert entities[0]["severity"] == "high"

    def test_no_hashes(self, store):
        raw = "No entries found."
        entities = parse_kerberoast(raw, store)
        assert len(entities) == 1
        assert entities[0]["hash_count"] == 0
        assert entities[0]["severity"] == "info"


# ── AS-REP Roast ─────────────────────────────────────────────────────────────


class TestParseASREPRoast:
    def test_hashes_found(self, store):
        raw = "$krb5asrep$23$user1@CORP.LOCAL:abc...\n$krb5asrep$23$user2@CORP.LOCAL:def..."
        entities = parse_asreproast(raw, store)
        assert len(entities) == 1
        assert entities[0]["hash_count"] == 2
        assert entities[0]["severity"] == "high"

    def test_no_hashes(self, store):
        raw = "No entries found."
        entities = parse_asreproast(raw, store)
        assert len(entities) == 1
        assert entities[0]["hash_count"] == 0
        assert entities[0]["severity"] == "info"


# ── secretsdump ──────────────────────────────────────────────────────────────


class TestParseSecretsdump:
    def test_ntlm_hashes(self, store):
        raw = (
            "[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
            "[*] Using the DRSUAPI method to get NTDS.DIT secrets\n"
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4:::\n"
            "[*] LSA Secrets\n"
        )
        entities = parse_secretsdump(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "critical"
        assert entities[0]["hash_count"] == 2
        assert "NTLM" in entities[0]["types_found"]
        assert "NTDS.DIT" in entities[0]["types_found"]
        assert "LSA" in entities[0]["types_found"]

    def test_no_hashes(self, store):
        raw = "[*] Target not a domain controller\n[-] Access denied"
        entities = parse_secretsdump(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "info"
        assert entities[0]["hash_count"] == 0
        assert entities[0]["types_found"] == []
