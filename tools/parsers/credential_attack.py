"""Parser for hydra credential attack output, Responder hash capture, and CrackMapExec SMB enum."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

_HYDRA_SUCCESS_RE = re.compile(r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)")

# Responder NTLMv2-SSP hash line example:
# [SMB] NTLMv2-SSP Hash     : WORKGROUP\alice::WORKGROUP:aabbcc...:...
_RESPONDER_HASH_RE = re.compile(
    r"\[.*?NTLMv2-SSP Hash\s*[:\-]\s*"
    r"(?P<domain>[^\\]+)\\(?P<username>\S+)::"
    r"(?P<rest>\S+)"
)
# Source IP line:
# [SMB] NTLMv2-SSP Client   : 192.168.1.50
_RESPONDER_CLIENT_RE = re.compile(r"\[.*?NTLMv2-SSP Client\s*[:\-]\s*(?P<ip>\S+)")

# CrackMapExec output patterns:
# SMB  192.168.1.5  445  WINHOST  [+] Enumerated shares
# SMB  192.168.1.5  445  WINHOST  ADMIN$  NO ACCESS  Remote Admin
# SMB  192.168.1.5  445  WINHOST  alice   2024-01-01 ...
# SMB  192.168.1.5  445  WINHOST  Admins  membercount: 3
_CME_HOST_RE = re.compile(
    r"SMB\s+(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<hostname>\S+)\s+"
    r"\[(?P<status>[+*\-])\]\s+(?P<msg>.+)"
)
_CME_SHARE_RE = re.compile(
    r"SMB\s+(?P<host>\S+)\s+\d+\s+\S+\s+"
    r"(?P<share>\$?\w[\w\-\.]*)\s+"
    r"(?P<perms>READ|WRITE|NO ACCESS|READ,WRITE)\s*"
    r"(?P<remark>.*)"
)
_CME_USER_RE = re.compile(
    r"SMB\s+(?P<host>\S+)\s+\d+\s+\S+\s+"
    r"(?P<username>[a-zA-Z0-9_\-\.]+)\s+"
    r"\d{4}-\d{2}-\d{2}"  # last PW set date confirms it's a user line
)
_CME_GROUP_RE = re.compile(
    r"SMB\s+(?P<host>\S+)\s+\d+\s+\S+\s+"
    r"(?P<group>.+?)\s+membercount:\s*(?P<count>\d+)",
    re.IGNORECASE,
)


def parse_hydra(raw: str, store: "TargetStore") -> list[dict]:
    """Parse hydra output for successful logins."""
    entities: list[dict] = []
    for m in _HYDRA_SUCCESS_RE.finditer(raw):
        entities.append(
            {
                "type": "credential",
                "port": int(m.group(1)),
                "service": m.group(2),
                "host": m.group(3),
                "username": m.group(4),
                "password": m.group(5),
            }
        )
    return entities


def parse_responder(raw: str, store: "TargetStore") -> list[dict]:
    """Parse Responder output for captured NetNTLM hashes.

    Extracts lines containing 'NTLMv2-SSP Hash' and correlates them with the
    nearest preceding 'NTLMv2-SSP Client' line to determine the source IP.
    Returns entities of type 'credential_capture'.
    """
    entities: list[dict] = []
    lines = raw.splitlines()
    last_client_ip = ""

    for line in lines:
        client_match = _RESPONDER_CLIENT_RE.search(line)
        if client_match:
            last_client_ip = client_match.group("ip")
            continue

        hash_match = _RESPONDER_HASH_RE.search(line)
        if hash_match:
            domain = hash_match.group("domain").strip()
            user = hash_match.group("username").strip()
            full_hash = f"{domain}\\{user}::{hash_match.group('rest')}"
            entities.append(
                {
                    "type": "credential_capture",
                    "username": user,
                    "domain": domain,
                    "hash": full_hash,
                    "source_ip": last_client_ip,
                    "hash_type": "NTLMv2-SSP",
                }
            )

    return entities


def parse_crackmapexec_enum(raw: str, store: "TargetStore") -> list[dict]:
    """Parse CrackMapExec SMB enumeration output.

    Extracts discovered hosts, share names with permissions, enumerated
    usernames, and group names with member counts.
    Returns entities of type 'smb_enum'.
    """
    entities: list[dict] = []
    seen_hosts: set[str] = set()

    for line in raw.splitlines():
        line = line.rstrip()

        # Groups (check before user to avoid false-positive username matches)
        gm = _CME_GROUP_RE.search(line)
        if gm:
            entities.append(
                {
                    "type": "smb_enum",
                    "host": gm.group("host"),
                    "subtype": "group",
                    "group": gm.group("group").strip(),
                    "member_count": int(gm.group("count")),
                }
            )
            continue

        # Shares
        sm = _CME_SHARE_RE.search(line)
        if sm:
            entities.append(
                {
                    "type": "smb_enum",
                    "host": sm.group("host"),
                    "subtype": "share",
                    "share": sm.group("share"),
                    "permissions": sm.group("perms").strip(),
                    "remark": sm.group("remark").strip(),
                }
            )
            continue

        # Users (lines with a datestamp after username)
        um = _CME_USER_RE.search(line)
        if um:
            entities.append(
                {
                    "type": "smb_enum",
                    "host": um.group("host"),
                    "subtype": "user",
                    "username": um.group("username"),
                }
            )
            continue

        # General [+] host status messages
        hm = _CME_HOST_RE.search(line)
        if hm:
            host_key = f"{hm.group('host')}:{hm.group('hostname')}"
            if host_key not in seen_hosts and hm.group("status") == "+":
                seen_hosts.add(host_key)
                entities.append(
                    {
                        "type": "smb_enum",
                        "host": hm.group("host"),
                        "subtype": "host",
                        "hostname": hm.group("hostname"),
                        "port": int(hm.group("port")),
                        "message": hm.group("msg").strip(),
                    }
                )

    return entities


# ── Register all parsers ─────────────────────────────────────────────────────

PARSER_MAP[("credential_attack", "hydra_brute")] = parse_hydra
PARSER_MAP[("credential_attack", "hydra_spray")] = parse_hydra
PARSER_MAP[("credential_attack", "hydra_combo")] = parse_hydra
PARSER_MAP[("credential_attack", "responder")] = parse_responder
PARSER_MAP[("credential_attack", "crackmapexec_enum")] = parse_crackmapexec_enum
