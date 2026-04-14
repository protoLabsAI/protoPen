"""Opsec tool — MAC randomization, interface fingerprint management, scan hardening.

Handles pre/post engagement interface preparation to reduce blue team detectability
during authorized penetration tests. Also provides nmap flag profiles for each
engagement mode (passive/active/redteam).
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from tools._tool_base import Tool

logger = logging.getLogger(__name__)

_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}")


class OpsecTool(Tool):
    """MAC randomization, interface fingerprint management, and scan opsec profiles."""

    @property
    def name(self) -> str:
        return "opsec"

    @property
    def description(self) -> str:
        return (
            "Opsec management for engagement fingerprint reduction. Actions:\n"
            "- mac_randomize: Randomize MAC on a network interface\n"
            "- mac_restore: Restore a saved original MAC address\n"
            "- mac_status: Show current MAC on an interface\n"
            "- pre_scan_setup: Randomize MAC on all engagement interfaces + print nmap opsec flags\n"
            "- post_scan_cleanup: Restore original MACs on all interfaces\n"
            "- nmap_flags: Return opsec-hardened nmap flag set for a given engagement mode"
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "mac_randomize",
                        "mac_restore",
                        "mac_status",
                        "pre_scan_setup",
                        "post_scan_cleanup",
                        "nmap_flags",
                    ],
                    "description": "Opsec action to perform.",
                },
                "interface": {
                    "type": "string",
                    "description": "Network interface name (e.g. wlan0, eth0, wlan1mon).",
                },
                "original_mac": {
                    "type": "string",
                    "description": "MAC address to restore (for mac_restore action).",
                },
                "interfaces": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of interfaces to process (for pre/post scan actions).",
                },
                "mode": {
                    "type": "string",
                    "enum": ["passive", "active", "redteam"],
                    "description": "Engagement mode — controls how aggressive opsec flags are.",
                },
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        if action == "mac_randomize":
            return await self._mac_randomize(kwargs.get("interface", ""))
        if action == "mac_restore":
            return await self._mac_restore(kwargs.get("interface", ""), kwargs.get("original_mac", ""))
        if action == "mac_status":
            return await self._mac_status(kwargs.get("interface", ""))
        if action == "pre_scan_setup":
            return await self._pre_scan_setup(kwargs.get("interfaces", []))
        if action == "post_scan_cleanup":
            return await self._post_scan_cleanup(kwargs.get("interfaces", []))
        if action == "nmap_flags":
            return self._nmap_flags(kwargs.get("mode", "active"))
        return f"Unknown action: {action}"

    # ── internal helpers ─────────────────────────────────────────────────────

    async def _run_cmd(self, *cmd: str, timeout: int = 15) -> tuple[int, str]:
        """Run a command, return (returncode, output)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode or 0, stdout.decode(errors="replace").strip()
        except FileNotFoundError:
            return 127, f"Command not found: {cmd[0]}"
        except asyncio.TimeoutError:
            return 124, f"Timed out: {' '.join(cmd)}"
        except Exception as exc:
            return 1, str(exc)

    async def _get_mac(self, interface: str) -> str:
        """Return current MAC for an interface using 'ip link show'."""
        rc, out = await self._run_cmd("ip", "link", "show", interface)
        if rc != 0:
            return ""
        m = _MAC_RE.search(out)
        return m.group(0) if m else ""

    async def _set_mac(self, interface: str, mac: str) -> tuple[bool, str]:
        """Set MAC on interface via 'ip link'. Returns (success, message)."""
        # Bring interface down, change MAC, bring back up
        rc, out = await self._run_cmd("sudo", "ip", "link", "set", interface, "down")
        if rc != 0:
            return False, f"Failed to bring {interface} down: {out}"
        rc, out = await self._run_cmd("sudo", "ip", "link", "set", interface, "address", mac)
        if rc != 0:
            await self._run_cmd("sudo", "ip", "link", "set", interface, "up")
            return False, f"Failed to set MAC on {interface}: {out}"
        rc, out = await self._run_cmd("sudo", "ip", "link", "set", interface, "up")
        if rc != 0:
            return False, f"MAC changed but failed to bring {interface} back up: {out}"
        return True, f"MAC on {interface} set to {mac}"

    async def _random_mac(self, interface: str) -> tuple[bool, str, str]:
        """Randomize MAC using macchanger -r. Returns (success, new_mac, message)."""
        # Try macchanger first (preferred — preserves vendor prefix option)
        rc, out = await self._run_cmd("which", "macchanger")
        if rc == 0:
            # Bring interface down
            await self._run_cmd("sudo", "ip", "link", "set", interface, "down")
            rc, out = await self._run_cmd("sudo", "macchanger", "-r", interface)
            await self._run_cmd("sudo", "ip", "link", "set", interface, "up")
            if rc == 0:
                m = _MAC_RE.search(out)
                new_mac = m.group(0) if m else ""
                return True, new_mac, out
            return False, "", f"macchanger failed: {out}"

        # Fallback: generate a random MAC manually (locally administered, unicast)
        import random

        octets = [random.randint(0, 255) for _ in range(6)]
        octets[0] = (octets[0] & 0xFE) | 0x02  # unicast, locally administered
        new_mac = ":".join(f"{b:02x}" for b in octets)
        ok, msg = await self._set_mac(interface, new_mac)
        return ok, new_mac if ok else "", msg

    # ── actions ──────────────────────────────────────────────────────────────

    async def _mac_randomize(self, interface: str) -> str:
        if not interface:
            return "Error: interface is required."
        original = await self._get_mac(interface)
        if not original:
            return f"Error: could not read MAC for interface '{interface}'. Is it correct?"

        ok, new_mac, detail = await self._random_mac(interface)
        if not ok:
            return f"MAC randomization failed on {interface}: {detail}"

        logger.info("[opsec] %s: MAC randomized %s → %s", interface, original, new_mac)
        return (
            f"MAC randomized on {interface}\n"
            f"  Original : {original}\n"
            f"  New      : {new_mac}\n"
            f"  Save the original MAC — use mac_restore to revert after the engagement."
        )

    async def _mac_restore(self, interface: str, original_mac: str) -> str:
        if not interface or not original_mac:
            return "Error: both interface and original_mac are required."
        ok, msg = await self._set_mac(interface, original_mac)
        if ok:
            logger.info("[opsec] %s: MAC restored to %s", interface, original_mac)
            return f"MAC on {interface} restored to {original_mac}"
        return f"MAC restore failed: {msg}"

    async def _mac_status(self, interface: str) -> str:
        if not interface:
            return "Error: interface is required."
        mac = await self._get_mac(interface)
        if not mac:
            return f"Could not read MAC for '{interface}'. Check the interface name."

        # Heuristic: locally administered bit set = randomized
        first_octet = int(mac.split(":")[0].replace("-", ""), 16)
        randomized = bool(first_octet & 0x02)
        return (
            f"Interface : {interface}\n"
            f"MAC       : {mac}\n"
            f"Status    : {'randomized (locally administered)' if randomized else 'hardware/OUI MAC'}"
        )

    async def _pre_scan_setup(self, interfaces: list[str]) -> str:
        if not interfaces:
            return (
                "No interfaces specified. Pass the list of interfaces you want randomized "
                "(e.g. ['wlan0', 'eth0']). Skipping MAC randomization.\n\n" + self._nmap_flags("active")
            )
        lines = ["## Pre-scan Opsec Setup\n"]
        for iface in interfaces:
            original = await self._get_mac(iface)
            if not original:
                lines.append(f"  {iface}: skipped (interface not found)")
                continue
            ok, new_mac, detail = await self._random_mac(iface)
            if ok:
                lines.append(f"  {iface}: {original} → {new_mac} ✓")
                logger.info("[opsec] pre-scan: %s randomized %s → %s", iface, original, new_mac)
            else:
                lines.append(f"  {iface}: randomization failed — {detail}")
        lines.append("\n" + self._nmap_flags("active"))
        return "\n".join(lines)

    async def _post_scan_cleanup(self, interfaces: list[str]) -> str:
        lines = ["## Post-scan Opsec Cleanup\n"]
        for iface in interfaces:
            mac = await self._get_mac(iface)
            first_octet = int(mac.split(":")[0].replace("-", ""), 16) if mac else 0
            if mac and (first_octet & 0x02):
                lines.append(
                    f"  {iface}: currently {mac} (locally administered / randomized). "
                    f"Run mac_restore with your original MAC to revert."
                )
            elif mac:
                lines.append(f"  {iface}: {mac} (appears to be hardware MAC — no restore needed)")
            else:
                lines.append(f"  {iface}: could not read MAC")
        return "\n".join(lines)

    def _nmap_flags(self, mode: str) -> str:
        """Return opsec-hardened nmap flags for each engagement mode."""
        base = "## Nmap Opsec Flags\n\nAdd these to every nmap invocation to reduce your scan's detectability:\n\n"
        if mode == "passive":
            flags = [
                "--spoof-mac 0          # random MAC in packet headers",
                "-T2                    # polite timing — slower, lower IDS signature",
                "--randomize-hosts      # randomize host scan order",
                "--data-length 25       # random packet padding",
                "--max-retries 1        # fewer retries = fewer log entries",
            ]
            note = "(Passive mode — minimizing any active-scan signature)"
        elif mode == "redteam":
            flags = [
                "--spoof-mac 0          # random MAC in packet headers",
                "-T1                    # sneaky timing — very slow, evades most IDS",
                "-D RND:5               # 5 random decoy IPs mixed with real source",
                "--randomize-hosts      # randomize host scan order",
                "--data-length 25       # random packet padding",
                "--source-port 53       # spoof source port as DNS",
                "--max-retries 1",
            ]
            note = "(Redteam mode — full evasion: decoys, spoofed ports, sneaky timing)"
        else:  # active
            flags = [
                "--spoof-mac 0          # random MAC in packet headers",
                "-T2                    # polite timing — avoids most rate-limit triggers",
                "--randomize-hosts      # randomize host scan order",
                "--data-length 25       # random packet padding",
                "--max-retries 2",
            ]
            note = "(Active mode — balanced: quieter than default T3 but still practical)"

        flag_str = "\n".join(f"  {f}" for f in flags)
        return f"{base}```\nnmap {flag_str} <target>\n```\n\n{note}"
