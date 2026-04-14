"""BlackArch curated tool wrappers + guarded shell fallback.

Provides structured interfaces to common pen testing CLI tools with
parsed output, plus a shell_exec fallback with command filtering.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
from pathlib import Path
from typing import Any, Optional

from tools.parsers import ingest_output
from tools._tool_base import Tool

logger = logging.getLogger(__name__)

_BLOCKED_COMMANDS = {
    "rm",
    "rmdir",
    "mkfs",
    "dd",
    "fdisk",
    "parted",
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "init",
    "chmod",
    "chown",
    "chgrp",
    "systemctl",
    "service",
    "useradd",
    "userdel",
    "passwd",
    "usermod",
    "iptables",
    "ip6tables",
    "nft",
}

_SAFE_COMMANDS = {
    "nmap",
    "tshark",
    "tcpdump",
    "wireshark",
    "kismet",
    "hcxdumptool",
    "hcxpcapngtool",
    "airodump-ng",
    "airmon-ng",
    "nikto",
    "gobuster",
    "dirb",
    "ffuf",
    "sqlmap",
    "wpscan",
    "hashcat",
    "john",
    "bettercap",
    "dig",
    "nslookup",
    "whois",
    "host",
    "ping",
    "traceroute",
    "mtr",
    "curl",
    "wget",
    "arp-scan",
    "netdiscover",
    "enum4linux",
    "smbclient",
    "rpcclient",
    "hydra",
    "medusa",
}


class BlackArchTool(Tool):
    """Curated wrappers for BlackArch pen testing tools + guarded shell access."""

    def __init__(
        self,
        wifi_interface: str = "wlan1",
        monitor_interface: str = "wlan1mon",
        workspace: str = "/tmp/protopen",
    ):
        self._wifi = wifi_interface
        self._mon = monitor_interface
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._engagement_manager = None  # Set externally for shell_exec force override

    @property
    def name(self) -> str:
        return "blackarch"

    @property
    def description(self) -> str:
        return (
            "Run pen testing tools from the BlackArch arsenal on the local system. "
            "Curated tools with structured output: nmap (network scanning), "
            "aircrack-ng suite (WiFi capture/crack), bettercap (MITM/recon), "
            "hashcat (hash cracking), sqlmap (SQL injection), nikto/gobuster (web scanning). "
            "Also provides a guarded shell_exec for any other installed tool."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": [
                        "nmap_scan",
                        "nmap_vuln_scan",
                        "nmap_os_detect",
                        "nmap_udp_scan",
                        "airmon_start",
                        "airmon_stop",
                        "airodump_scan",
                        "bettercap_recon",
                        "bettercap_mitm",
                        "hashcat_crack",
                        "hashcat_rules",
                        "nikto_scan",
                        "gobuster_scan",
                        "tshark_capture",
                        "shell_exec",
                    ],
                },
                "target": {"type": "string", "description": "Target IP, hostname, or CIDR"},
                "ports": {"type": "string", "description": "Port spec (e.g. '22,80,443')"},
                "interface": {"type": "string", "description": "Network interface override"},
                "wordlist": {"type": "string", "description": "Path to wordlist file"},
                "hash_file": {"type": "string", "description": "Path to hash file"},
                "hash_type": {"type": "integer", "description": "Hashcat hash type ID"},
                "url": {"type": "string", "description": "Target URL for web scanning"},
                "command": {"type": "string", "description": "Full command for shell_exec"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 120)"},
                "count": {"type": "integer", "description": "Packet count for captures"},
                "output_file": {"type": "string", "description": "Output file path"},
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        dispatch = {
            "nmap_scan": lambda: self.nmap_scan(
                kwargs.get("target", ""),
                kwargs.get("ports"),
                kwargs.get("timeout", 120),
            ),
            "nmap_vuln_scan": lambda: self.nmap_vuln_scan(
                kwargs.get("target", ""),
                kwargs.get("timeout", 300),
            ),
            "nmap_os_detect": lambda: self.nmap_os_detect(
                kwargs.get("target", ""),
                kwargs.get("timeout", 300),
            ),
            "nmap_udp_scan": lambda: self.nmap_udp_scan(
                kwargs.get("target", ""),
                kwargs.get("ports"),
                kwargs.get("timeout", 300),
            ),
            "airmon_start": lambda: self.airmon_start(kwargs.get("interface")),
            "airmon_stop": lambda: self.airmon_stop(kwargs.get("interface")),
            "airodump_scan": lambda: self.airodump_scan(
                kwargs.get("interface"),
                kwargs.get("timeout", 30),
                kwargs.get("output_file"),
            ),
            "bettercap_recon": lambda: self.bettercap_recon(
                kwargs.get("interface", "eth0"),
                kwargs.get("timeout", 30),
            ),
            "bettercap_mitm": lambda: self.bettercap_mitm(
                kwargs.get("target", ""),
                kwargs.get("interface", "eth0"),
                kwargs.get("timeout", 60),
            ),
            "hashcat_crack": lambda: self.hashcat_crack(
                kwargs.get("hash_file", ""),
                kwargs.get("hash_type", 22000),
                kwargs.get("wordlist", "/usr/share/wordlists/rockyou.txt"),
                kwargs.get("timeout", 600),
            ),
            "hashcat_rules": lambda: self.hashcat_rules(
                kwargs.get("hash_file", ""),
                kwargs.get("hash_type", 22000),
                kwargs.get("wordlist", "/usr/share/wordlists/rockyou.txt"),
                kwargs.get("rules", "/usr/share/hashcat/rules/best64.rule"),
                kwargs.get("timeout", 600),
            ),
            "nikto_scan": lambda: self.nikto_scan(
                kwargs.get("url", ""),
                kwargs.get("timeout", 120),
            ),
            "gobuster_scan": lambda: self.gobuster_scan(
                kwargs.get("url", ""),
                kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
                kwargs.get("timeout", 120),
            ),
            "tshark_capture": lambda: self.tshark_capture(
                kwargs.get("interface"),
                kwargs.get("count", 100),
                kwargs.get("timeout", 30),
            ),
            "shell_exec": lambda: self.shell_exec(
                kwargs.get("command", ""),
                kwargs.get("timeout", 120),
                kwargs.get("force", False),
            ),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            result = await fn()
            ingest_output("blackarch", action, result, getattr(self, "_target_store", None))
            return result
        except Exception as exc:
            return f"BlackArch error ({action}): {exc}"

    async def _run(self, *args: str, timeout: int = 120) -> str:
        logger.info("Running: %s", " ".join(args))
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return f"Command timed out after {timeout}s: {' '.join(args)}"
        output = stdout.decode(errors="replace")
        if stderr:
            output += f"\n[stderr] {stderr.decode(errors='replace')}"
        return output.strip()

    # Opsec nmap flags applied to every scan:
    #   --spoof-mac 0      random MAC in packet headers
    #   -T2                polite timing — avoids most IDS rate-limit triggers
    #   --randomize-hosts  randomize scan order
    #   --data-length 25   random packet padding to break signature matching
    _NMAP_OPSEC = ["--spoof-mac", "0", "-T2", "--randomize-hosts", "--data-length", "25"]

    async def nmap_scan(self, target: str, ports: Optional[str] = None, timeout: int = 120) -> str:
        args = ["nmap", "-sV", "-oX", "-"] + self._NMAP_OPSEC
        if ports:
            args.extend(["-p", ports])
        args.append(target)
        return await self._run(*args, timeout=timeout)

    async def nmap_vuln_scan(self, target: str, timeout: int = 300) -> str:
        return await self._run(
            "nmap",
            "-sV",
            "--script",
            "vuln",
            "-oX",
            "-",
            *self._NMAP_OPSEC,
            target,
            timeout=timeout,
        )

    async def nmap_os_detect(self, target: str, timeout: int = 300) -> str:
        """OS detection scan (-O flag, requires root)."""
        return await self._run(
            "nmap",
            "-O",
            "-sV",
            "-oX",
            "-",
            *self._NMAP_OPSEC,
            target,
            timeout=timeout,
        )

    async def nmap_udp_scan(self, target: str, ports: Optional[str] = None, timeout: int = 300) -> str:
        """UDP scan (-sU flag, requires root)."""
        args = ["nmap", "-sU", "-sV", "-oX", "-"] + self._NMAP_OPSEC
        if ports:
            args.extend(["-p", ports])
        args.append(target)
        return await self._run(*args, timeout=timeout)

    async def airmon_start(self, interface: Optional[str] = None) -> str:
        return await self._run("airmon-ng", "start", interface or self._wifi)

    async def airmon_stop(self, interface: Optional[str] = None) -> str:
        return await self._run("airmon-ng", "stop", interface or self._mon)

    async def airodump_scan(
        self,
        interface: Optional[str] = None,
        timeout: int = 30,
        output_file: Optional[str] = None,
    ) -> str:
        out = output_file or str(self._workspace / "airodump")
        return await self._run(
            "airodump-ng",
            "--write",
            out,
            "--output-format",
            "csv",
            interface or self._mon,
            timeout=timeout,
        )

    async def bettercap_recon(self, interface: str = "eth0", timeout: int = 30) -> str:
        caplet = f"set net.interface {interface}; net.recon on; sleep {timeout}; net.show; quit"
        return await self._run("bettercap", "-iface", interface, "-eval", caplet, timeout=timeout + 10)

    async def bettercap_mitm(self, target: str, interface: str = "eth0", timeout: int = 60) -> str:
        """ARP spoof MITM with network sniffing via bettercap."""
        caplet = (
            f"set net.interface {interface}; "
            f"set arp.spoof.targets {target}; "
            "net.recon on; arp.spoof on; net.sniff on; "
            f"sleep {timeout}; net.show; quit"
        )
        return await self._run(
            "bettercap",
            "-iface",
            interface,
            "-eval",
            caplet,
            timeout=timeout + 10,
        )

    async def hashcat_crack(
        self,
        hash_file: str,
        hash_type: int = 22000,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        timeout: int = 600,
    ) -> str:
        return await self._run(
            "hashcat",
            "-m",
            str(hash_type),
            "-a",
            "0",
            hash_file,
            wordlist,
            "--force",
            timeout=timeout,
        )

    async def hashcat_rules(
        self,
        hash_file: str,
        hash_type: int = 22000,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        rules: str = "/usr/share/hashcat/rules/best64.rule",
        timeout: int = 600,
    ) -> str:
        """Rule-based hashcat attack (-a 0 with rules)."""
        return await self._run(
            "hashcat",
            "-m",
            str(hash_type),
            "-a",
            "0",
            hash_file,
            wordlist,
            "-r",
            rules,
            "--force",
            timeout=timeout,
        )

    async def nikto_scan(self, url: str, timeout: int = 120) -> str:
        return await self._run("nikto", "-h", url, timeout=timeout)

    async def gobuster_scan(
        self,
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        timeout: int = 120,
    ) -> str:
        return await self._run("gobuster", "dir", "-u", url, "-w", wordlist, "-q", timeout=timeout)

    async def tshark_capture(self, interface: Optional[str] = None, count: int = 100, timeout: int = 30) -> str:
        return await self._run("tshark", "-i", interface or self._mon, "-c", str(count), timeout=timeout)

    async def shell_exec(self, command: str, timeout: int = 120, force: bool = False) -> str:
        """Execute a shell command with deny-by-default filtering.

        Only commands in _SAFE_COMMANDS are allowed.  Unknown commands are
        BLOCKED unless force=True AND engagement mode is REDTEAM (2).
        Commands in _BLOCKED_COMMANDS are always denied regardless of force.
        """
        parts = shlex.split(command)
        if not parts:
            return "Empty command"
        base_cmd = Path(parts[0]).name

        # Hard deny — never allowed, even with force
        if base_cmd in _BLOCKED_COMMANDS:
            return f"Blocked: '{base_cmd}' is on the deny list for safety"

        # Allow list — known-safe security tools
        if base_cmd in _SAFE_COMMANDS:
            return await self._run(*parts, timeout=timeout)

        # Unknown command — deny by default
        eng_mode = 0
        if self._engagement_manager:
            eng_mode = self._engagement_manager.mode.value

        if force and eng_mode >= 2:  # REDTEAM
            logger.warning("shell_exec: FORCE override for '%s' in REDTEAM mode", base_cmd)
            return await self._run(*parts, timeout=timeout)

        if force:
            return (
                f"Blocked: '{base_cmd}' is not in the allow list. "
                f"force=True requires REDTEAM mode (current mode level: {eng_mode})"
            )

        return f"Blocked: '{base_cmd}' is not in the allow list. Use a curated action or add to _SAFE_COMMANDS."
