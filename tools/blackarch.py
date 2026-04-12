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

try:
    from nanobot.agent.tools.base import Tool
except ImportError:
    from tools._tool_base import Tool

logger = logging.getLogger(__name__)

_BLOCKED_COMMANDS = {
    "rm", "rmdir", "mkfs", "dd", "fdisk", "parted",
    "shutdown", "reboot", "poweroff", "halt", "init",
    "chmod", "chown", "chgrp",
    "systemctl", "service",
    "useradd", "userdel", "passwd", "usermod",
    "iptables", "ip6tables", "nft",
}

_SAFE_COMMANDS = {
    "nmap", "tshark", "tcpdump", "wireshark",
    "kismet", "hcxdumptool", "hcxpcapngtool",
    "airodump-ng", "airmon-ng",
    "nikto", "gobuster", "dirb", "ffuf",
    "sqlmap", "wpscan",
    "hashcat", "john",
    "bettercap",
    "dig", "nslookup", "whois", "host",
    "ping", "traceroute", "mtr",
    "curl", "wget",
    "arp-scan", "netdiscover",
    "enum4linux", "smbclient", "rpcclient",
    "hydra", "medusa",
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
                        "nmap_scan", "nmap_vuln_scan",
                        "airmon_start", "airmon_stop", "airodump_scan",
                        "bettercap_recon",
                        "hashcat_crack",
                        "nikto_scan", "gobuster_scan",
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
                kwargs.get("target", ""), kwargs.get("ports"), kwargs.get("timeout", 120),
            ),
            "nmap_vuln_scan": lambda: self.nmap_vuln_scan(
                kwargs.get("target", ""), kwargs.get("timeout", 300),
            ),
            "airmon_start": lambda: self.airmon_start(kwargs.get("interface")),
            "airmon_stop": lambda: self.airmon_stop(kwargs.get("interface")),
            "airodump_scan": lambda: self.airodump_scan(
                kwargs.get("interface"), kwargs.get("timeout", 30), kwargs.get("output_file"),
            ),
            "bettercap_recon": lambda: self.bettercap_recon(
                kwargs.get("interface", "eth0"), kwargs.get("timeout", 30),
            ),
            "hashcat_crack": lambda: self.hashcat_crack(
                kwargs.get("hash_file", ""), kwargs.get("hash_type", 22000),
                kwargs.get("wordlist", "/usr/share/wordlists/rockyou.txt"),
                kwargs.get("timeout", 600),
            ),
            "nikto_scan": lambda: self.nikto_scan(
                kwargs.get("url", ""), kwargs.get("timeout", 120),
            ),
            "gobuster_scan": lambda: self.gobuster_scan(
                kwargs.get("url", ""),
                kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
                kwargs.get("timeout", 120),
            ),
            "tshark_capture": lambda: self.tshark_capture(
                kwargs.get("interface"), kwargs.get("count", 100), kwargs.get("timeout", 30),
            ),
            "shell_exec": lambda: self.shell_exec(
                kwargs.get("command", ""), kwargs.get("timeout", 120),
            ),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            return await fn()
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

    async def nmap_scan(self, target: str, ports: Optional[str] = None, timeout: int = 120) -> str:
        args = ["nmap", "-sV", "-oX", "-"]
        if ports:
            args.extend(["-p", ports])
        args.append(target)
        return await self._run(*args, timeout=timeout)

    async def nmap_vuln_scan(self, target: str, timeout: int = 300) -> str:
        return await self._run("nmap", "-sV", "--script", "vuln", "-oX", "-", target, timeout=timeout)

    async def airmon_start(self, interface: Optional[str] = None) -> str:
        return await self._run("airmon-ng", "start", interface or self._wifi)

    async def airmon_stop(self, interface: Optional[str] = None) -> str:
        return await self._run("airmon-ng", "stop", interface or self._mon)

    async def airodump_scan(
        self, interface: Optional[str] = None, timeout: int = 30, output_file: Optional[str] = None,
    ) -> str:
        out = output_file or str(self._workspace / "airodump")
        return await self._run(
            "airodump-ng", "--write", out, "--output-format", "csv",
            interface or self._mon, timeout=timeout,
        )

    async def bettercap_recon(self, interface: str = "eth0", timeout: int = 30) -> str:
        caplet = f"set net.interface {interface}; net.recon on; sleep {timeout}; net.show; quit"
        return await self._run("bettercap", "-iface", interface, "-eval", caplet, timeout=timeout + 10)

    async def hashcat_crack(
        self, hash_file: str, hash_type: int = 22000,
        wordlist: str = "/usr/share/wordlists/rockyou.txt", timeout: int = 600,
    ) -> str:
        return await self._run(
            "hashcat", "-m", str(hash_type), "-a", "0", hash_file, wordlist, "--force",
            timeout=timeout,
        )

    async def nikto_scan(self, url: str, timeout: int = 120) -> str:
        return await self._run("nikto", "-h", url, timeout=timeout)

    async def gobuster_scan(
        self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", timeout: int = 120,
    ) -> str:
        return await self._run("gobuster", "dir", "-u", url, "-w", wordlist, "-q", timeout=timeout)

    async def tshark_capture(self, interface: Optional[str] = None, count: int = 100, timeout: int = 30) -> str:
        return await self._run("tshark", "-i", interface or self._mon, "-c", str(count), timeout=timeout)

    async def shell_exec(self, command: str, timeout: int = 120) -> str:
        parts = shlex.split(command)
        if not parts:
            return "Empty command"
        base_cmd = Path(parts[0]).name
        if base_cmd in _BLOCKED_COMMANDS:
            return f"Blocked: '{base_cmd}' is on the deny list for safety"
        if base_cmd not in _SAFE_COMMANDS:
            logger.warning("shell_exec: unrecognized command '%s' — allowing with caution", base_cmd)
        return await self._run(*parts, timeout=timeout)
