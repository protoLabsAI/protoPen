"""Scope validation for engagement target enforcement.

Validates that tool targets (IPs, hostnames, URLs) are within the defined
engagement scope before allowing execution.
"""
from __future__ import annotations

import ipaddress
import fnmatch
from typing import Optional
from urllib.parse import urlparse


# Maps tool action names to the argument key that contains the target.
# Tools not listed here have no extractable remote target.
_TOOL_TARGET_ARG: dict[str, str] = {
    "nmap_scan": "target",
    "nmap_vuln_scan": "target",
    "nikto_scan": "url",
    "gobuster_scan": "url",
    # Enhanced BlackArch
    "nmap_os_detect": "target",
    "nmap_udp_scan": "target",
    # DNS Enum
    "dig_query": "target",
    "nslookup": "target",
    "zone_transfer": "target",
    "reverse_lookup": "target",
    "dns_brute": "target",
    # Subdomain Discovery
    "subfinder": "target",
    "amass_passive": "target",
    # OSINT
    "theharvester": "target",
    "whois_lookup": "target",
}


class ScopeValidator:
    """Validates that targets fall within the engagement scope.

    Scope config format:
        {"type": "cidr",   "targets": ["192.168.4.0/24", "10.0.0.0/8"]}
        {"type": "domain", "targets": ["*.example.com"]}
        {"type": "any"}

    Args:
        scope_config: Dict with "type" and optional "targets" keys.
    """

    def __init__(self, scope_config: dict):
        self._type = scope_config.get("type", "any")
        self._targets = scope_config.get("targets", [])
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        if self._type == "cidr":
            for t in self._targets:
                try:
                    self._networks.append(ipaddress.ip_network(t, strict=False))
                except ValueError:
                    pass

    def is_in_scope(self, target: str) -> bool:
        """Check if a target string (IP, hostname, or URL) is within scope."""
        if self._type == "any":
            return True
        if not target:
            return False
        if self._type == "cidr":
            return self._check_cidr(target)
        elif self._type == "domain":
            return self._check_domain(target)
        return False

    def extract_target(self, tool_name: str, args: dict) -> Optional[str]:
        """Extract the remote target from a tool call's arguments.

        Returns None if the tool doesn't target a remote host.
        """
        arg_key = _TOOL_TARGET_ARG.get(tool_name)
        if arg_key is None:
            return None
        value = args.get(arg_key)
        if not value:
            return None
        return str(value)

    def _check_cidr(self, target: str) -> bool:
        ip = self._extract_ip(target)
        if ip is None:
            return False
        return any(ip in net for net in self._networks)

    def _check_domain(self, target: str) -> bool:
        hostname = self._extract_hostname(target)
        if not hostname:
            return False
        hostname_lower = hostname.lower()
        return any(
            fnmatch.fnmatch(hostname_lower, pattern.lower())
            for pattern in self._targets
        )

    @staticmethod
    def _extract_ip(target: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        try:
            return ipaddress.ip_address(target)
        except ValueError:
            pass
        try:
            parsed = urlparse(target)
            host = parsed.hostname
            if host:
                return ipaddress.ip_address(host)
        except (ValueError, TypeError):
            pass
        return None

    @staticmethod
    def _extract_hostname(target: str) -> Optional[str]:
        try:
            parsed = urlparse(target)
            if parsed.hostname:
                return parsed.hostname
        except (ValueError, TypeError):
            pass
        try:
            ipaddress.ip_address(target)
            return None
        except ValueError:
            pass
        if target and not target.startswith("/"):
            return target
        return None
