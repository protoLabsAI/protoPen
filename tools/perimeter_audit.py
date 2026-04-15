"""Perimeter audit — router/CPE attack surface, UPnP, NAT traversal, firewall gaps.

Simulates what an external attacker discovers about the network boundary:
  - Router fingerprinting and default credential testing
  - UPnP device discovery and abuse
  - Port-forward enumeration
  - WAN-side port scan (routes via pivot/proxy if configured)
  - DNS rebinding vulnerability check
  - Router-specific CVE checks via RouterSploit
  - Firewall egress/ingress gap analysis
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from tools.parsers import ingest_output
from tools._tool_base import Tool

logger = logging.getLogger(__name__)


class PerimeterAuditTool(Tool):
    """Router/CPE and network perimeter audit — UPnP, NAT, RouterSploit, WAN exposure."""

    def __init__(self, workspace: str = "/tmp/protopen"):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None

    @property
    def name(self) -> str:
        return "perimeter_audit"

    @property
    def description(self) -> str:
        return (
            "Network perimeter and router/CPE audit. Discovers router fingerprint, "
            "tests default credentials, enumerates UPnP port mappings, checks for "
            "RouterSploit-known CVEs, and identifies NAT/firewall exposure gaps."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Audit action to perform",
                    "enum": [
                        "router_fingerprint",
                        "upnp_discover",
                        "upnp_portmap",
                        "upnp_add_portmap",
                        "default_creds",
                        "routersploit_scan",
                        "wan_portscan",
                        "dns_rebind_check",
                        "firewall_egress",
                        "full_perimeter",
                    ],
                },
                "target": {
                    "type": "string",
                    "description": "Router IP (default: gateway) or WAN IP for wan_portscan",
                },
                "interface": {"type": "string", "description": "Network interface (default: eth0)"},
                "external_ip": {"type": "string", "description": "WAN IP to scan from external vantage"},
                "pivot_host": {
                    "type": "string",
                    "description": "SSH pivot host for WAN-side scanning (user@host)",
                },
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 60)"},
            },
            "required": ["action"],
        }

    @staticmethod
    def _is_public_ip(ip: str) -> bool:
        """Return True if ip is a routable public address (not RFC-1918/loopback/link-local)."""
        import ipaddress

        try:
            addr = ipaddress.ip_address(ip)
            return not (addr.is_private or addr.is_loopback or addr.is_link_local)
        except ValueError:
            return False  # hostname or empty — treat as non-public for safety

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        target = kwargs.get("target", "")
        interface = kwargs.get("interface", "eth0")
        external_ip = kwargs.get("external_ip", "")
        timeout = kwargs.get("timeout", 60)

        # Pivot resolution: env var is authoritative.
        # Agent-supplied pivot_host is accepted ONLY if it looks like user@host and is
        # NOT the same as the target/external_ip (guards against the agent confusing
        # the two).  PIVOT_HOST env always wins if set.
        env_pivot = os.environ.get("PIVOT_HOST", "")
        raw_pivot = kwargs.get("pivot_host", "")
        scan_target = external_ip or target
        # Reject agent-supplied pivot if it equals the scan target (agent confusion)
        if raw_pivot and raw_pivot == scan_target:
            logger.warning("pivot_host == scan target (%s) — ignoring agent value, using PIVOT_HOST env", scan_target)
            raw_pivot = ""
        pivot_host = env_pivot or raw_pivot

        # Hard guard: never scan a public IP from local when PIVOT_HOST is configured.
        # A local scan of a public WAN IP goes through hairpin NAT — the result is
        # meaningless for external attack simulation.
        wan_actions = {"wan_portscan", "tcp_probe", "acs_fingerprint", "full_perimeter"}
        if action in wan_actions and self._is_public_ip(scan_target) and not pivot_host:
            return (
                f"BLOCKED: {action} on public IP {scan_target!r} requires an external pivot.\n"
                "Set PIVOT_HOST=user@host in the environment or pass pivot_host=user@host.\n"
                "Scanning a public WAN IP from the local host traverses hairpin NAT and "
                "produces invalid results — it does not simulate an external attacker's view."
            )

        ports = kwargs.get("ports", "")
        dispatch = {
            "router_fingerprint": lambda: self.router_fingerprint(target, interface, timeout),
            "upnp_discover": lambda: self.upnp_discover(interface, timeout),
            "upnp_portmap": lambda: self.upnp_portmap(target, timeout),
            "upnp_add_portmap": lambda: self.upnp_add_portmap(target, timeout),
            "default_creds": lambda: self.default_creds(target, timeout),
            "routersploit_scan": lambda: self.routersploit_scan(target, timeout),
            "wan_portscan": lambda: self.wan_portscan(external_ip, pivot_host, timeout),
            "tcp_probe": lambda: self.tcp_probe(target or external_ip, ports, pivot_host, timeout),
            "acs_fingerprint": lambda: self.acs_fingerprint(target or external_ip, pivot_host, timeout),
            "dns_rebind_check": lambda: self.dns_rebind_check(target, timeout),
            "firewall_egress": lambda: self.firewall_egress(timeout),
            "full_perimeter": lambda: self.full_perimeter(target, interface, external_ip, pivot_host, timeout),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            result = await fn()
            ingest_output("perimeter_audit", action, result, self._target_store)
            return result
        except Exception as exc:
            logger.exception("perimeter_audit error (%s)", action)
            return f"perimeter_audit error ({action}): {exc}"

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _run(self, *args: str, timeout: int = 60, env: dict | None = None) -> str:
        logger.info("Running: %s", " ".join(str(a) for a in args))
        import os as _os

        run_env = _os.environ.copy()
        if env:
            run_env.update(env)
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=run_env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return f"Timed out after {timeout}s"
        out = stdout.decode(errors="replace").strip()
        err = stderr.decode(errors="replace").strip()
        return out + (f"\n[stderr] {err}" if err else "")

    async def _get_gateway(self, interface: str = "eth0") -> str:
        """Detect the default gateway IP."""
        out = await self._run("ip", "route", "show", "default", timeout=5)
        m = re.search(r"default via ([\d.]+)", out)
        if m:
            return m.group(1)
        # fallback for non-Linux
        out2 = await self._run("route", "-n", timeout=5)
        m2 = re.search(r"0\.0\.0\.0\s+([\d.]+)", out2)
        return m2.group(1) if m2 else "192.168.1.1"

    async def _curl(self, url: str, timeout: int = 15, extra_args: list[str] | None = None) -> str:
        args = ["curl", "-s", "--max-time", str(timeout), "-L", "--connect-timeout", "5", url]
        if extra_args:
            args.extend(extra_args)
        return await self._run(*args, timeout=timeout + 5)

    # ── actions ───────────────────────────────────────────────────────────────

    async def router_fingerprint(self, target: str, interface: str = "eth0", timeout: int = 30) -> str:
        """Fingerprint the router: model, firmware, web UI exposure, banner grab."""
        if not target:
            target = await self._get_gateway(interface)

        results = [f"Router fingerprint: {target}"]

        # Parallel: nmap banner + HTTP title + HTTPS title + SNMP
        async def nmap_banner():
            return await self._run(
                "nmap",
                "-sV",
                "-p",
                "22,23,80,443,8080,8443,8888,7547",
                "--script",
                "banner,http-title,ssh-hostkey",
                "-T4",
                "--open",
                target,
                timeout=30,
            )

        async def http_title():
            out = await self._curl(f"http://{target}/", timeout=10)
            m = re.search(r"<title>(.*?)</title>", out, re.IGNORECASE | re.DOTALL)
            return f"HTTP title: {m.group(1).strip()[:100] if m else '(no title)'}\n{out[:300]}"

        async def https_title():
            out = await self._curl(f"https://{target}/", timeout=10, extra_args=["-k"])
            m = re.search(r"<title>(.*?)</title>", out, re.IGNORECASE | re.DOTALL)
            return f"HTTPS title: {m.group(1).strip()[:100] if m else '(no title)'}\n{out[:300]}"

        async def snmp_community():
            return await self._run("snmpwalk", "-v2c", "-c", "public", target, "system", timeout=10)

        nmap_out, http_out, https_out, snmp_out = await asyncio.gather(
            nmap_banner(),
            http_title(),
            https_title(),
            snmp_community(),
            return_exceptions=True,
        )
        for label, out in [("nmap", nmap_out), ("HTTP", http_out), ("HTTPS", https_out), ("SNMP", snmp_out)]:
            if isinstance(out, Exception):
                results.append(f"  {label}: error — {out}")
            else:
                results.append(f"  {label}:\n{str(out)[:500]}")

        return "\n".join(results)

    async def upnp_discover(self, interface: str = "eth0", timeout: int = 30) -> str:
        """Discover UPnP devices via SSDP M-SEARCH broadcast."""
        results = ["UPnP discovery via SSDP:"]

        # upnpc from miniupnpc
        upnpc = await self._run("upnpc", "-l", timeout=15)
        if "command not found" not in upnpc and "No such file" not in upnpc:
            results.append(f"upnpc:\n{upnpc}")

        # nmap UPnP scripts
        nmap_out = await self._run(
            "nmap", "-sU", "-p", "1900", "--script", "upnp-info", "-T4", "224.0.0.0/4", timeout=25
        )
        results.append(f"nmap UPnP:\n{nmap_out[:1000]}")

        # miranda/upnp-inspector fallback via curl SSDP
        ssdp_msg = (
            'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n'
        )
        # netcat approach
        nc_out = await self._run("bash", "-c", f'echo -e "{ssdp_msg}" | nc -u -w3 239.255.255.250 1900', timeout=8)
        if nc_out and "command not found" not in nc_out:
            results.append(f"SSDP responses:\n{nc_out[:500]}")

        return "\n".join(results)

    async def upnp_portmap(self, target: str, timeout: int = 20) -> str:
        """Enumerate existing UPnP port mappings from the router IGD."""
        if not target:
            target = await self._get_gateway()
        results = [f"UPnP port mappings on {target}:"]

        out = await self._run("upnpc", "-u", f"http://{target}:1900/rootDesc.xml", "-l", timeout=15)
        if "command not found" not in out and "No such file" not in out:
            results.append(out)
            return "\n".join(results)

        # fallback: query IGD directly via curl
        soap_body = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewPortMappingIndex>0</NewPortMappingIndex>
</u:GetGenericPortMappingEntry></s:Body></s:Envelope>"""
        raw = await self._run(
            "curl",
            "-s",
            "--max-time",
            "10",
            "-H",
            "Content-Type: text/xml; charset=utf-8",
            "-H",
            'SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"',
            "--data",
            soap_body,
            f"http://{target}:49000/igdupnp/control/WANIPConn1",
            timeout=15,
        )
        results.append(f"IGD SOAP: {raw[:500]}")
        return "\n".join(results)

    async def upnp_add_portmap(self, target: str, timeout: int = 20) -> str:
        """Attempt to add a UPnP port mapping (tests for unauthenticated IGD abuse)."""
        if not target:
            target = await self._get_gateway()
        results = [f"UPnP port mapping abuse test on {target}:"]
        results.append("NOTE: This adds a test port mapping (TCP/65535 → 65535) and immediately removes it.")

        # Try via upnpc
        add = await self._run(
            "upnpc",
            "-u",
            f"http://{target}:1900/rootDesc.xml",
            "-a",
            "192.168.4.1",
            "65535",
            "65535",
            "TCP",
            "protopen_test",
            timeout=15,
        )
        results.append(f"Add result: {add[:200]}")

        # Remove immediately
        rm = await self._run("upnpc", "-u", f"http://{target}:1900/rootDesc.xml", "-d", "65535", "TCP", timeout=10)
        results.append(f"Remove result: {rm[:200]}")

        if "success" in add.lower() or "portmapping" in add.lower():
            results.append("FINDING: UPnP IGD accepts unauthenticated port mapping additions — WAN exposure possible")
        return "\n".join(results)

    async def default_creds(self, target: str, timeout: int = 45) -> str:
        """Test common router default credentials on HTTP/HTTPS admin interfaces."""
        if not target:
            target = await self._get_gateway()
        results = [f"Default credential test: {target}"]

        # Common default creds for home routers
        cred_pairs = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", ""),
            ("admin", "1234"),
            ("admin", "admin123"),
            ("root", "root"),
            ("root", "admin"),
            ("admin", "motorola"),  # Motorola/Arris
            ("admin", "password1"),
            ("cusadmin", "highspeed"),  # Comcast/Xfinity
            ("admin", "attadmin"),  # AT&T
            ("admin", "comcast"),
        ]
        found: list[str] = []
        for user, passwd in cred_pairs:
            for port in ["80", "443", "8080", "8443"]:
                scheme = "https" if port in ("443", "8443") else "http"
                url = f"{scheme}://{target}:{port}/"
                auth_arg = f"{user}:{passwd}"
                raw = await self._run(
                    "curl",
                    "-s",
                    "--max-time",
                    "5",
                    "-k",
                    "-u",
                    auth_arg,
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    url,
                    timeout=8,
                )
                code = raw.strip()
                if code in ("200", "302", "301") and code != "401":
                    found.append(f"  VALID: {user}:{passwd} on {url} (HTTP {code})")
                    break

        if found:
            results.append("CREDENTIALS FOUND:")
            results.extend(found)
        else:
            results.append("  No default credentials accepted (all returned 401/403 or timed out)")
        return "\n".join(results)

    async def routersploit_scan(self, target: str, timeout: int = 120) -> str:
        """Run RouterSploit autopwn against the target router."""
        if not target:
            target = await self._get_gateway()
        results = [f"RouterSploit scan: {target}"]

        # Check if rsf is available
        check = await self._run("which", "rsf", timeout=5)
        if not check or "not found" in check:
            # try python module
            check2 = await self._run("python3", "-c", "import routersploit", timeout=5)
            if "No module" in check2:
                results.append(
                    "RouterSploit not installed. Install: pip install routersploit\n"
                    "  or: blackarch: pacman -S routersploit"
                )
                # fallback: nmap router scripts
                nmap_out = await self._run(
                    "nmap",
                    "-sV",
                    "-p",
                    "80,443,8080,23,22,7547",
                    "--script",
                    "http-router-info,telnet-info",
                    target,
                    timeout=60,
                )
                results.append(f"nmap router scripts:\n{nmap_out}")
                return "\n".join(results)

        # RouterSploit autopwn via stdin
        rsf_script = f"""use scanners/routers/router_scan
set target {target}
run
exit
"""
        proc = await asyncio.create_subprocess_exec(
            "rsf",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(input=rsf_script.encode()), timeout=timeout)
            out = stdout.decode(errors="replace")
            results.append(out[:3000])
        except asyncio.TimeoutError:
            proc.kill()
            results.append(f"RouterSploit timed out after {timeout}s")
        return "\n".join(results)

    async def wan_portscan(self, external_ip: str, pivot_host: str = "", timeout: int = 120) -> str:
        """Scan WAN IP from external vantage — via SSH pivot or direct if on external network.

        Runs parallel SYN scan + ACK scan to distinguish open/filtered/closed and detect
        stateful firewalls vs direct RST. Reports ALL port states (not just open).

        pivot_host: SSH connection string (user@host) for an external VPS.
        If no pivot, falls back to scanning from current host (only useful if externally routed).
        """
        if not external_ip:
            return "wan_portscan: external_ip required. Get it via external_recon wan_ip first."

        # Port list includes common service ports + ISP/CPE management ports (7547 CWMP, 4567 ACS)
        port_list = (
            "21,22,23,25,53,80,110,143,443,465,587,993,995,1194,1723,3389,4500,5060,4567,7547,8080,8443,8888,9000,9443"
        )

        results = [f"WAN port scan: {external_ip}"]

        if pivot_host:
            results.append(f"  Using SSH pivot: {pivot_host}")
            ssh_prefix = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10", pivot_host]

            # Parallel SYN scan + ACK scan — together reveal firewall type
            # SYN: open=SYN+ACK, closed=RST, filtered=no-response
            # ACK: unfiltered=RST, filtered=no-response  (stateful firewall drops ACK to non-established)
            syn_cmd = f"nmap -sS -sV -p {port_list} -T4 {external_ip}"
            ack_cmd = f"nmap -sA -p {port_list} -T4 {external_ip}"

            syn_out, ack_out = await asyncio.gather(
                self._run(*ssh_prefix, syn_cmd, timeout=timeout),
                self._run(*ssh_prefix, ack_cmd, timeout=timeout),
            )
            results.append("--- SYN scan (service detection) ---")
            results.append(syn_out[:2500])
            results.append("--- ACK scan (firewall fingerprint) ---")
            results.append(ack_out[:1500])
        else:
            results.append("  No pivot configured — scanning from local (results only valid if externally routed)")
            out = await self._run(
                "nmap",
                "-sV",
                "-p",
                port_list,
                "-T3",
                external_ip,
                timeout=timeout,
            )
            results.append(out[:3000])

        return "\n".join(results)

    async def tcp_probe(self, target: str, ports: str = "", pivot_host: str = "", timeout: int = 60) -> str:
        """Deep TCP flag analysis on specific ports — distinguishes silent-drop, RST, and FIN+ACK.

        Uses hping3 SYN probes (with flag inspection) and nmap stealth scan battery (-sA -sF -sN).
        This reveals whether a "filtered" port is:
          - Silent drop (stateful firewall, no response)
          - RST (port closed, no application)
          - FIN+ACK (active ISP/CPE management — IP-allowlisted service rejecting unknown sources)
          - SYN+ACK (open, accepting connections)

        ports: comma-separated port list (default: 4567,7547,9443 — known CPE/ACS management ports)
        """
        if not target:
            return "tcp_probe: target IP required"
        if not ports:
            ports = "4567,7547,9443"

        results = [f"TCP flag analysis: {target} ports {ports}"]

        port_list_space = ports.replace(",", " ")

        async def run_remote(cmd: str) -> str:
            if pivot_host:
                return await self._run(
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "ConnectTimeout=10",
                    pivot_host,
                    cmd,
                    timeout=timeout,
                )
            return await self._run("sh", "-c", cmd, timeout=timeout)

        # hping3 SYN probes — one per port, capture flags in response
        hping_tasks = []
        for p in ports.split(","):
            p = p.strip()
            if p:
                hping_tasks.append(
                    run_remote(f"hping3 -S -p {p} -c 3 --fast {target} 2>&1 || echo 'hping3 not available'")
                )

        # nmap stealth battery: ACK + FIN + NULL scans
        ack_scan = run_remote(f"nmap -sA -p {ports} -T4 --reason {target}")
        fin_scan = run_remote(f"nmap -sF -p {ports} -T4 --reason {target}")
        null_scan = run_remote(f"nmap -sN -p {ports} -T4 --reason {target}")

        all_results = await asyncio.gather(*hping_tasks, ack_scan, fin_scan, null_scan, return_exceptions=True)

        hping_results = all_results[: len(hping_tasks)]
        ack_out, fin_out, null_out = all_results[len(hping_tasks) :]

        # Parse hping output for response flags
        for i, (p, hping_out) in enumerate(zip(ports.split(","), hping_results)):
            if isinstance(hping_out, Exception):
                continue
            results.append(f"\n--- hping3 SYN probe: port {p.strip()} ---")
            results.append(str(hping_out)[:600])
            # Detect key response patterns
            if "flags=FA" in str(hping_out) or "FIN,ACK" in str(hping_out):
                results.append(
                    f"  ** FINDING: Port {p.strip()} returns FIN+ACK — active rejection, not silent drop."
                    " Indicates IP-allowlisted service (ISP/CPE management — only authorized source IPs"
                    " complete the handshake). The port IS open on the device but rejects unauthorized sources."
                )
            elif "flags=RA" in str(hping_out) or "RST,ACK" in str(hping_out):
                results.append(f"  Port {p.strip()}: RST+ACK — port closed, no application listening")
            elif "flags=SA" in str(hping_out) or "SYN,ACK" in str(hping_out):
                results.append(f"  Port {p.strip()}: SYN+ACK — port OPEN, service accepting connections")
            elif "100% packet loss" in str(hping_out) or "0 packets received" in str(hping_out):
                results.append(f"  Port {p.strip()}: No response — silent drop (stateful firewall)")

        results.append("\n--- ACK scan (stateful firewall detection) ---")
        results.append(str(ack_out)[:800] if not isinstance(ack_out, Exception) else str(ack_out))
        results.append("\n--- FIN scan ---")
        results.append(str(fin_out)[:600] if not isinstance(fin_out, Exception) else str(fin_out))
        results.append("\n--- NULL scan ---")
        results.append(str(null_out)[:600] if not isinstance(null_out, Exception) else str(null_out))

        results.append(
            "\nInterpretation guide:"
            "\n  FIN+ACK  → IP-allowlisted management port (ISP/CPE ACS, TR-069 ACS, vendor portal)"
            "\n  RST/RST+ACK → Port closed, no service"
            "\n  SYN+ACK  → Port open, service accepting"
            "\n  No response → Silent drop by stateful firewall"
        )

        return "\n".join(results)

    async def acs_fingerprint(self, target: str, pivot_host: str = "", timeout: int = 60) -> str:
        """Fingerprint ISP/CPE management infrastructure on a WAN IP.

        Probes known ISP remote-management ports:
          - 7547 (TR-069/CWMP — standard ISP CPE management)
          - 4567 (proprietary ACS — used by Lumen/CenturyLink, some Comcast CPE)
          - 9443 (HTTPS management — Arris, Technicolor)
          - 9000 (alternative management)
          - 30005 (Huawei HG management)

        Correlates findings with ASN/rDNS to identify ISP and known management platform.
        """
        if not target:
            return "acs_fingerprint: target IP required"

        results = [f"ISP/ACS management fingerprint: {target}"]

        async def run_remote(cmd: str) -> str:
            if pivot_host:
                return await self._run(
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "ConnectTimeout=10",
                    pivot_host,
                    cmd,
                    timeout=timeout,
                )
            return await self._run("sh", "-c", cmd, timeout=timeout)

        # Known ISP management ports with ISP associations
        mgmt_ports = {
            "7547": "TR-069/CWMP (universal ISP CPE management — RFC 3920)",
            "4567": "Proprietary ACS (Lumen/CenturyLink, some Comcast — IP-allowlisted)",
            "9443": "HTTPS management (Arris, Technicolor, Hitron CPE)",
            "9000": "Alternative management (various ISP CPE)",
            "30005": "Huawei HG management portal",
            "8181": "Sercomm/ActionTec management",
        }

        # Parallel: nmap service probe + banner grabs on each port
        port_csv = ",".join(mgmt_ports.keys())
        scan_task = run_remote(f"nmap -sV -sS -p {port_csv} --version-intensity 5 -T4 --reason {target}")

        banner_tasks = {}
        for port, desc in mgmt_ports.items():
            banner_tasks[port] = run_remote(
                f"timeout 5 bash -c 'echo -e \"GET / HTTP/1.0\\r\\n\\r\\n\" | nc -w 3 {target} {port} 2>&1 | head -5'"
            )

        scan_out, *banner_outs = await asyncio.gather(scan_task, *banner_tasks.values(), return_exceptions=True)

        results.append("\n--- Port scan: CPE management ports ---")
        results.append(str(scan_out)[:2000] if not isinstance(scan_out, Exception) else str(scan_out))

        results.append("\n--- Banner grabs ---")
        for (port, desc), banner_out in zip(mgmt_ports.items(), banner_outs):
            if isinstance(banner_out, Exception):
                continue
            banner_str = str(banner_out).strip()[:200]
            if banner_str and "timed out" not in banner_str.lower() and "refused" not in banner_str.lower():
                results.append(f"  Port {port} ({desc}):")
                results.append(f"    {banner_str}")

        # ISP identification from rDNS patterns
        rdns_out = await run_remote(f"dig +short -x {target}")
        rdns = str(rdns_out).strip()
        results.append(f"\n--- rDNS: {rdns or '(none)'} ---")

        isp_hints = []
        rdns_lower = rdns.lower()
        if any(x in rdns_lower for x in ["qwest", "centurylink", "lumen", "ptld", "cybermesa"]):
            isp_hints.append(
                "CenturyLink/Lumen (AS209) — Known ACS ports: 4567 (proprietary), 7547 (CWMP). "
                "Port 4567 on Lumen CPE is IP-allowlisted to Lumen ACS servers only."
            )
        elif any(x in rdns_lower for x in ["comcast", "xfinity", "comcast.net"]):
            isp_hints.append("Comcast/Xfinity — Known ACS ports: 7547 (CWMP), 8080 (X1 platform)")
        elif any(x in rdns_lower for x in ["att.net", "sbcglobal", "bellsouth"]):
            isp_hints.append("AT&T — Known ACS ports: 7547 (CWMP), 49152-49155 (TR-064 UPnP)")
        elif any(x in rdns_lower for x in ["verizon", "vz.net", "vzfios"]):
            isp_hints.append("Verizon/FiOS — Known ACS ports: 7547 (CWMP), 4567 (some CPE)")
        elif any(x in rdns_lower for x in ["cox.net", "coxnet"]):
            isp_hints.append("Cox — Known ACS ports: 7547 (CWMP)")

        if isp_hints:
            results.append("\n--- ISP identification ---")
            for hint in isp_hints:
                results.append(f"  {hint}")
        else:
            results.append("\n  ISP not matched from rDNS — check Shodan/BGP for ASN correlation")

        return "\n".join(results)

    async def dns_rebind_check(self, domain: str, timeout: int = 20) -> str:
        """Check for DNS rebinding vulnerability — does router block private IP responses for public queries."""
        if not domain:
            domain = await self._get_gateway()
        results = [f"DNS rebinding check: {domain}"]

        # Check if router's DNS rebinding protection is active
        # Rebind protection blocks DNS responses that resolve public hostnames to private IPs
        # Test: resolve a known rebind test domain
        test_domains = [
            "make-192-168-1-1.rebind.network",
            "169.254.169.254.xip.io",
        ]
        for td in test_domains:
            out = await self._run("dig", "+short", td, timeout=8)
            if re.search(r"\b(192\.168|10\.|172\.(1[6-9]|2\d|3[01])\.|169\.254)", out):
                results.append(f"  VULNERABLE: {td} resolved to private IP {out.strip()}")
                results.append("  Router DNS rebinding protection: INACTIVE")
            else:
                results.append(f"  {td}: {out.strip() or '(blocked or NXDOMAIN)'}")

        # Check router admin interface for rebinding protection setting
        gw = await self._get_gateway()
        admin_raw = await self._curl(f"http://{gw}/", timeout=8)
        if "rebind" in admin_raw.lower() or "dns" in admin_raw.lower():
            results.append("  Router web UI mentions DNS/rebind settings")

        results.append(
            "\nNote: DNS rebinding attacks let malicious websites access your router admin\n"
            "interface. Mitigation: enable DNS rebinding protection in router settings."
        )
        return "\n".join(results)

    async def firewall_egress(self, timeout: int = 60) -> str:
        """Test which outbound ports are allowed through the firewall."""
        results = ["Firewall egress test — outbound ports:"]

        # Common ports to test egress
        test_ports = {
            "21": "FTP",
            "22": "SSH",
            "23": "Telnet",
            "25": "SMTP",
            "53": "DNS",
            "80": "HTTP",
            "443": "HTTPS",
            "465": "SMTPS",
            "587": "SMTP submission",
            "993": "IMAPS",
            "1194": "OpenVPN",
            "3389": "RDP",
            "4444": "Metasploit default",
            "6667": "IRC",
            "8080": "Alt-HTTP",
            "9001": "Tor",
        }

        # Use nc/ncat to test each port against a reliable external host
        test_host = "scanme.nmap.org"
        open_ports: list[str] = []
        filtered_ports: list[str] = []

        async def test_port(port: str, name: str) -> tuple[str, str, bool]:
            out = await self._run("nc", "-zv", "-w", "3", test_host, port, timeout=6)
            is_open = "succeeded" in out.lower() or "open" in out.lower() or "connected" in out.lower()
            return port, name, is_open

        test_tasks = [test_port(p, n) for p, n in test_ports.items()]
        port_results = await asyncio.gather(*test_tasks, return_exceptions=True)

        for r in port_results:
            if isinstance(r, Exception):
                continue
            port, name, is_open = r
            if is_open:
                open_ports.append(f"  OPEN  {port:5s} {name}")
            else:
                filtered_ports.append(f"  BLOCK {port:5s} {name}")

        results.extend(open_ports)
        results.extend(filtered_ports)

        concerning = [p for p in open_ports if any(x in p for x in ["4444", "6667", "9001", "23 ", "25 "])]
        if concerning:
            results.append(f"\nNOTE: Concerning egress ports open: {concerning}")

        return "\n".join(results)

    async def full_perimeter(
        self,
        target: str,
        interface: str,
        external_ip: str,
        pivot_host: str,
        timeout: int,
    ) -> str:
        """Full perimeter audit — all checks in parallel."""
        if not target:
            target = await self._get_gateway(interface)

        parts = [f"=== Full Perimeter Audit: {target} ===\n"]

        tasks = {
            "Router Fingerprint": self.router_fingerprint(target, interface, 30),
            "UPnP Discovery": self.upnp_discover(interface, 25),
            "UPnP Port Mappings": self.upnp_portmap(target, 20),
            "Default Credentials": self.default_creds(target, 45),
            "DNS Rebinding": self.dns_rebind_check(target, 20),
            "Firewall Egress": self.firewall_egress(60),
        }
        if external_ip or pivot_host:
            tasks["WAN Port Scan"] = self.wan_portscan(external_ip, pivot_host, 90)
            tasks["ACS Fingerprint"] = self.acs_fingerprint(external_ip or target, pivot_host, 60)
            tasks["TCP Probe (CPE ports)"] = self.tcp_probe(external_ip or target, "4567,7547,9443", pivot_host, 60)

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for label, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                parts.append(f"## {label}\nError: {result}\n")
            else:
                parts.append(f"## {label}\n{result}\n")

        return "\n".join(parts)
