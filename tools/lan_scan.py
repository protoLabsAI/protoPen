"""LAN discovery and enumeration — ARP sweep, NetBIOS, SNMP, mDNS, SMB.

Risk level: 1 (active) — sends ARP/UDP/TCP probes onto the local network.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from tools._subprocess import communicate_or_kill
from tools._tool_base import Tool
from tools.parsers import ingest_output

logger = logging.getLogger(__name__)

ACTIONS: dict[str, dict[str, Any]] = {
    "arp_sweep": {
        "cmd": ["arp-scan", "-I", "{interface}", "{network}"],
        "timeout": 60,
        "description": (
            "Fast L2 host discovery via ARP — returns IP, MAC, and vendor info for every host on the subnet."
        ),
    },
    "netdiscover": {
        "cmd": ["netdiscover", "-r", "{network}", "-P", "-N"],
        "timeout": 120,
        "description": (
            "Passive/active ARP recon using netdiscover — outputs IP/MAC/vendor table suitable for host inventory."
        ),
    },
    "nbtscan": {
        "cmd": ["nbtscan", "-r", "{network}"],
        "timeout": 60,
        "description": (
            "NetBIOS name scan — finds Windows hosts and workgroup/domain names via UDP NetBIOS Name Service queries."
        ),
    },
    "snmp_sweep": {
        "cmd": [
            "nmap",
            "-sU",
            "-p",
            "161",
            "--script",
            "snmp-info",
            "--script-args",
            "snmpcommunity=public,private",
            "-oX",
            "-",
            "{network}",
        ],
        "timeout": 300,
        "description": (
            "Nmap UDP/161 sweep with snmp-info script — discovers SNMP-enabled "
            "devices and extracts sysDescr/sysName via community strings."
        ),
    },
    "mdns_enum": {
        "cmd": ["avahi-browse", "-a", "-t", "-p"],
        "timeout": 60,
        "description": (
            "Enumerate mDNS/Bonjour services via avahi-browse — returns all advertised services with type and hostname."
        ),
    },
    "smb_discovery": {
        "cmd": [
            "nmap",
            "-p",
            "139,445",
            "--script",
            "smb-os-discovery,smb2-security-mode,smb-security-mode",
            "-oX",
            "-",
            "{network}",
        ],
        "timeout": 300,
        "description": (
            "Nmap SMB discovery — finds SMB hosts and collects OS fingerprint, "
            "SMBv1/v2 negotiation state, and security mode flags."
        ),
    },
    "full_lan_sweep": {
        "cmd": [
            "python3",
            "-c",
            "import subprocess,json,shlex,xml.etree.ElementTree as ET; "
            "arp=subprocess.run(['arp-scan','-I','{interface}','{network}'],"
            "capture_output=True,text=True,timeout=60); "
            "hosts=[]; "
            "for line in arp.stdout.splitlines():\n"
            "  parts=line.split('\\t')\n"
            "  if len(parts)>=2 and parts[0].count('.')==3:\n"
            "    entry={{'ip':parts[0].strip(),'mac':parts[1].strip(),"
            "'vendor':parts[2].strip() if len(parts)>2 else ''}}\n"
            "    hosts.append(entry)\n"
            "ips=[h['ip'] for h in hosts]; "
            "nmap_out={{'hosts':[]}}; "
            "if ips:\n"
            "  nm=subprocess.run(['nmap','-sV','-O','--top-ports','100','-T3','-oX','-']+ips,"
            "  capture_output=True,text=True,timeout=600)\n"
            "  try:\n"
            "    root=ET.fromstring(nm.stdout)\n"
            "    for h in root.iter('host'):\n"
            "      addr=h.find('address[@addrtype=\"ipv4\"]')\n"
            "      os_el=h.find('os/osmatch')\n"
            "      svcs=[]\n"
            "      for p in h.iter('port'):\n"
            "        st=p.find('state')\n"
            "        sv=p.find('service')\n"
            "        if st is not None and st.get('state')=='open':\n"
            "          svcs.append({{'port':int(p.get('portid',0)),"
            "'service':sv.get('name','') if sv is not None else '',"
            "'version':sv.get('version','') if sv is not None else ''}})\n"
            "      nmap_out['hosts'].append({{'ip':addr.get('addr','') if addr is not None else '',"
            "'os':os_el.get('name','') if os_el is not None else '','services':svcs}})\n"
            "  except Exception as e:\n"
            "    nmap_out['nmap_parse_error']=str(e)\n"
            "print(json.dumps({{'network':'{network}','interface':'{interface}',"
            "'arp_hosts':hosts,'nmap_detail':nmap_out}}))",
        ],
        "timeout": 720,
        "description": (
            "Combined sweep: ARP scan for host discovery, then nmap -sV -O "
            "--top-ports 100 -T3 against all discovered IPs. Returns structured JSON."
        ),
    },
}


class LanScanTool(Tool):
    """LAN discovery and enumeration — risk level 1 (active probing)."""

    def __init__(self) -> None:
        self._target_store: Any | None = None

    @property
    def name(self) -> str:
        return "lan_scan"

    @property
    def description(self) -> str:
        return (
            "LAN discovery and enumeration (risk level 1 — active). "
            "ARP sweep (arp-scan), passive/active ARP recon (netdiscover), "
            "NetBIOS name scan (nbtscan), SNMP device sweep, mDNS/Bonjour "
            "enumeration, SMB host discovery, and a combined full-LAN sweep "
            "with service/OS fingerprinting."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": list(ACTIONS.keys()),
                },
                "network": {
                    "type": "string",
                    "description": "Target subnet in CIDR notation (e.g. 192.168.1.0/24)",
                },
                "interface": {
                    "type": "string",
                    "description": "Network interface to use (default: eth0)",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Override execution timeout in seconds",
                },
            },
            "required": ["action"],
        }

    async def _run(
        self,
        *,
        action: str,
        cmd: list[str],
        timeout: int,
        target_hint: str = "",
    ) -> str:
        logger.info(
            "[lan_scan] %s → %s (timeout=%ds)",
            action,
            target_hint or "n/a",
            timeout,
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            binary = cmd[0] if cmd else "unknown"
            logger.warning("[lan_scan] %s: binary '%s' not found", action, binary)
            return json.dumps({"error": f"{binary} not found", "tool": "lan_scan", "action": action})
        result = await communicate_or_kill(proc, timeout)
        if result is None:
            return f"Command timed out after {timeout}s: {' '.join(cmd[:4])}..."
        stdout, stderr = result

        output = stdout.decode(errors="replace")
        if stderr:
            err_text = stderr.decode(errors="replace").strip()
            if err_text:
                output += f"\n[stderr] {err_text}"
        return output.strip()

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        network = kwargs.get("network", "192.168.1.0/24")
        interface = kwargs.get("interface", "eth0")
        timeout = kwargs.get("timeout", None)

        if action not in ACTIONS:
            available = ", ".join(sorted(ACTIONS.keys()))
            return f"Unknown action: {action}. Available: {available}"

        spec = ACTIONS[action]
        effective_timeout = timeout if timeout is not None else spec.get("timeout", 120)

        cmd = [c.format(network=network, interface=interface) for c in spec["cmd"]]

        result = await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=network,
        )
        ingest_output("lan_scan", action, result, self._target_store)
        return result
