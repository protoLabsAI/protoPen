"""IoT device security audit — discovery, fingerprinting, and vulnerability assessment.

Distinct from iot_protocol (which handles protocol I/O like MQTT pub/sub, Modbus reads).
This tool focuses on *security assessment*: finding devices, identifying insecure services,
testing default credentials, and detecting common IoT misconfigurations.

Risk tiers:
  1 (active)  — service probes: device_discovery, telnet_check, snmp_audit,
                  firmware_exposure, rtsp_discover, fingerprint, http_admin_check,
                  mqtt_audit, full_iot_audit
  2 (redteam) — credential attacks: default_creds
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)

# IoT-relevant port set — covers common device categories:
#   Telnet (23,2323), SSH (22), FTP (21), HTTP/S admin UIs (80,443,8080,8081,8443,8888),
#   MQTT (1883,8883), CoAP (5683), Modbus (502), BACnet (47808), RTSP cameras (554,8554),
#   SNMP (161 UDP), UPnP (1900 UDP), TR-069 ACS (7547), printer (9100)
_IOT_TCP_PORTS = "21,22,23,80,443,502,554,1883,2323,7547,8080,8081,8443,8554,8883,9100"


class IoTAuditTool(BasePentestTool):
    """IoT security audit: discovery, fingerprinting, and vulnerability assessment."""

    name = "iot_audit"
    description = (
        "IoT device security audit for home/office networks. "
        "device_discovery: nmap IoT port sweep across a CIDR — finds all devices with IoT-relevant services. "
        "fingerprint: deep OS/service/banner fingerprint on a single host. "
        "telnet_check: detect open Telnet on 23/2323 — always a high-severity finding on IoT. "
        "http_admin_check: find web admin panels and test for default accounts (nmap http-default-accounts). "
        "mqtt_audit: test MQTT broker for anonymous access via mosquitto_sub against $SYS topics. "
        "snmp_audit: probe SNMP with default community strings (public/private) using onesixtyone. "
        "rtsp_discover: find RTSP camera streams and check whether authentication is required. "
        "firmware_exposure: banner-grab all common ports for firmware version strings. "
        "default_creds: hydra credential spray against SSH/Telnet/FTP/HTTP using IoT defaults. "
        "full_iot_audit: orchestrates discovery → fingerprint → all checks against a network."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        # ── Discovery ─────────────────────────────────────────────────────────
        "device_discovery": {
            "cmd": [
                "nmap",
                "-n",
                "--open",
                "-sV",
                "-p",
                _IOT_TCP_PORTS,
                "--script",
                "banner,http-title,http-server-header",
                "-T4",
                "-oX",
                "-",
                "{network}",
            ],
            "timeout": 300,
            "description": "nmap IoT port sweep across a CIDR",
        },
        # ── Deep fingerprint ─────────────────────────────────────────────────
        "fingerprint": {
            "cmd": [
                "nmap",
                "-n",
                "-sV",
                "-O",
                "-p",
                _IOT_TCP_PORTS,
                "--script",
                "banner,http-title,http-server-header,ssl-cert",
                "-T4",
                "-oX",
                "-",
                "{target}",
            ],
            "timeout": 120,
            "description": "Deep OS + service version + banner fingerprint on a single host",
        },
        # ── Telnet ───────────────────────────────────────────────────────────
        "telnet_check": {
            "cmd": [
                "nmap",
                "-n",
                "-sV",
                "-p",
                "23,2323",
                "--script",
                "banner,telnet-ntlm-info",
                "-oX",
                "-",
                "{target}",
            ],
            "timeout": 60,
            "description": "Check for open Telnet on port 23 and 2323",
        },
        # ── HTTP admin panels ────────────────────────────────────────────────
        "http_admin_check": {
            "cmd": [
                "nmap",
                "-n",
                "-sV",
                "-p",
                "80,443,8080,8081,8443,8888",
                "--script",
                "http-title,http-auth-finder,http-default-accounts",
                "--script-args",
                "http-default-accounts.category=security,http-default-accounts.fingerprintfile=nse-default-account-db",
                "-T4",
                "-oX",
                "-",
                "{target}",
            ],
            "timeout": 120,
            "description": "Enumerate HTTP admin UIs and test default accounts",
        },
        # ── MQTT anonymous access ─────────────────────────────────────────────
        "mqtt_audit": {
            "cmd": [
                "mosquitto_sub",
                "-h",
                "{target}",
                "-p",
                "1883",
                "-t",
                "$SYS/#",
                "-C",
                "10",
                "-W",
                "8",
                "--quiet",
            ],
            "timeout": 20,
            "description": "Test MQTT broker for anonymous access via $SYS topic subscription",
        },
        # ── SNMP community strings ────────────────────────────────────────────
        "snmp_audit": {
            "cmd": [
                "onesixtyone",
                "-c",
                "/usr/share/doc/onesixtyone/dict.txt",
                "{target}",
            ],
            "timeout": 60,
            "description": "Probe SNMP with default community strings using onesixtyone",
        },
        # ── RTSP cameras ─────────────────────────────────────────────────────
        "rtsp_discover": {
            "cmd": [
                "nmap",
                "-n",
                "-sV",
                "-p",
                "554,8554",
                "--script",
                "rtsp-url-brute",
                "-T4",
                "-oX",
                "-",
                "{target}",
            ],
            "timeout": 90,
            "description": "Find RTSP camera streams and check for auth requirement",
        },
        # ── Firmware version strings ──────────────────────────────────────────
        "firmware_exposure": {
            "cmd": [
                "nmap",
                "-n",
                "-sV",
                "-p",
                "21,22,23,80,443,8080,8443",
                "--script",
                "banner,http-server-header,ftp-syst",
                "-T4",
                "-oX",
                "-",
                "{target}",
            ],
            "timeout": 90,
            "description": "Banner-grab common ports for firmware and version strings",
        },
        # ── Default credential spray (redteam) ───────────────────────────────
        # Requires seclists installed. Uses separate user/pass lists rather than
        # a CSV combo file so hydra's -L/-P mode is reliably portable.
        "default_creds": {
            "cmd": [
                "hydra",
                "-L",
                "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                "-P",
                "/usr/share/seclists/Passwords/Common-Credentials/best110.txt",
                "-s",
                "{port}",
                "-f",
                "-t",
                "4",
                "-W",
                "3",
                "{target}",
                "{service}",
            ],
            "timeout": 300,
            "description": "Credential spray using common IoT defaults (hydra)",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        network: str = "",
        port: int = 80,
        service: str = "http",
        timeout: int = 0,
    ) -> str:
        """Execute an iot_audit action.

        Args:
            target:  Single IP/hostname for targeted checks.
            network: CIDR notation for sweep actions (device_discovery, full_iot_audit).
            port:    Override port for default_creds.
            service: Protocol for default_creds (ssh, telnet, ftp, http).
            timeout: Override the action's built-in timeout; 0 = use action default.
        """
        if action == "mqtt_audit" and not target:
            return "SKIP: mqtt_audit requires a target host — set mqtt_broker variable"

        if action == "full_iot_audit":
            return await self._full_iot_audit(network or target, timeout)

        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        scan_target = target or network
        cmd = [
            str(c).format(
                target=scan_target,
                network=network or target,
                port=port,
                service=service,
            )
            for c in spec["cmd"]
        ]
        # Caller timeout overrides spec default when explicitly provided (non-zero).
        effective_timeout = timeout if timeout > 0 else spec.get("timeout", 120)
        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=scan_target,
        )

    async def _full_iot_audit(self, network: str, timeout: int) -> str:
        """Discovery sweep → parallel targeted checks across the network."""
        sections: list[str] = []

        # Phase 1: broad discovery
        logger.info("[iot_audit] full_iot_audit: discovery on %s", network)
        discovery = await self.execute("device_discovery", network=network, timeout=300)
        sections.append(f"=== device_discovery ===\n{discovery}")

        # Phase 2: targeted checks — run in parallel against the network range
        checks = [
            "telnet_check",
            "http_admin_check",
            "snmp_audit",
            "rtsp_discover",
            "firmware_exposure",
        ]
        check_timeout = timeout if timeout > 0 else 120
        results = await asyncio.gather(
            *[self.execute(check, target=network, timeout=check_timeout) for check in checks],
            return_exceptions=True,
        )
        for check, result in zip(checks, results):
            text = str(result) if isinstance(result, Exception) else result
            sections.append(f"=== {check} ===\n{text}")

        # Phase 3: MQTT audit against the network gateway (best-effort)
        gateway = _guess_gateway(network)
        if gateway:
            mqtt_result = await self.execute("mqtt_audit", target=gateway, timeout=20)
            sections.append(f"=== mqtt_audit ===\n{mqtt_result}")

        return "\n\n".join(sections)


def _guess_gateway(network: str) -> str:
    """Return the .1 host of the given CIDR as a best-effort gateway guess."""
    try:
        import ipaddress

        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())
        return str(hosts[0]) if hosts else ""
    except Exception:
        return ""
