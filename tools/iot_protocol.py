"""IoT protocol security testing — MQTT, CoAP, Modbus, BACnet, UPnP, Zigbee."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class IoTProtocolTool(BasePentestTool):
    """IoT protocol security testing and enumeration."""

    name = "iot_protocol"
    description = (
        "IoT protocol testing — MQTT topic discovery, publish/subscribe tests, "
        "credential brute-force; CoAP resource discovery and reads; "
        "Modbus/BACnet device scanning and register reads; UPnP discovery; "
        "Zigbee traffic sniffing."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "mqtt_discover": {
            "cmd": ["mosquitto_sub", "-h", "{target}", "-t", "#", "-v", "-C", "{count}"],
            "timeout": 30,
            "description": "Subscribe to all MQTT topics and capture messages",
        },
        "mqtt_pub_test": {
            "cmd": ["mosquitto_pub", "-h", "{target}", "-t", "{topic}", "-m", "{message}"],
            "timeout": 10,
            "description": "Test MQTT publish permissions on a topic",
        },
        "mqtt_bruteforce": {
            "cmd": ["ncrack", "mqtt://{target}", "--user", "{username}", "-P", "{wordlist}"],
            "timeout": 120,
            "description": "Brute-force MQTT broker credentials",
        },
        "coap_discover": {
            "cmd": ["coap-client", "-m", "get", "coap://{target}/.well-known/core"],
            "timeout": 15,
            "description": "Discover CoAP resources via .well-known/core",
        },
        "coap_get": {
            "cmd": ["coap-client", "-m", "get", "coap://{target}/{resource}"],
            "timeout": 15,
            "description": "Read a CoAP resource",
        },
        "modbus_scan": {
            "cmd": ["nmap", "-sV", "-p", "502", "--script", "modbus-discover", "-oX", "-", "{target}"],
            "timeout": 60,
            "description": "Scan for Modbus TCP devices",
        },
        "modbus_read": {
            "cmd": [
                "modbus-cli", "-s", "{slave_id}",
                "read", "{target}", "{register}", "{count}",
            ],
            "timeout": 15,
            "description": "Read Modbus holding registers",
        },
        "bacnet_scan": {
            "cmd": ["nmap", "-sU", "-p", "47808", "--script", "bacnet-info", "-oX", "-", "{target}"],
            "timeout": 60,
            "description": "Scan for BACnet building automation devices",
        },
        "upnp_discover": {
            "cmd": ["nmap", "-sU", "-p", "1900", "--script", "upnp-info", "-oX", "-", "{target}"],
            "timeout": 60,
            "description": "Discover UPnP devices and services",
        },
        "zigbee_sniff": {
            "cmd": ["zbdump", "-c", "{channel}", "-w", "{path}"],
            "timeout": 30,
            "description": "Sniff Zigbee traffic on a specific channel",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "localhost",
        topic: str = "#",
        message: str = "test",
        username: str = "admin",
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        count: int = 100,
        resource: str = "",
        slave_id: int = 1,
        register: int = 0,
        channel: int = 11,
        path: str = "/tmp/zigbee.pcap",
        timeout: int = 30,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            str(c).format(
                target=target,
                topic=topic,
                message=message,
                username=username,
                wordlist=wordlist,
                count=count,
                resource=resource,
                slave_id=slave_id,
                register=register,
                channel=channel,
                path=path,
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
