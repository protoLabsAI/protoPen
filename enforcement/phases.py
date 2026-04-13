"""Kill chain phase definitions and tool-to-phase mapping.

Maps every pentest tool action to its minimum kill chain phase.
Used by EnforcementMiddleware to enforce phase ceilings — an engagement
capped at ENUMERATION cannot invoke EXPLOITATION-phase tools.
"""
from __future__ import annotations

from enum import IntEnum
from typing import Optional


class KillChainPhase(IntEnum):
    """Simplified kill chain phases for engagement phase gating."""
    RECON = 0
    ENUMERATION = 1
    EXPLOITATION = 2
    POST_EXPLOITATION = 3
    LATERAL_MOVEMENT = 4
    PERSISTENCE = 5
    EXFIL = 6


TOOL_PHASE_MAP: dict[str, KillChainPhase] = {
    # ── PortaPack / RF ──
    "rf_scan": KillChainPhase.RECON,
    "rf_read_screen": KillChainPhase.RECON,
    "rf_radio_info": KillChainPhase.RECON,
    "rf_screenshot": KillChainPhase.RECON,
    "rf_capture": KillChainPhase.RECON,
    "rf_set_frequency": KillChainPhase.RECON,
    "rf_app_start": KillChainPhase.RECON,
    "rf_replay": KillChainPhase.EXPLOITATION,
    "rf_send_pocsag": KillChainPhase.EXPLOITATION,

    # ── Flipper Zero ──
    "flip_subghz_rx": KillChainPhase.RECON,
    "flip_nfc_read": KillChainPhase.RECON,
    "flip_rfid_read": KillChainPhase.RECON,
    "flip_ir_rx": KillChainPhase.RECON,
    "flip_ble_scan": KillChainPhase.RECON,
    "flip_storage_list": KillChainPhase.RECON,
    "flip_subghz_tx": KillChainPhase.EXPLOITATION,
    "flip_nfc_write": KillChainPhase.EXPLOITATION,
    "flip_rfid_write": KillChainPhase.EXPLOITATION,
    "flip_ir_tx": KillChainPhase.EXPLOITATION,
    "flip_subghz_bruteforce": KillChainPhase.EXPLOITATION,

    # ── WiFi Marauder ──
    "wifi_scan_aps": KillChainPhase.RECON,
    "wifi_scan_stations": KillChainPhase.RECON,
    "wifi_sniff_pmkid": KillChainPhase.ENUMERATION,
    "wifi_deauth": KillChainPhase.EXPLOITATION,
    "wifi_beacon_spam": KillChainPhase.EXPLOITATION,
    "wifi_evil_portal": KillChainPhase.EXPLOITATION,
    "wifi_karma": KillChainPhase.EXPLOITATION,

    # ── BlackArch / Network ──
    "nmap_scan": KillChainPhase.RECON,
    "nmap_vuln_scan": KillChainPhase.ENUMERATION,
    "aircrack_monitor": KillChainPhase.RECON,
    "aircrack_capture": KillChainPhase.RECON,
    "aircrack_crack": KillChainPhase.EXPLOITATION,
    "bettercap_recon": KillChainPhase.RECON,
    "bettercap_mitm": KillChainPhase.EXPLOITATION,
    "shell_exec": KillChainPhase.EXPLOITATION,

    # ── BlackArch curated actions ──
    "nikto_scan": KillChainPhase.ENUMERATION,
    "gobuster_scan": KillChainPhase.ENUMERATION,
    "hashcat_crack": KillChainPhase.EXPLOITATION,
    "tshark_capture": KillChainPhase.RECON,
    "airodump_scan": KillChainPhase.RECON,
    "airmon_start": KillChainPhase.RECON,
    "airmon_stop": KillChainPhase.RECON,

    # ── Enhanced BlackArch ──
    "nmap_os_detect": KillChainPhase.RECON,
    "nmap_udp_scan": KillChainPhase.ENUMERATION,
    "hashcat_rules": KillChainPhase.EXPLOITATION,

    # ── DNS Enum ──
    "dig_query": KillChainPhase.RECON,
    "nslookup": KillChainPhase.RECON,
    "zone_transfer": KillChainPhase.ENUMERATION,
    "reverse_lookup": KillChainPhase.RECON,
    "dns_brute": KillChainPhase.ENUMERATION,

    # ── Subdomain Discovery ──
    "subfinder": KillChainPhase.RECON,
    "amass_passive": KillChainPhase.RECON,

    # ── OSINT ──
    "theharvester": KillChainPhase.RECON,
    "whois_lookup": KillChainPhase.RECON,
}


def get_tool_phase(tool_name: str) -> Optional[KillChainPhase]:
    """Get the kill chain phase for a tool action.

    Returns None if the tool is not in the phase map (i.e., it's not a
    pentest tool and phase gating doesn't apply).
    """
    return TOOL_PHASE_MAP.get(tool_name)
