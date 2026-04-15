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
    VULN_ASSESSMENT = 2
    EXPLOITATION = 3
    POST_EXPLOITATION = 4
    LATERAL_MOVEMENT = 5
    PERSISTENCE = 6
    EXFILTRATION = 7
    CLEANUP = 8


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
    "gobuster_scan": KillChainPhase.ENUMERATION,
    "hashcat_crack": KillChainPhase.EXPLOITATION,
    "tshark_capture": KillChainPhase.RECON,
    "airodump_scan": KillChainPhase.RECON,
    "airmon_start": KillChainPhase.RECON,
    "airmon_stop": KillChainPhase.RECON,
    # ── Enhanced BlackArch ──
    "nmap_os_detect": KillChainPhase.RECON,
    "nmap_udp_scan": KillChainPhase.ENUMERATION,
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
    # ── Web Enum ──
    "gobuster_dir": KillChainPhase.ENUMERATION,
    "gobuster_vhost": KillChainPhase.ENUMERATION,
    "ffuf_fuzz": KillChainPhase.ENUMERATION,
    "ffuf_param": KillChainPhase.ENUMERATION,
    # ── Service Enum ──
    "enum4linux_full": KillChainPhase.ENUMERATION,
    "smb_shares": KillChainPhase.ENUMERATION,
    "smb_list": KillChainPhase.ENUMERATION,
    "rpc_info": KillChainPhase.ENUMERATION,
    "rpc_users": KillChainPhase.ENUMERATION,
    # ── SSL Audit ──
    "ssl_full_audit": KillChainPhase.ENUMERATION,
    "ssl_protocols": KillChainPhase.ENUMERATION,
    "ssl_ciphers": KillChainPhase.ENUMERATION,
    "ssl_vulnerabilities": KillChainPhase.ENUMERATION,
    "ssl_certificates": KillChainPhase.ENUMERATION,
    # ── API Enum ──
    "swagger_scan": KillChainPhase.ENUMERATION,
    "endpoint_brute": KillChainPhase.ENUMERATION,
    "method_check": KillChainPhase.ENUMERATION,
    # ── Vuln Assessment ──
    "nikto_scan": KillChainPhase.VULN_ASSESSMENT,
    "nuclei_scan": KillChainPhase.VULN_ASSESSMENT,
    "nuclei_tagged": KillChainPhase.VULN_ASSESSMENT,
    "nse_vuln": KillChainPhase.VULN_ASSESSMENT,
    # ── SQL Testing ──
    "sqli_detect": KillChainPhase.VULN_ASSESSMENT,
    "sqli_forms": KillChainPhase.VULN_ASSESSMENT,
    "sqli_dbs": KillChainPhase.EXPLOITATION,
    "sqli_tables": KillChainPhase.EXPLOITATION,
    # ── Web Vuln ──
    "xss_scan": KillChainPhase.VULN_ASSESSMENT,
    "cors_check": KillChainPhase.VULN_ASSESSMENT,
    "redirect_check": KillChainPhase.VULN_ASSESSMENT,
    # ── CVE Match ──
    "cve_search": KillChainPhase.VULN_ASSESSMENT,
    "cve_nmap": KillChainPhase.VULN_ASSESSMENT,
    "cve_nuclei": KillChainPhase.VULN_ASSESSMENT,
    # ── Metasploit ──
    "msf_search": KillChainPhase.VULN_ASSESSMENT,
    "msf_info": KillChainPhase.VULN_ASSESSMENT,
    "msf_run": KillChainPhase.EXPLOITATION,
    "msf_payload": KillChainPhase.EXPLOITATION,
    # ── Credential Attack ──
    "hydra_brute": KillChainPhase.EXPLOITATION,
    "hydra_spray": KillChainPhase.EXPLOITATION,
    "hydra_combo": KillChainPhase.EXPLOITATION,
    # ── Hash Cracking ──
    "hash_identify": KillChainPhase.VULN_ASSESSMENT,
    "hashcat_dict": KillChainPhase.EXPLOITATION,
    "hashcat_rules": KillChainPhase.EXPLOITATION,
    "john_crack": KillChainPhase.EXPLOITATION,
    "john_show": KillChainPhase.EXPLOITATION,
    # ── Priv Esc ──
    "linpeas": KillChainPhase.POST_EXPLOITATION,
    "sudo_check": KillChainPhase.POST_EXPLOITATION,
    "suid_find": KillChainPhase.POST_EXPLOITATION,
    "kernel_exploits": KillChainPhase.POST_EXPLOITATION,
    # ── Lateral Movement ──
    "psexec": KillChainPhase.LATERAL_MOVEMENT,
    "wmiexec": KillChainPhase.LATERAL_MOVEMENT,
    "evil_winrm": KillChainPhase.LATERAL_MOVEMENT,
    "pth_winrm": KillChainPhase.LATERAL_MOVEMENT,
    "ssh_pivot": KillChainPhase.LATERAL_MOVEMENT,
    # ── Data Exfil ──
    "scp_download": KillChainPhase.EXFILTRATION,
    "smb_download": KillChainPhase.EXFILTRATION,
    "http_exfil": KillChainPhase.EXFILTRATION,
    # ── Persistence ──
    "add_ssh_key": KillChainPhase.PERSISTENCE,
    "add_cron": KillChainPhase.PERSISTENCE,
    "check_persistence": KillChainPhase.POST_EXPLOITATION,
    # ── Cleanup ──
    "remove_ssh_key": KillChainPhase.CLEANUP,
    "remove_cron": KillChainPhase.CLEANUP,
    "remove_files": KillChainPhase.CLEANUP,
    "cleanup_report": KillChainPhase.CLEANUP,
    # ── JWT Analysis ──
    "jwt_decode": KillChainPhase.VULN_ASSESSMENT,
    "jwt_alg_none": KillChainPhase.VULN_ASSESSMENT,
    "jwt_crack": KillChainPhase.EXPLOITATION,
    "jwt_tamper": KillChainPhase.EXPLOITATION,
    # ── SSRF Detection ──
    "ssrf_basic": KillChainPhase.VULN_ASSESSMENT,
    "ssrf_cloud_meta": KillChainPhase.VULN_ASSESSMENT,
    "ssrf_callback": KillChainPhase.VULN_ASSESSMENT,
    "ssrf_generate_payloads": KillChainPhase.VULN_ASSESSMENT,
    # ── Auth Testing ──
    "idor_check": KillChainPhase.VULN_ASSESSMENT,
    "privesc_horizontal": KillChainPhase.VULN_ASSESSMENT,
    "privesc_vertical": KillChainPhase.VULN_ASSESSMENT,
    "session_fixation": KillChainPhase.VULN_ASSESSMENT,
    "token_replay": KillChainPhase.VULN_ASSESSMENT,
    # ── Rate Limit ──
    "rate_detect": KillChainPhase.VULN_ASSESSMENT,
    "rate_bypass_headers": KillChainPhase.VULN_ASSESSMENT,
    "rate_bypass_path": KillChainPhase.VULN_ASSESSMENT,
    # ── GraphQL ──
    "gql_introspect": KillChainPhase.ENUMERATION,
    "gql_depth_test": KillChainPhase.VULN_ASSESSMENT,
    "gql_batch": KillChainPhase.VULN_ASSESSMENT,
    "gql_field_suggest": KillChainPhase.ENUMERATION,
    # ── BLE / NFC / SubGHz backfill ──
    "ble_scan": KillChainPhase.RECON,
    "nfc_emulate": KillChainPhase.EXPLOITATION,
    "subghz_bruteforce": KillChainPhase.EXPLOITATION,
    # ── Container/K8s Audit ──
    "kube_hunter": KillChainPhase.ENUMERATION,
    "kube_hunter_internal": KillChainPhase.ENUMERATION,
    "kube_bench": KillChainPhase.ENUMERATION,
    "kube_bench_target": KillChainPhase.ENUMERATION,
    "deepce": KillChainPhase.VULN_ASSESSMENT,
    "cdk_evaluate": KillChainPhase.VULN_ASSESSMENT,
    "cdk_exploit": KillChainPhase.EXPLOITATION,
    "trivy_image": KillChainPhase.VULN_ASSESSMENT,
    "trivy_k8s": KillChainPhase.VULN_ASSESSMENT,
    "trivy_fs": KillChainPhase.VULN_ASSESSMENT,
    # ── WebSocket Testing ──
    "auth_bypass": KillChainPhase.VULN_ASSESSMENT,
    "cswsh": KillChainPhase.VULN_ASSESSMENT,
    "ws_injection": KillChainPhase.VULN_ASSESSMENT,
    # ── IoT Audit ──
    "device_discovery": KillChainPhase.RECON,
    "fingerprint": KillChainPhase.ENUMERATION,
    "telnet_check": KillChainPhase.ENUMERATION,
    "http_admin_check": KillChainPhase.ENUMERATION,
    "mqtt_audit": KillChainPhase.ENUMERATION,
    "snmp_audit": KillChainPhase.ENUMERATION,
    "rtsp_discover": KillChainPhase.ENUMERATION,
    "firmware_exposure": KillChainPhase.ENUMERATION,
    "default_creds": KillChainPhase.EXPLOITATION,
    "full_iot_audit": KillChainPhase.ENUMERATION,
}


def get_tool_phase(tool_name: str) -> Optional[KillChainPhase]:
    """Get the kill chain phase for a tool action.

    Returns None if the tool is not in the phase map (i.e., it's not a
    pentest tool and phase gating doesn't apply).
    """
    return TOOL_PHASE_MAP.get(tool_name)
