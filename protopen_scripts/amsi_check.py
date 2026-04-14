#!/usr/bin/env python3
"""AMSI detection signature analyzer.

Static analysis of a file for common AMSI detection signatures:
PowerShell attack strings and known malware patterns.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import logging
from typing import Any

logger = logging.getLogger(__name__)

# AMSI detection signatures (simplified AMSI signature database)
AMSI_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    # PowerShell offensive patterns
    (re.compile(r'Invoke-Expression|IEX\s*\(', re.IGNORECASE), "ps_invoke_expression", "PowerShell IEX/Invoke-Expression"),
    (re.compile(r'Invoke-Shellcode', re.IGNORECASE), "ps_shellcode", "PowerShell shellcode injection"),
    (re.compile(r'Invoke-ReflectivePEInjection', re.IGNORECASE), "ps_reflective_pe", "Reflective PE injection"),
    (re.compile(r'Mimikatz|sekurlsa|lsadump|kerberos::', re.IGNORECASE), "mimikatz", "Mimikatz credential dump"),
    (re.compile(r'Invoke-Mimikatz', re.IGNORECASE), "ps_mimikatz", "PowerSploit Invoke-Mimikatz"),
    (re.compile(r'Net\.WebClient|DownloadString|DownloadFile', re.IGNORECASE), "ps_downloader", "PowerShell web downloader"),
    (re.compile(r'AmsiScanBuffer|AmsiInitialize|amsi\.dll', re.IGNORECASE), "amsi_bypass", "AMSI bypass attempt targeting AMSI itself"),
    (re.compile(r'\[Ref\]\.Assembly\.Load|Assembly\.Load\(', re.IGNORECASE), "ps_assembly_load", "PowerShell assembly loading (in-memory execution)"),
    (re.compile(r'VirtualAlloc|WriteProcessMemory|CreateThread', re.IGNORECASE), "mem_injection", "Memory injection API calls"),
    (re.compile(r'base64_decode|FromBase64String', re.IGNORECASE), "base64_decode", "Base64 decode (payload obfuscation)"),
    (re.compile(r'Invoke-WMIMethod|Get-WmiObject', re.IGNORECASE), "wmi_exec", "WMI execution technique"),
    (re.compile(r'Invoke-Obfuscation', re.IGNORECASE), "invoke_obfuscation", "Invoke-Obfuscation framework"),
    (re.compile(r'empire|cobalt.strike|metasploit', re.IGNORECASE), "c2_framework", "C2 framework reference"),
    (re.compile(r'powersploit|nishang|powercat', re.IGNORECASE), "offensive_ps_framework", "Offensive PowerShell framework"),
    (re.compile(r'-Enc(?:oded)?Command\s+[A-Za-z0-9+/=]{20,}', re.IGNORECASE), "ps_encoded_cmd", "PowerShell -EncodedCommand (obfuscated)"),
    (re.compile(r'\$env:COMPUTERNAME|\$env:USERNAME|\$env:TEMP', re.IGNORECASE), "ps_env_enum", "PowerShell environment enumeration"),
    (re.compile(r'netsh\s+(?:advfirewall|firewall)', re.IGNORECASE), "firewall_tamper", "Firewall rule manipulation"),
    (re.compile(r'reg\s+(?:add|delete|export|import)', re.IGNORECASE), "registry_tamper", "Registry modification"),
    (re.compile(r'schtasks\s+/create', re.IGNORECASE), "scheduled_task", "Scheduled task creation (persistence)"),
    (re.compile(r'whoami\s*/priv|SeDebugPrivilege|SeImpersonatePrivilege', re.IGNORECASE), "priv_check", "Privilege escalation check"),
    (re.compile(r'cmd\.exe\s+/c\s+|cmd\s+/c\s+', re.IGNORECASE), "cmd_exec", "CMD execution"),
    (re.compile(r'wscript\.shell|CreateObject\("WScript', re.IGNORECASE), "wsh", "Windows Script Host execution"),
    (re.compile(r'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', re.IGNORECASE), "run_key_persist", "Registry run key persistence"),
    (re.compile(r'Add-MpPreference\s+-ExclusionPath', re.IGNORECASE), "av_exclusion", "Windows Defender exclusion addition"),
    (re.compile(r'Set-MpPreference\s+-DisableRealtimeMonitoring', re.IGNORECASE), "av_disable", "Disable Windows Defender real-time monitoring"),
    # Common shellcode patterns
    (re.compile(rb'\xfc\xe8\x89\x00\x00\x00|\xfc\xe8\x82\x00\x00\x00'.decode('latin-1'), re.DOTALL), "shellcode_stub", "Common shellcode stager pattern"),
    (re.compile(r'\x90{10,}', re.DOTALL), "nop_sled", "NOP sled detected"),
]

# File type specific checks
POWERSHELL_EXTENSIONS = {'.ps1', '.psm1', '.psd1'}
PE_MAGIC = b'MZ'


def _is_binary_file(content: bytes) -> bool:
    """Heuristic: check if file appears to be binary."""
    try:
        content[:1024].decode('utf-8')
        return False
    except UnicodeDecodeError:
        return True


def main() -> None:
    parser = argparse.ArgumentParser(description="AMSI detection signature analyzer")
    parser.add_argument("--payload", required=True, help="Path to file to analyze")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"findings": []}

    try:
        if not os.path.isfile(args.payload):
            result["error"] = f"File not found: {args.payload}"
            print(json.dumps(result))
            return

        file_size = os.path.getsize(args.payload)
        _, ext = os.path.splitext(args.payload)
        ext = ext.lower()

        with open(args.payload, 'rb') as fh:
            raw_content = fh.read()

        is_binary = _is_binary_file(raw_content)

        # Decode for text analysis
        try:
            text_content = raw_content.decode('utf-8', errors='replace')
        except Exception:
            text_content = raw_content.decode('latin-1', errors='replace')

        signatures_found: list[dict] = []
        for pattern, sig_name, description in AMSI_SIGNATURES:
            try:
                if pattern.search(text_content):
                    signatures_found.append({
                        "signature": sig_name,
                        "description": description,
                        "severity": "high" if sig_name in ("amsi_bypass", "mimikatz", "mem_injection", "c2_framework") else "medium",
                    })
            except Exception:
                pass

        sig_count = len(signatures_found)
        overall_severity = "info" if sig_count == 0 else ("critical" if sig_count >= 3 else "medium" if sig_count >= 1 else "info")

        # PE file check
        is_pe = raw_content[:2] == PE_MAGIC

        result["findings"].append({
            "severity": overall_severity,
            "vulnerability_type": "amsi_test",
            "message": f"Payload analyzed — {sig_count} signature(s) detected",
            "file": args.payload,
            "file_size_bytes": file_size,
            "file_type": "PE executable" if is_pe else ("PowerShell" if ext in POWERSHELL_EXTENSIONS else "text/other"),
            "is_binary": is_binary,
            "signatures_detected": signatures_found,
        })

        if sig_count == 0:
            result["findings"].append({
                "severity": "info",
                "vulnerability_type": "amsi_test",
                "message": "No known AMSI detection signatures found — payload may be obfuscated or clean",
            })

    except Exception as exc:
        result["error"] = str(exc)
        result["findings"].append({
            "severity": "error",
            "vulnerability_type": "amsi_test",
            "message": f"AMSI analysis failed: {exc}",
        })
        logger.error("amsi_check error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
