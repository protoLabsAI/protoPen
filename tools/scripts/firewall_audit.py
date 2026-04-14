#!/usr/bin/env python3
"""Firewall configuration audit.

Usage: python3 firewall_audit.py
Outputs: JSON with firewall rules and issues.
"""

import json
import platform
import subprocess


def main() -> None:
    os_type = platform.system()
    issues: list[dict] = []
    rules = ""

    if os_type == "Linux":
        try:
            r = subprocess.run(
                ["iptables", "-L", "-n", "--line-numbers"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            rules = r.stdout
        except FileNotFoundError:
            rules = ""

        if "ACCEPT" in rules and "DROP" not in rules and "REJECT" not in rules:
            issues.append(
                {
                    "severity": "high",
                    "check": "Default Policy",
                    "value": "No deny rules found",
                    "recommendation": "Set default policy to DROP",
                }
            )
        if not rules.strip() or "Chain INPUT (policy ACCEPT)" in rules:
            issues.append(
                {
                    "severity": "critical",
                    "check": "Input Policy",
                    "value": "ACCEPT (default)",
                    "recommendation": "Set INPUT policy to DROP, whitelist needed ports",
                }
            )

    elif os_type == "Darwin":
        try:
            r = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            rules = r.stdout
        except FileNotFoundError:
            rules = ""

        if "disabled" in rules.lower():
            issues.append(
                {
                    "severity": "high",
                    "check": "macOS Firewall",
                    "value": "Disabled",
                    "recommendation": "Enable application firewall",
                }
            )

    print(
        json.dumps(
            {
                "os": os_type,
                "rules_snippet": rules[:500],
                "issues": issues,
            }
        )
    )


if __name__ == "__main__":
    main()
