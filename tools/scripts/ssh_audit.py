#!/usr/bin/env python3
"""SSH configuration audit against CIS benchmarks.

Usage: python3 ssh_audit.py <target>
Outputs: JSON with checks, issues, pass/fail counts.
"""

import json
import subprocess
import sys


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "localhost"

    try:
        r = subprocess.run(
            ["ssh", "-G", target],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        print(
            json.dumps(
                {
                    "target": target,
                    "error": "ssh not found",
                    "checks_run": 0,
                    "issues": [],
                    "pass_count": 0,
                    "fail_count": 0,
                }
            )
        )
        return

    cfg: dict[str, str] = {}
    for line in r.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            cfg[parts[0]] = parts[1]

    issues: list[dict] = []

    if cfg.get("passwordauthentication", "") == "yes":
        issues.append(
            {
                "severity": "high",
                "check": "PasswordAuthentication",
                "value": "yes",
                "recommendation": "Set to no, use key-based auth",
            }
        )

    if cfg.get("permitrootlogin", "") != "no":
        issues.append(
            {
                "severity": "high",
                "check": "PermitRootLogin",
                "value": cfg.get("permitrootlogin", "unset"),
                "recommendation": "Set to no",
            }
        )

    if cfg.get("protocol", "") == "1":
        issues.append(
            {
                "severity": "critical",
                "check": "Protocol",
                "value": "1",
                "recommendation": "Use Protocol 2 only",
            }
        )

    if cfg.get("x11forwarding", "") == "yes":
        issues.append(
            {
                "severity": "medium",
                "check": "X11Forwarding",
                "value": "yes",
                "recommendation": "Disable unless needed",
            }
        )

    if cfg.get("permitemptypasswords", "") == "yes":
        issues.append(
            {
                "severity": "critical",
                "check": "PermitEmptyPasswords",
                "value": "yes",
                "recommendation": "Set to no",
            }
        )

    print(
        json.dumps(
            {
                "target": target,
                "checks_run": 5,
                "issues": issues,
                "pass_count": 5 - len(issues),
                "fail_count": len(issues),
            }
        )
    )


if __name__ == "__main__":
    main()
