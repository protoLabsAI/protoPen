#!/usr/bin/env python3
"""SSH hardening validation against security baseline.

Usage: python3 ssh_harden.py <target>
Outputs: JSON with per-check pass/fail, severity, and remediation.
"""

import json
import subprocess
import sys


RULES = [
    ("PermitRootLogin", "no", "critical", "PermitRootLogin no"),
    ("PasswordAuthentication", "no", "high", "PasswordAuthentication no"),
    ("PermitEmptyPasswords", "no", "critical", "PermitEmptyPasswords no"),
    ("X11Forwarding", "no", "medium", "X11Forwarding no"),
    ("MaxAuthTries", "3", "medium", "MaxAuthTries 3"),
    ("AllowAgentForwarding", "no", "low", "AllowAgentForwarding no"),
    ("ClientAliveInterval", "300", "low", "ClientAliveInterval 300"),
    ("LoginGraceTime", "60", "medium", "LoginGraceTime 60"),
]


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
                    "service": "ssh",
                    "target": target,
                    "error": "ssh not found",
                    "total_checks": 0,
                    "passed": 0,
                    "failed": 0,
                    "checks": [],
                }
            )
        )
        return

    cfg: dict[str, str] = {}
    for line in r.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            cfg[parts[0]] = parts[1]

    checks: list[dict] = []
    for setting, expected, severity, fix in RULES:
        actual = cfg.get(setting.lower(), "unset")
        passed = actual == expected
        checks.append(
            {
                "check": setting,
                "expected": expected,
                "actual": actual,
                "passed": passed,
                "severity": severity,
                "remediation": f"Set in /etc/ssh/sshd_config: {fix}",
            }
        )

    passed_count = sum(1 for c in checks if c["passed"])
    print(
        json.dumps(
            {
                "service": "ssh",
                "target": target,
                "total_checks": len(checks),
                "passed": passed_count,
                "failed": len(checks) - passed_count,
                "checks": checks,
            }
        )
    )


if __name__ == "__main__":
    main()
