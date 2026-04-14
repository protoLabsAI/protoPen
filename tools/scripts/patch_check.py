#!/usr/bin/env python3
"""Pending security patch assessment.

Usage: python3 patch_check.py
Outputs: JSON with pending update counts and severity.
"""

import json
import platform
import subprocess


def main() -> None:
    os_type = platform.system()
    packages: list[str] = []

    if os_type == "Linux":
        # Try apt first, then yum
        try:
            r = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines()[1:]:
                    if "/" in line:
                        packages.append(line.split("/")[0])
            else:
                raise FileNotFoundError("apt failed")
        except FileNotFoundError:
            try:
                r = subprocess.run(
                    ["yum", "check-update", "--quiet"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                for line in r.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        packages.append(parts[0])
            except FileNotFoundError:
                pass

    elif os_type == "Darwin":
        try:
            r = subprocess.run(
                ["softwareupdate", "-l"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            for line in r.stdout.splitlines():
                if "*" in line:
                    packages.append(line.strip().lstrip("* "))
        except FileNotFoundError:
            pass

    if len(packages) > 20:
        severity = "critical"
    elif len(packages) > 5:
        severity = "high"
    elif packages:
        severity = "medium"
    else:
        severity = "info"

    print(
        json.dumps(
            {
                "os": os_type,
                "pending_updates": len(packages),
                "packages": packages[:30],
                "severity": severity,
            }
        )
    )


if __name__ == "__main__":
    main()
