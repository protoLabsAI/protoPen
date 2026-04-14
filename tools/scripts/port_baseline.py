#!/usr/bin/env python3
"""Port baseline comparison — compare open ports against expected set.

Usage: python3 port_baseline.py <target> [expected_ports_json] [timeout]
Outputs: JSON with open ports, unexpected, and missing ports.
"""

import json
import subprocess
import sys
import xml.etree.ElementTree as ET


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    expected_ports = json.loads(sys.argv[2]) if len(sys.argv) > 2 else [22, 80, 443]
    timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 60

    # Build a port range covering expected ports + common ports (1-1024)
    # instead of all 65535 which is too slow for baseline checks
    if expected_ports:
        extra = ",".join(str(p) for p in expected_ports if p > 1024)
        port_spec = f"1-1024,{extra}" if extra else "1-1024"
    else:
        port_spec = "1-1024"

    try:
        r = subprocess.run(
            ["nmap", "-sT", f"-p{port_spec}", "--min-rate=1000", "-T4", target, "-oX", "-"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        print(
            json.dumps(
                {
                    "target": target,
                    "error": "nmap not found",
                    "open_ports": [],
                    "expected": expected_ports,
                    "unexpected": [],
                    "missing_expected": expected_ports,
                    "issues": [],
                }
            )
        )
        return

    ports: list[dict] = []
    try:
        root = ET.fromstring(r.stdout)
        for p in root.iter("port"):
            state = p.find("state")
            svc = p.find("service")
            if state is not None and state.get("state") == "open":
                ports.append(
                    {
                        "port": int(p.get("portid", 0)),
                        "protocol": p.get("protocol", ""),
                        "service": svc.get("name", "") if svc is not None else "",
                    }
                )
    except ET.ParseError:
        pass

    open_set = {p["port"] for p in ports}
    unexpected = [p for p in ports if p["port"] not in expected_ports]
    missing = [ep for ep in expected_ports if ep not in open_set]

    print(
        json.dumps(
            {
                "target": target,
                "open_ports": ports,
                "expected": expected_ports,
                "unexpected": unexpected,
                "missing_expected": missing,
                "issues": [
                    {"severity": "high", "check": "Unexpected port", "port": p["port"], "service": p["service"]}
                    for p in unexpected
                ],
            }
        )
    )


if __name__ == "__main__":
    main()
