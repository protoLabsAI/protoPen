#!/usr/bin/env python3
"""TLS/SSL configuration audit.

Usage: python3 tls_audit.py <target> [port]
Outputs: JSON with protocol, cipher, cert info, and issues.
"""
import datetime
import json
import socket
import ssl
import sys


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    issues: list[dict] = []
    ctx = ssl.create_default_context()

    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(5)
            s.connect((target, port))
            cert = s.getpeercert()
            ver = s.version()
            cipher = s.cipher()

            if ver and ("TLSv1.0" in ver or "TLSv1.1" in ver or "SSLv" in ver):
                issues.append({
                    "severity": "critical",
                    "check": "Protocol Version",
                    "value": ver,
                    "recommendation": "Use TLS 1.2+ only",
                })

            not_after = cert.get("notAfter", "") if cert else ""
            exp = None
            if not_after:
                exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")

            if exp and exp < datetime.datetime.utcnow():
                issues.append({
                    "severity": "critical",
                    "check": "Certificate Expiry",
                    "value": not_after,
                    "recommendation": "Renew certificate",
                })
            elif exp and (exp - datetime.datetime.utcnow()).days < 30:
                days_left = (exp - datetime.datetime.utcnow()).days
                issues.append({
                    "severity": "high",
                    "check": "Certificate Expiry",
                    "value": f"Expires in {days_left} days",
                    "recommendation": "Renew soon",
                })

            if cipher and cipher[2] < 128:
                issues.append({
                    "severity": "high",
                    "check": "Cipher Strength",
                    "value": f"{cipher[0]} ({cipher[2]} bits)",
                    "recommendation": "Use 128-bit+ ciphers",
                })

            cert_subject = {}
            if cert and cert.get("subject"):
                cert_subject = dict(x[0] for x in cert["subject"])

            print(json.dumps({
                "target": target,
                "port": port,
                "protocol": ver,
                "cipher": cipher[0] if cipher else "",
                "cert_subject": cert_subject,
                "issues": issues,
            }))

    except Exception as e:
        print(json.dumps({
            "target": target,
            "port": port,
            "error": str(e),
            "issues": [{"severity": "info", "check": "TLS Connection", "value": str(e)}],
        }))


if __name__ == "__main__":
    main()
