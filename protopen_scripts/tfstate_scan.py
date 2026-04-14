#!/usr/bin/env python3
"""Terraform state file secret scanner.

Finds *.tfstate and *.tfvars files under a given path and scans them
for secrets: passwords, API keys, private keys, tokens, etc.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Secret detection patterns: (pattern, key_name, severity, description)
SECRET_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP|PRIVATE)\s+PRIVATE\s+KEY-----'), "private_key", "critical", "Private key material"),
    (re.compile(r'"(?:password|passwd|pass)"\s*:\s*"([^"]{4,})"', re.IGNORECASE), "password", "critical", "Password in Terraform state"),
    (re.compile(r'"(?:secret_key|secret_access_key|aws_secret)"\s*:\s*"([A-Za-z0-9/+]{20,})"', re.IGNORECASE), "aws_secret_key", "critical", "AWS secret access key"),
    (re.compile(r'"(?:access_key|aws_access_key_id)"\s*:\s*"(AKI[A-Z0-9]{16,})"', re.IGNORECASE), "aws_access_key", "critical", "AWS access key ID"),
    (re.compile(r'"(?:api_key|apikey|api_token)"\s*:\s*"([A-Za-z0-9_\-]{20,})"', re.IGNORECASE), "api_key", "high", "API key"),
    (re.compile(r'"(?:token|auth_token|access_token|refresh_token)"\s*:\s*"([A-Za-z0-9_\-\.]{20,})"', re.IGNORECASE), "token", "high", "Auth token"),
    (re.compile(r'"(?:private_key|rsa_private_key)"\s*:\s*"(-----BEGIN)', re.IGNORECASE), "private_key", "critical", "Private key reference"),
    (re.compile(r'"connection_string"\s*:\s*"([^"]{10,})"', re.IGNORECASE), "connection_string", "high", "Database connection string"),
    (re.compile(r'"(?:database_url|db_url|db_password)"\s*:\s*"([^"]{4,})"', re.IGNORECASE), "database_cred", "critical", "Database credential"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_key_id", "critical", "AWS Access Key ID (raw)"),
    (re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}'), "github_token", "critical", "GitHub personal access token"),
    (re.compile(r'sk-[A-Za-z0-9]{20,}'), "openai_key", "critical", "OpenAI API key"),
    (re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'), "slack_token", "high", "Slack token"),
    (re.compile(r'"(?:client_secret|oauth_secret)"\s*:\s*"([A-Za-z0-9_\-]{8,})"', re.IGNORECASE), "oauth_secret", "high", "OAuth client secret"),
    (re.compile(r'-----BEGIN CERTIFICATE-----'), "certificate", "medium", "Certificate material (may be sensitive)"),
    (re.compile(r'"(?:private_dns|private_ip)"\s*:\s*"(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)', re.IGNORECASE), "private_ip", "medium", "Private IP address exposed in state"),
    (re.compile(r'"(?:account_id|aws_account_id)"\s*:\s*"(\d{12})"', re.IGNORECASE), "aws_account_id", "medium", "AWS Account ID"),
]


def _mask_value(value: str, max_prefix: int = 4) -> str:
    """Mask sensitive value for safe display."""
    if len(value) <= max_prefix:
        return "***"
    return value[:max_prefix] + "..." + ("*" * min(8, len(value) - max_prefix))


def scan_file(filepath: str) -> list[dict[str, Any]]:
    """Scan a single file for secrets."""
    findings: list[dict[str, Any]] = []

    try:
        with open(filepath, 'r', errors='replace') as fh:
            content = fh.read()
    except OSError as exc:
        logger.debug("Could not read %s: %s", filepath, exc)
        return findings

    lines = content.splitlines()

    for pattern, key_name, severity, description in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            # Find line number
            line_no = content[:match.start()].count('\n') + 1
            matched_text = match.group(0)

            # Extract the actual secret value if in a capture group
            if match.lastindex and match.lastindex >= 1:
                secret_value = match.group(1) if match.group(1) else matched_text
            else:
                secret_value = matched_text

            masked = _mask_value(secret_value)

            findings.append({
                "path": filepath,
                "severity": severity,
                "description": description,
                "key": key_name,
                "line": line_no,
                "value_preview": masked,
            })

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Terraform state file secret scanner")
    parser.add_argument("--path", required=True, help="Path to scan for .tfstate and .tfvars files")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"secrets_found": []}

    try:
        if not os.path.exists(args.path):
            result["error"] = f"Path not found: {args.path}"
            print(json.dumps(result))
            return

        # Find all tfstate and tfvars files
        tfstate_files = glob.glob(os.path.join(args.path, "**/*.tfstate"), recursive=True)
        tfvars_files = glob.glob(os.path.join(args.path, "**/*.tfvars"), recursive=True)
        tfvars_json = glob.glob(os.path.join(args.path, "**/*.tfvars.json"), recursive=True)

        all_files = tfstate_files + tfvars_files + tfvars_json

        # Also check *.auto.tfvars
        auto_tfvars = glob.glob(os.path.join(args.path, "**/*.auto.tfvars"), recursive=True)
        all_files.extend(auto_tfvars)

        if not all_files:
            result["info"] = f"No .tfstate or .tfvars files found under {args.path}"
            print(json.dumps(result))
            return

        for filepath in all_files:
            findings = scan_file(filepath)
            result["secrets_found"].extend(findings)

        result["summary"] = {
            "files_scanned": len(all_files),
            "secrets_found": len(result["secrets_found"]),
            "critical": sum(1 for s in result["secrets_found"] if s["severity"] == "critical"),
            "high": sum(1 for s in result["secrets_found"] if s["severity"] == "high"),
        }

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("tfstate_scan error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
