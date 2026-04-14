#!/usr/bin/env python3
"""Post-install script auditor.

Finds all package.json files under a given directory and checks
install-time hooks (preinstall, install, postinstall) for dangerous commands
like curl, wget, eval, exec, or downloading remote scripts.
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

INSTALL_HOOKS = ('preinstall', 'install', 'postinstall', 'prepare')

# Patterns that indicate dangerous behavior in install scripts
DANGEROUS_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'\bcurl\b', re.IGNORECASE), "high", "curl command — potential remote code download"),
    (re.compile(r'\bwget\b', re.IGNORECASE), "high", "wget command — potential remote code download"),
    (re.compile(r'\beval\b', re.IGNORECASE), "critical", "eval usage — dynamic code execution"),
    (re.compile(r'\bexec\b(?!\s*[-./\w])', re.IGNORECASE), "high", "exec() call — command execution"),
    (re.compile(r'\bpython\s+-c\b', re.IGNORECASE), "high", "inline Python execution"),
    (re.compile(r'\bpython3\s+-c\b', re.IGNORECASE), "high", "inline Python execution"),
    (re.compile(r'\bbash\s+-c\b', re.IGNORECASE), "high", "inline bash execution"),
    (re.compile(r'\bsh\s+-c\b', re.IGNORECASE), "high", "inline sh execution"),
    (re.compile(r'https?://', re.IGNORECASE), "medium", "URL reference — may download remote content"),
    (re.compile(r'\bnode\s+-e\b', re.IGNORECASE), "high", "inline Node.js evaluation"),
    (re.compile(r'\bnpx\b', re.IGNORECASE), "medium", "npx invocation — executes remote or local package"),
    (re.compile(r'base64\s+--decode|-d\b.*base64', re.IGNORECASE), "critical", "base64 decode — encoded payload execution"),
    (re.compile(r'powershell', re.IGNORECASE), "critical", "PowerShell invocation"),
    (re.compile(r'chmod\s+[+]?[0-7]*x', re.IGNORECASE), "medium", "chmod +x — making file executable"),
    (re.compile(r'/dev/tcp/', re.IGNORECASE), "critical", "bash /dev/tcp reverse shell pattern"),
    (re.compile(r'nc\s+-', re.IGNORECASE), "high", "netcat invocation — potential reverse shell"),
]


def audit_package_json(filepath: str) -> list[dict[str, Any]] | None:
    """Audit a package.json for dangerous install scripts."""
    try:
        with open(filepath) as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("Skipping %s: %s", filepath, exc)
        return None

    if not isinstance(data, dict):
        return None

    scripts = data.get('scripts', {})
    if not isinstance(scripts, dict):
        return None

    package_name = data.get('name', os.path.dirname(filepath))
    findings: list[dict[str, Any]] = []

    for hook in INSTALL_HOOKS:
        script_content = scripts.get(hook, '')
        if not script_content:
            continue

        script_str = str(script_content)
        risks: list[str] = []
        max_severity = "low"

        sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        for pattern, severity, description in DANGEROUS_PATTERNS:
            if pattern.search(script_str):
                risks.append(f"{severity}: {description}")
                if sev_order.get(severity, 0) > sev_order.get(max_severity, 0):
                    max_severity = severity

        if risks:
            findings.append({
                "package": package_name,
                "file": filepath,
                "hook": hook,
                "risk": max_severity,
                "content": script_str,
                "risks": risks,
            })

    return findings if findings else None


def main() -> None:
    parser = argparse.ArgumentParser(description="Post-install script auditor")
    parser.add_argument("--package-dir", required=True, help="Directory to scan for package.json files")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"scripts": []}

    try:
        if not os.path.isdir(args.package_dir):
            result["error"] = f"Package directory not found: {args.package_dir}"
            print(json.dumps(result))
            return

        # Find all package.json files (exclude node_modules nested packages)
        all_packages = glob.glob(
            os.path.join(args.package_dir, "**/package.json"),
            recursive=True,
        )
        # Filter out node_modules to focus on direct deps
        package_files = [
            p for p in all_packages
            if 'node_modules' not in p.split(os.sep)[:-1]
        ]

        # Also include node_modules package.json for completeness (limit depth)
        nm_packages = [
            p for p in all_packages
            if '/node_modules/' in p
            and p.count('/node_modules/') == 1  # only top-level node_modules
        ]

        all_to_check = package_files + nm_packages[:500]  # cap node_modules

        for filepath in all_to_check:
            findings = audit_package_json(filepath)
            if findings:
                result["scripts"].extend(findings)

        result["summary"] = {
            "files_scanned": len(all_to_check),
            "dangerous_scripts_found": len(result["scripts"]),
        }

    except Exception as exc:
        result["error"] = str(exc)
        logger.error("postinstall_audit error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
