"""Supply-chain security testing — dependency confusion, typosquatting, secret detection."""

from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class SupplyChainTool(BasePentestTool):
    """Supply-chain security testing — dependency confusion, typosquatting, secret detection."""

    name = "supply_chain"
    description = (
        "Supply-chain security testing — dependency confusion, typosquatting, "
        "package provenance auditing, post-install script analysis, and secret "
        "detection with trufflehog, gitleaks, and depscan."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "dependency_confusion_test": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.dep_confusion",
                "--registry",
                "{registry}",
                "--packages-file",
                "{packages_file}",
                "--output-json",
            ],
            "timeout": 120,
            "description": "Test for dependency confusion against package registry",
        },
        "typosquat_scan": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.typosquat",
                "--package",
                "{package_name}",
                "--registry",
                "{registry}",
                "--output-json",
            ],
            "timeout": 120,
            "description": "Scan for typosquatted package names in registry",
        },
        "package_provenance_audit": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.provenance",
                "--package",
                "{package_name}",
                "--registry",
                "{registry}",
                "--output-json",
            ],
            "timeout": 120,
            "description": "Audit package provenance and supply-chain integrity",
        },
        "postinstall_audit": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.postinstall_audit",
                "--package-dir",
                "{target}",
                "--output-json",
            ],
            "timeout": 120,
            "description": "Analyse post-install scripts for malicious behaviour",
        },
        "trufflehog_scan": {
            "cmd": ["trufflehog", "git", "file://{target}", "--json", "--no-update"],
            "timeout": 120,
            "description": "Scan git repo for leaked secrets with trufflehog",
        },
        "gitleaks_scan": {
            "cmd": [
                "gitleaks",
                "detect",
                "--source",
                "{target}",
                "--report-format",
                "json",
                "--report-path",
                "/dev/stdout",
            ],
            "timeout": 120,
            "description": "Detect hardcoded secrets in source with gitleaks",
        },
        "depscan": {
            "cmd": [
                "depscan",
                "--src",
                "{target}",
                "--report_file",
                "/dev/stdout",
                "--type",
                "{scan_type}",
            ],
            "timeout": 120,
            "description": "Dependency vulnerability scan with OWASP depscan",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        package_name: str = "",
        registry: str = "https://registry.npmjs.org",
        packages_file: str = "",
        scan_type: str = "nodejs",
        timeout: int = 120,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target,
                package_name=package_name,
                registry=registry,
                packages_file=packages_file,
                scan_type=scan_type,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", timeout)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target,
        )
