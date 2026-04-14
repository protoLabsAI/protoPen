"""CI/CD pipeline security scanning — truffleHog, gitleaks, actionlint, semgrep, checkov."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class CICDAuditTool(BasePentestTool):
    """CI/CD pipeline and supply-chain security scanning."""

    name = "cicd_audit"
    description = (
        "CI/CD security — secret detection (truffleHog, gitleaks), "
        "GitHub Actions linting (actionlint), dependency vulnerability checks "
        "(OWASP dependency-check), static analysis (semgrep), IaC scanning (checkov)."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "trufflehog_scan": {
            "cmd": ["trufflehog", "git", "{repo_url}", "--json", "--no-update"],
            "timeout": 300,
            "description": "Scan git repo history for leaked secrets and credentials",
        },
        "trufflehog_filesystem": {
            "cmd": ["trufflehog", "filesystem", "{path}", "--json", "--no-update"],
            "timeout": 180,
            "description": "Scan local filesystem path for secrets",
        },
        "gitleaks_detect": {
            "cmd": [
                "gitleaks", "detect", "--source", "{path}",
                "--report-format", "json", "--report-path", "/dev/stdout",
                "--no-banner",
            ],
            "timeout": 180,
            "description": "Detect secrets committed to a git repository",
        },
        "gitleaks_protect": {
            "cmd": [
                "gitleaks", "protect", "--source", "{path}",
                "--report-format", "json", "--report-path", "/dev/stdout",
                "--no-banner", "--staged",
            ],
            "timeout": 60,
            "description": "Scan staged changes for secrets before commit",
        },
        "github_actions_audit": {
            "cmd": ["actionlint", "-format", "{{json .}}", "{path}"],
            "timeout": 60,
            "description": "Lint GitHub Actions workflow files for security issues",
        },
        "dependency_check": {
            "cmd": [
                "dependency-check", "--scan", "{path}",
                "--format", "JSON", "--out", "/dev/stdout",
                "--disableAssembly",
            ],
            "timeout": 600,
            "description": "OWASP dependency-check for known vulnerable libraries",
        },
        "semgrep_ci": {
            "cmd": ["semgrep", "scan", "--config", "auto", "--json", "{path}"],
            "timeout": 300,
            "description": "Static analysis security scan with semgrep rules",
        },
        "checkov_iac": {
            "cmd": ["checkov", "-d", "{path}", "-o", "json", "--compact"],
            "timeout": 180,
            "description": "Infrastructure-as-code security scan (Terraform, K8s manifests, Dockerfiles)",
        },
    }

    async def execute(
        self,
        action: str,
        repo_url: str = "",
        path: str = ".",
        timeout: int = 120,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(repo_url=repo_url, path=path, timeout=timeout)
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", timeout)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=repo_url or path,
        )
