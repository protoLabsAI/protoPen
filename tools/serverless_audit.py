"""Serverless & IaC security testing — Lambda injection, edge function auditing, IaC scanning."""

from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class ServerlessAuditTool(BasePentestTool):
    """Serverless & IaC security testing — Lambda injection, edge function auditing, IaC scanning."""

    name = "serverless_audit"
    description = (
        "Serverless & IaC security testing — Lambda injection, edge function "
        "auditing, event trigger abuse, Terraform state scanning, IaC security "
        "checks with checkov, serverless misconfiguration, and cold-start races."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "lambda_inject_test": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.lambda_inject",
                "--function-url",
                "{target}",
                "--event-type",
                "{event_type}",
                "--output-json",
            ],
            "timeout": 120,
            "description": "Test Lambda function for event injection vulnerabilities",
        },
        "edge_function_audit": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.edge_audit",
                "--url",
                "{target}",
                "--provider",
                "{provider}",
                "--output-json",
            ],
            "timeout": 120,
            "description": "Audit edge/CDN functions for security issues",
        },
        "event_trigger_abuse": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.event_trigger",
                "--function-url",
                "{target}",
                "--trigger-type",
                "{trigger_type}",
                "--output-json",
            ],
            "timeout": 120,
            "description": "Test for event trigger abuse (S3, SQS, SNS, etc.)",
        },
        "tfstate_scan": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.tfstate_scan",
                "--path",
                "{target}",
                "--output-json",
            ],
            "timeout": 120,
            "description": "Scan Terraform state files for exposed secrets and misconfigs",
        },
        "iac_security_scan": {
            "cmd": ["checkov", "--directory", "{target}", "--output", "json", "--compact"],
            "timeout": 120,
            "description": "Run checkov IaC security scan on Terraform/CloudFormation",
        },
        "serverless_misconfig": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.serverless_misconfig",
                "--profile",
                "{profile}",
                "--region",
                "{region}",
                "--output-json",
            ],
            "timeout": 120,
            "description": "Detect serverless misconfigurations in AWS account",
        },
        "cold_start_race": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.cold_start_race",
                "--function-url",
                "{target}",
                "--concurrency",
                "{concurrency}",
                "--output-json",
            ],
            "timeout": 120,
            "description": "Test cold-start race conditions in serverless functions",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        event_type: str = "http",
        provider: str = "aws",
        trigger_type: str = "s3",
        profile: str = "default",
        region: str = "us-east-1",
        concurrency: int = 50,
        timeout: int = 120,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            str(c).format(
                target=target,
                event_type=event_type,
                provider=provider,
                trigger_type=trigger_type,
                profile=profile,
                region=region,
                concurrency=concurrency,
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
