#!/usr/bin/env python3
"""Serverless misconfiguration detector.

Optionally uses boto3 to list Lambda functions and check for overly permissive
resource policies. If boto3 is not installed or credentials are absent, returns
an informational message.
"""

from __future__ import annotations

import argparse
import json
import sys
import logging
from typing import Any

logger = logging.getLogger(__name__)

RISKY_PRINCIPALS = {"*", "0.0.0.0/0"}
RISKY_ACTIONS = {
    "lambda:*",
    "lambda:InvokeFunction",
    "lambda:InvokeFunctionUrl",
    "sts:AssumeRole",
    "*",
}


def _check_policy_statement(stmt: dict) -> list[str]:
    """Check a single policy statement for risky permissions."""
    issues: list[str] = []
    effect = stmt.get("Effect", "")
    if effect != "Allow":
        return issues

    principal = stmt.get("Principal", {})
    if isinstance(principal, str):
        principals = {principal}
    elif isinstance(principal, dict):
        principals = set()
        for v in principal.values():
            if isinstance(v, list):
                principals.update(v)
            else:
                principals.add(v)
    else:
        principals = set()

    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]

    for principal in principals:
        if principal in RISKY_PRINCIPALS:
            for action in actions:
                if action in RISKY_ACTIONS or action == "*":
                    issues.append(f"Principal '{principal}' has '{action}' permission — public invoke possible")

    return issues


def run_boto3_checks(profile: str, region: str) -> list[dict[str, Any]]:
    """Run Lambda checks using boto3."""
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        return [
            {
                "function_name": "N/A",
                "severity": "info",
                "description": "boto3 not installed — skipping AWS credential-based checks",
            }
        ]

    misconfigs: list[dict[str, Any]] = []

    try:
        session = boto3.Session(profile_name=profile if profile != "default" else None, region_name=region)
        lambda_client = session.client("lambda")

        # List functions
        paginator = lambda_client.get_paginator("list_functions")
        functions: list[dict] = []
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))

        misconfigs.append(
            {
                "function_name": "summary",
                "severity": "info",
                "description": f"Found {len(functions)} Lambda function(s) in {region}",
            }
        )

        for func in functions:
            func_name = func.get("FunctionName", "unknown")
            func_url_config = func.get("FunctionUrlConfig")

            # Check for public function URLs
            try:
                url_config = lambda_client.get_function_url_config(FunctionName=func_name)
                auth_type = url_config.get("AuthType", "AWS_IAM")
                if auth_type == "NONE":
                    misconfigs.append(
                        {
                            "function_name": func_name,
                            "severity": "high",
                            "description": f"Lambda '{func_name}' has public Function URL with no auth (AuthType=NONE)",
                        }
                    )
            except ClientError:
                pass

            # Check resource-based policy
            try:
                policy_response = lambda_client.get_policy(FunctionName=func_name)
                policy = json.loads(policy_response.get("Policy", "{}"))
                for stmt in policy.get("Statement", []):
                    issues = _check_policy_statement(stmt)
                    for issue in issues:
                        misconfigs.append(
                            {
                                "function_name": func_name,
                                "severity": "high",
                                "description": f"Overly permissive resource policy: {issue}",
                            }
                        )
            except ClientError:
                pass

            # Check environment variables for secrets
            env = func.get("Environment", {}).get("Variables", {})
            secret_keys = {
                k for k in env if any(s in k.lower() for s in ("password", "secret", "key", "token", "credential"))
            }
            if secret_keys:
                misconfigs.append(
                    {
                        "function_name": func_name,
                        "severity": "medium",
                        "description": f"Lambda '{func_name}' has potentially sensitive environment variables: {', '.join(sorted(secret_keys))} — prefer AWS Secrets Manager",
                    }
                )

            # Check for deprecated runtime
            runtime = func.get("Runtime", "")
            deprecated_runtimes = {
                "nodejs8.10",
                "nodejs10.x",
                "nodejs12.x",
                "python2.7",
                "python3.6",
                "python3.7",
                "ruby2.5",
                "java8",
            }
            if runtime in deprecated_runtimes:
                misconfigs.append(
                    {
                        "function_name": func_name,
                        "severity": "medium",
                        "description": f"Lambda '{func_name}' uses deprecated runtime: {runtime}",
                    }
                )

    except Exception as exc:  # NoCredentialsError, etc.
        misconfigs.append(
            {
                "function_name": "N/A",
                "severity": "info",
                "description": f"AWS credentials check failed: {type(exc).__name__}: {exc}",
            }
        )

    return misconfigs


def main() -> None:
    parser = argparse.ArgumentParser(description="Serverless misconfiguration detector")
    parser.add_argument("--profile", default="default", help="AWS profile name")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--output-json", action="store_true", help="Always output JSON (default)")
    args = parser.parse_args()

    result: dict[str, Any] = {"misconfigs": []}

    try:
        misconfigs = run_boto3_checks(args.profile, args.region)
        result["misconfigs"] = misconfigs

    except Exception as exc:
        result["error"] = str(exc)
        result["misconfigs"].append(
            {
                "function_name": "N/A",
                "severity": "error",
                "description": f"Scan failed: {exc}",
            }
        )
        logger.error("serverless_misconfig error: %s", exc)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
