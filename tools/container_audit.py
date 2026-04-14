"""Container & Kubernetes security auditing — kube-hunter, deepce, CDK, kube-bench, Trivy."""
from __future__ import annotations

import json
import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class ContainerAuditTool(BasePentestTool):
    """Container and Kubernetes security auditing and escape detection."""

    name = "container_audit"
    description = (
        "Container & K8s security — kube-hunter cluster scanning, deepce container "
        "escape detection, CDK exploitation toolkit, kube-bench CIS benchmarks, "
        "Trivy image vulnerability scanning."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "kube_hunter": {
            "cmd": ["kube-hunter", "--remote", "{target}", "--report", "json"],
            "timeout": 120,
            "description": "Scan Kubernetes cluster for security weaknesses (RBAC, exposed APIs, CVEs)",
        },
        "kube_hunter_internal": {
            "cmd": ["kube-hunter", "--internal", "--report", "json"],
            "timeout": 120,
            "description": "Run kube-hunter from inside a pod (in-cluster scan)",
        },
        "kube_bench": {
            "cmd": ["kube-bench", "run", "--json"],
            "timeout": 180,
            "description": "Run CIS Kubernetes Benchmark checks against the local node",
        },
        "kube_bench_target": {
            "cmd": [
                "kube-bench", "run", "--json",
                "--benchmark", "{benchmark}",
            ],
            "timeout": 180,
            "description": "Run CIS benchmark for a specific K8s version (e.g. gke-1.2.0, eks-1.1.0)",
        },
        "deepce": {
            "cmd": ["deepce", "--json", "--no-color"],
            "timeout": 60,
            "description": "Detect container escape vectors from inside a running container",
        },
        "cdk_evaluate": {
            "cmd": ["cdk", "evaluate", "--full", "--output", "json"],
            "timeout": 90,
            "description": "Evaluate container for exploitation opportunities (CDK toolkit)",
        },
        "cdk_exploit": {
            "cmd": ["cdk", "exploit", "{exploit_name}"],
            "timeout": 60,
            "description": "Run a specific CDK exploit (e.g. service-account, mount-cgroup)",
        },
        "trivy_image": {
            "cmd": [
                "trivy", "image", "--format", "json",
                "--severity", "{severity}", "{image}",
            ],
            "timeout": 300,
            "description": "Scan container image for known CVEs (Trivy)",
        },
        "trivy_k8s": {
            "cmd": [
                "trivy", "k8s", "--format", "json",
                "--report", "summary", "{target}",
            ],
            "timeout": 300,
            "description": "Scan Kubernetes cluster resources for misconfigurations and CVEs",
        },
        "trivy_fs": {
            "cmd": [
                "trivy", "fs", "--format", "json",
                "--severity", "{severity}", "{path}",
            ],
            "timeout": 180,
            "description": "Scan filesystem/project for vulnerabilities in dependencies",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "localhost",
        image: str = "",
        path: str = ".",
        severity: str = "HIGH,CRITICAL",
        benchmark: str = "cis-1.8",
        exploit_name: str = "",
        timeout: int = 120,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target,
                image=image,
                path=path,
                severity=severity,
                benchmark=benchmark,
                exploit_name=exploit_name,
                timeout=timeout,
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
