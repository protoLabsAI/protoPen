"""gRPC and protobuf security testing — reflection, fuzzing, auth bypass."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class GRPCAuditTool(BasePentestTool):
    """gRPC and protobuf security testing."""

    name = "grpc_audit"
    description = (
        "gRPC security — server reflection enumeration, service description, "
        "method invocation, fuzzing, auth bypass testing, TLS enforcement checks, "
        "gRPC-Web testing, exposed endpoint scanning."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "grpc_reflection": {
            "cmd": ["grpcurl", "-plaintext", "{target}", "list"],
            "timeout": 15,
            "description": "List services via gRPC server reflection",
        },
        "grpc_describe": {
            "cmd": ["grpcurl", "-plaintext", "{target}", "describe", "{service}"],
            "timeout": 15,
            "description": "Describe service methods and message types",
        },
        "grpc_call": {
            "cmd": ["grpcurl", "-plaintext", "-d", "{data}", "{target}", "{method}"],
            "timeout": 30,
            "description": "Call a gRPC method with data payload",
        },
        "grpc_fuzz": {
            "cmd": ["grpc-fuzz", "--target", "{target}", "--service", "{service}", "--count", "{count}", "--json"],
            "timeout": 120,
            "description": "Fuzz gRPC service methods for crashes",
        },
        "grpc_auth_test": {
            "cmd": ["grpcurl", "-plaintext", "-H", "Authorization: {auth_header}", "{target}", "{method}"],
            "timeout": 15,
            "description": "Test gRPC method with/without authentication",
        },
        "grpc_tls_check": {
            "cmd": ["grpcurl", "{target}", "list"],
            "timeout": 15,
            "description": "Check if gRPC endpoint enforces TLS (no -plaintext flag)",
        },
        "grpc_web_test": {
            "cmd": [
                "grpcurl", "-plaintext", "-import-path", "{proto_path}",
                "-proto", "{proto_file}", "{target}", "{method}",
            ],
            "timeout": 30,
            "description": "Test gRPC-Web endpoint with proto definitions",
        },
        "protoscan": {
            "cmd": ["protoscan", "--target", "{target}", "--json"],
            "timeout": 60,
            "description": "Scan for exposed protobuf/gRPC endpoints",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        service: str = "",
        method: str = "",
        data: str = "{}",
        auth_header: str = "",
        proto_path: str = ".",
        proto_file: str = "",
        count: int = 1000,
        timeout: int = 30,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            str(c).format(
                target=target, service=service, method=method, data=data,
                auth_header=auth_header, proto_path=proto_path,
                proto_file=proto_file, count=count, timeout=timeout,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", timeout)

        return await self._run(
            action=action, cmd=cmd, timeout=effective_timeout, target_hint=target,
        )
