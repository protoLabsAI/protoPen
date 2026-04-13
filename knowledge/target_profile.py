"""Target profiles — rich model of a target host built from tool outputs."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TargetPort:
    """A single open port on a target."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    cves: list[str] = field(default_factory=list)


@dataclass
class TargetProfile:
    """Aggregated intelligence about a single target host."""
    ip: str
    hostname: str = ""
    os: str = ""
    ports: list[TargetPort] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    web_paths: list[dict] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    shares: list[str] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    ssl_findings: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add_port(self, port: int, **kwargs) -> None:
        """Add a port if not already present."""
        if not any(p.port == port for p in self.ports):
            self.ports.append(TargetPort(port=port, **kwargs))

    def get_services(self) -> list[str]:
        """Return unique service names."""
        return list({p.service for p in self.ports if p.service})

    def has_service(self, service: str) -> bool:
        """Check if target has a specific service."""
        return any(
            service.lower() in p.service.lower()
            for p in self.ports if p.service
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os": self.os,
            "ports": [
                {
                    "port": p.port, "protocol": p.protocol,
                    "service": p.service, "version": p.version,
                }
                for p in self.ports
            ],
            "subdomains": self.subdomains,
            "web_paths": self.web_paths[:20],
            "users": self.users,
            "shares": self.shares,
            "credentials": [
                {**c, "password": "***"} for c in self.credentials
            ],
            "vulnerabilities": self.vulnerabilities[:20],
            "ssl_findings": self.ssl_findings[:10],
        }

    def summary(self) -> str:
        """One-paragraph summary for LLM context."""
        parts = [f"Target: {self.ip}"]
        if self.hostname:
            parts[0] += f" ({self.hostname})"
        if self.os:
            parts.append(f"OS: {self.os}")
        parts.append(f"Open ports: {len(self.ports)}")
        if self.ports:
            svcs = ", ".join(
                f"{p.port}/{p.service}" for p in self.ports[:10]
            )
            parts.append(f"Services: {svcs}")
        if self.vulnerabilities:
            parts.append(f"Vulns: {len(self.vulnerabilities)}")
        if self.credentials:
            parts.append(f"Creds: {len(self.credentials)}")
        if self.users:
            parts.append(f"Users: {len(self.users)}")
        return " | ".join(parts)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
