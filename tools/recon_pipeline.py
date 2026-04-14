"""Recon pipeline — subdomain enumeration, nuclei scanning, screenshots, attack graphs."""

from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class ReconPipelineTool(BasePentestTool):
    """Recon pipeline — subdomain enumeration, nuclei scanning, screenshots, attack graphs."""

    name = "recon_pipeline"
    description = (
        "Automated recon pipeline — full subdomain enumeration, HTTP probing, "
        "nuclei vulnerability scanning, screenshot capture, asset correlation, "
        "attack graph generation, and technology detection."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "full_pipeline": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.recon_pipeline",
                "--domain",
                "{domain}",
                "--output-dir",
                "{output_dir}",
                "--threads",
                "{threads}",
                "--output-json",
            ],
            "timeout": 300,
            "description": "Run full recon pipeline: subdomains, probing, scanning",
        },
        "subdomain_httpx": {
            "cmd": [
                "bash",
                "-c",
                "subfinder -d {domain} -silent | httpx -json -o /dev/stdout",
            ],
            "timeout": 300,
            "description": "Enumerate subdomains with subfinder and probe with httpx",
        },
        "nuclei_scan": {
            "cmd": [
                "nuclei",
                "-target",
                "{target}",
                "-severity",
                "{severity}",
                "-json",
                "-o",
                "/dev/stdout",
            ],
            "timeout": 300,
            "description": "Run nuclei vulnerability templates against target",
        },
        "screenshot_capture": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.screenshot",
                "--targets-file",
                "{targets_file}",
                "--output-dir",
                "{output_dir}",
                "--output-json",
            ],
            "timeout": 300,
            "description": "Capture screenshots of discovered web assets",
        },
        "asset_correlate": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.asset_correlate",
                "--input-dir",
                "{output_dir}",
                "--output-json",
            ],
            "timeout": 300,
            "description": "Correlate discovered assets across recon data sources",
        },
        "attack_graph_build": {
            "cmd": [
                "python3",
                "-m",
                "protopen_scripts.attack_graph",
                "--input-dir",
                "{output_dir}",
                "--domain",
                "{domain}",
                "--output-json",
            ],
            "timeout": 300,
            "description": "Build attack graph from correlated recon data",
        },
        "tech_detect": {
            "cmd": [
                "httpx",
                "-target",
                "{target}",
                "-tech-detect",
                "-json",
                "-o",
                "/dev/stdout",
            ],
            "timeout": 300,
            "description": "Detect technologies used by target web application",
        },
    }

    async def execute(
        self,
        action: str,
        domain: str = "",
        target: str = "",
        targets_file: str = "",
        output_dir: str = "/tmp/recon_pipeline",
        threads: int = 50,
        severity: str = "medium,high,critical",
        timeout: int = 300,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            str(c).format(
                domain=domain,
                target=target,
                targets_file=targets_file,
                output_dir=output_dir,
                threads=threads,
                severity=severity,
            )
            for c in spec["cmd"]
        ]
        effective_timeout = spec.get("timeout", timeout)

        return await self._run(
            action=action,
            cmd=cmd,
            timeout=effective_timeout,
            target_hint=target or domain,
        )
