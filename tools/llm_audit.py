"""AI/LLM security testing — prompt injection, model abuse, RAG poisoning detection."""
from __future__ import annotations

import logging
from typing import Any

from tools.base import BasePentestTool

logger = logging.getLogger(__name__)


class LLMAuditTool(BasePentestTool):
    """AI/LLM security testing — prompt injection, model abuse, RAG poisoning detection."""

    name = "llm_audit"
    description = (
        "AI/LLM security testing — prompt injection, model abuse, RAG poisoning "
        "detection. Wraps garak, promptfoo, and custom scripts for jailbreak, "
        "model extraction, and RAG poisoning checks."
    )

    ACTIONS: dict[str, dict[str, Any]] = {
        "garak_scan": {
            "cmd": [
                "garak", "--model_type", "rest",
                "--model_name", "{target}",
                "--probes", "all",
                "--report_prefix", "{output_dir}/garak",
            ],
            "timeout": 600,
            "description": "Full garak vulnerability scan against LLM endpoint",
        },
        "garak_probe": {
            "cmd": [
                "garak", "--model_type", "rest",
                "--model_name", "{target}",
                "--probes", "{probe}",
                "--report_prefix", "{output_dir}/garak",
            ],
            "timeout": 300,
            "description": "Run specific garak probe (e.g. promptinject, encoding)",
        },
        "promptfoo_eval": {
            "cmd": [
                "promptfoo", "eval",
                "--config", "{config_path}",
                "--output", "{output_dir}/results.json",
            ],
            "timeout": 300,
            "description": "Evaluate LLM against red-team test cases",
        },
        "promptfoo_redteam": {
            "cmd": [
                "promptfoo", "redteam",
                "--target", "{target}",
                "--output", "{output_dir}/redteam.json",
            ],
            "timeout": 300,
            "description": "Automated red-team testing of LLM endpoint",
        },
        "prompt_inject_test": {
            "cmd": [
                "python3", "-m", "protopen_scripts.prompt_inject",
                "--url", "{target}",
                "--payload-set", "{payload_set}",
                "--output-json",
            ],
            "timeout": 120,
            "description": "Test for direct/indirect prompt injection vulnerabilities",
        },
        "rag_poison_check": {
            "cmd": [
                "python3", "-m", "protopen_scripts.rag_audit",
                "--url", "{target}",
                "--corpus-path", "{corpus_path}",
                "--output-json",
            ],
            "timeout": 180,
            "description": "Detect RAG poisoning in knowledge base content",
        },
        "model_extract_test": {
            "cmd": [
                "python3", "-m", "protopen_scripts.model_extract",
                "--url", "{target}",
                "--queries", "{num_queries}",
                "--output-json",
            ],
            "timeout": 240,
            "description": "Test for model weight extraction via API queries",
        },
        "jailbreak_test": {
            "cmd": [
                "python3", "-m", "protopen_scripts.jailbreak",
                "--url", "{target}",
                "--technique", "{technique}",
                "--output-json",
            ],
            "timeout": 120,
            "description": "Test jailbreak techniques against LLM",
        },
    }

    async def execute(
        self,
        action: str,
        target: str = "",
        probe: str = "all",
        config_path: str = "",
        output_dir: str = "/tmp/llm_audit",
        payload_set: str = "default",
        corpus_path: str = "",
        num_queries: int = 100,
        technique: str = "all",
        timeout: int = 300,
    ) -> str:
        if action not in self.ACTIONS:
            return self._unknown_action(action)

        spec = self.ACTIONS[action]
        cmd = [
            c.format(
                target=target,
                probe=probe,
                config_path=config_path,
                output_dir=output_dir,
                payload_set=payload_set,
                corpus_path=corpus_path,
                num_queries=num_queries,
                technique=technique,
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
