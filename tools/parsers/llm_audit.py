"""Parser for llm_audit output — garak, promptfoo, prompt injection, RAG, model extraction, jailbreak."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore


def parse_garak_scan(raw: str, store: "TargetStore") -> list[dict]:
    """Parse garak JSON report into normalized LLM findings."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for vuln in data.get("vulnerabilities", []):
        severity = vuln.get("severity", "medium").lower()
        entities.append(
            {
                "type": "llm_finding",
                "check": vuln.get("probe", vuln.get("name", "")),
                "severity": severity,
                "vulnerability_type": vuln.get("type", "prompt_vulnerability"),
                "details": vuln.get("description", ""),
                "detector": vuln.get("detector", ""),
                "success_rate": vuln.get("success_rate", 0.0),
            }
        )
    return entities


def parse_promptfoo_eval(raw: str, store: "TargetStore") -> list[dict]:
    """Parse promptfoo eval results JSON — pass/fail/error outcomes."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for result in data.get("results", []):
        status = result.get("status", "unknown").lower()
        if status in ("fail", "error"):
            severity = "high" if status == "fail" else "medium"
            entities.append(
                {
                    "type": "llm_finding",
                    "check": result.get("test_name", result.get("description", "")),
                    "severity": severity,
                    "vulnerability_type": "eval_failure",
                    "details": result.get("output", ""),
                    "expected": result.get("expected", ""),
                    "actual": result.get("actual", ""),
                }
            )
    return entities


def parse_promptfoo_redteam(raw: str, store: "TargetStore") -> list[dict]:
    """Parse promptfoo redteam results JSON."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for finding in data.get("findings", []):
        entities.append(
            {
                "type": "llm_finding",
                "check": finding.get("attack_type", finding.get("name", "")),
                "severity": finding.get("severity", "high").lower(),
                "vulnerability_type": "redteam_finding",
                "details": finding.get("description", ""),
                "payload": finding.get("payload", ""),
                "response": finding.get("response", ""),
            }
        )
    return entities


def parse_prompt_inject(raw: str, store: "TargetStore") -> list[dict]:
    """Parse prompt injection test results — injection success rate."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for injection in data.get("injections", []):
        success = injection.get("success", False)
        entities.append(
            {
                "type": "llm_finding",
                "check": injection.get("payload_name", injection.get("technique", "")),
                "severity": "critical" if success else "info",
                "vulnerability_type": "prompt_injection",
                "details": injection.get("description", ""),
                "success": success,
                "response": injection.get("response", ""),
            }
        )
    return entities


def parse_rag_poison(raw: str, store: "TargetStore") -> list[dict]:
    """Parse RAG poisoning check results — poisoned entries found."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for entry in data.get("poisoned_entries", []):
        entities.append(
            {
                "type": "llm_finding",
                "check": entry.get("document_id", entry.get("chunk_id", "")),
                "severity": entry.get("severity", "high").lower(),
                "vulnerability_type": "rag_poisoning",
                "details": entry.get("description", ""),
                "confidence": entry.get("confidence", 0.0),
                "source": entry.get("source", ""),
            }
        )
    return entities


def parse_model_extract(raw: str, store: "TargetStore") -> list[dict]:
    """Parse model extraction test results — similarity scores."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for probe in data.get("probes", []):
        similarity = probe.get("similarity_score", 0.0)
        extractable = similarity > probe.get("threshold", 0.8)
        entities.append(
            {
                "type": "llm_finding",
                "check": probe.get("method", probe.get("name", "")),
                "severity": "critical" if extractable else "low",
                "vulnerability_type": "model_extraction",
                "details": probe.get("description", ""),
                "similarity_score": similarity,
                "extractable": extractable,
                "queries_used": probe.get("queries_used", 0),
            }
        )
    return entities


def parse_jailbreak(raw: str, store: "TargetStore") -> list[dict]:
    """Parse jailbreak test results — successful jailbreaks."""
    entities: list[dict] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return entities

    for attempt in data.get("attempts", []):
        success = attempt.get("success", False)
        entities.append(
            {
                "type": "llm_finding",
                "check": attempt.get("technique", attempt.get("name", "")),
                "severity": "critical" if success else "info",
                "vulnerability_type": "jailbreak",
                "details": attempt.get("description", ""),
                "success": success,
                "bypassed_guardrail": attempt.get("bypassed_guardrail", ""),
            }
        )
    return entities


PARSER_MAP[("llm_audit", "garak_scan")] = parse_garak_scan
PARSER_MAP[("llm_audit", "garak_probe")] = parse_garak_scan
PARSER_MAP[("llm_audit", "promptfoo_eval")] = parse_promptfoo_eval
PARSER_MAP[("llm_audit", "promptfoo_redteam")] = parse_promptfoo_redteam
PARSER_MAP[("llm_audit", "prompt_inject_test")] = parse_prompt_inject
PARSER_MAP[("llm_audit", "rag_poison_check")] = parse_rag_poison
PARSER_MAP[("llm_audit", "model_extract_test")] = parse_model_extract
PARSER_MAP[("llm_audit", "jailbreak_test")] = parse_jailbreak
