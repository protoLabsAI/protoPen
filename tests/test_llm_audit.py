"""Tests for llm_audit — mocked subprocess."""
from __future__ import annotations

import json

import pytest
from unittest.mock import patch, AsyncMock

from tools.llm_audit import LLMAuditTool


@pytest.fixture
def tool():
    return LLMAuditTool()


# -- Instantiation ------------------------------------------------------------

class TestInstantiation:
    def test_has_name(self, tool):
        assert tool.name == "llm_audit"

    def test_actions_defined(self, tool):
        expected = {
            "garak_scan", "garak_probe", "promptfoo_eval", "promptfoo_redteam",
            "prompt_inject_test", "rag_poison_check", "model_extract_test",
            "jailbreak_test",
        }
        assert set(tool.ACTIONS.keys()) == expected


# -- Dispatch ------------------------------------------------------------------

class TestDispatch:
    @pytest.mark.asyncio
    async def test_unknown_action(self, tool):
        result = await tool.execute("nonexistent_action")
        assert "Unknown action" in result


# -- garak_scan ----------------------------------------------------------------

class TestGarakScan:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_garak_scan(self, mock_exec, tool):
        output = json.dumps({"vulnerabilities": [
            {"probe": "promptinject", "severity": "high",
             "description": "Prompt injection via encoding bypass"},
        ]})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("garak_scan", target="http://llm.local:8080")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "garak"
        assert "--model_name" in cmd
        assert "http://llm.local:8080" in cmd
        data = json.loads(result)
        assert len(data["vulnerabilities"]) == 1

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_garak_scan_custom_output_dir(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"vulnerabilities":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("garak_scan", target="http://llm.local", output_dir="/tmp/custom")
        cmd = mock_exec.call_args[0]
        assert "/tmp/custom/garak" in cmd


# -- garak_probe ---------------------------------------------------------------

class TestGarakProbe:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_garak_probe_specific(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"vulnerabilities":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("garak_probe", target="http://llm.local", probe="encoding")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "garak"
        assert "encoding" in cmd


# -- promptfoo_eval ------------------------------------------------------------

class TestPromptfooEval:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_promptfoo_eval(self, mock_exec, tool):
        output = json.dumps({"results": [
            {"test_name": "sql_injection", "status": "fail", "output": "leaked data"},
        ]})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "promptfoo_eval", config_path="/tmp/config.yaml",
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "promptfoo"
        assert "--config" in cmd
        assert "/tmp/config.yaml" in cmd
        data = json.loads(result)
        assert data["results"][0]["status"] == "fail"


# -- promptfoo_redteam ---------------------------------------------------------

class TestPromptfooRedteam:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_promptfoo_redteam(self, mock_exec, tool):
        output = json.dumps({"findings": [
            {"attack_type": "jailbreak", "severity": "critical",
             "description": "Model bypassed safety guardrails"},
        ]})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("promptfoo_redteam", target="http://llm.local")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "promptfoo"
        assert "redteam" in cmd
        data = json.loads(result)
        assert data["findings"][0]["attack_type"] == "jailbreak"


# -- prompt_inject_test --------------------------------------------------------

class TestPromptInjectTest:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_prompt_inject_default(self, mock_exec, tool):
        output = json.dumps({"injections": [
            {"payload_name": "ignore_previous", "success": True,
             "description": "Direct prompt injection succeeded"},
        ]})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("prompt_inject_test", target="http://llm.local")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "python3"
        assert "protopen_scripts.prompt_inject" in cmd
        assert "--payload-set" in cmd
        assert "default" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_prompt_inject_custom_payload(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"injections":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("prompt_inject_test", target="http://llm.local", payload_set="advanced")
        cmd = mock_exec.call_args[0]
        assert "advanced" in cmd


# -- rag_poison_check ----------------------------------------------------------

class TestRagPoisonCheck:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_rag_poison_check(self, mock_exec, tool):
        output = json.dumps({"poisoned_entries": [
            {"document_id": "doc-42", "severity": "high",
             "description": "Injected instruction in corpus chunk",
             "confidence": 0.95},
        ]})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute(
            "rag_poison_check", target="http://llm.local",
            corpus_path="/data/corpus",
        )
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "python3"
        assert "protopen_scripts.rag_audit" in cmd
        assert "/data/corpus" in cmd
        data = json.loads(result)
        assert data["poisoned_entries"][0]["document_id"] == "doc-42"


# -- model_extract_test --------------------------------------------------------

class TestModelExtractTest:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_model_extract_default(self, mock_exec, tool):
        output = json.dumps({"probes": [
            {"method": "logit_extraction", "similarity_score": 0.92,
             "threshold": 0.8, "queries_used": 100,
             "description": "High similarity — extraction likely"},
        ]})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("model_extract_test", target="http://llm.local")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "python3"
        assert "protopen_scripts.model_extract" in cmd
        assert "100" in cmd

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_model_extract_custom_queries(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"probes":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("model_extract_test", target="http://llm.local", num_queries=500)
        cmd = mock_exec.call_args[0]
        assert "500" in cmd


# -- jailbreak_test ------------------------------------------------------------

class TestJailbreakTest:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_jailbreak_default(self, mock_exec, tool):
        output = json.dumps({"attempts": [
            {"technique": "DAN", "success": True,
             "description": "DAN jailbreak succeeded",
             "bypassed_guardrail": "content_filter"},
        ]})
        proc = AsyncMock()
        proc.communicate.return_value = (output.encode(), b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        result = await tool.execute("jailbreak_test", target="http://llm.local")
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "python3"
        assert "protopen_scripts.jailbreak" in cmd
        assert "all" in cmd
        data = json.loads(result)
        assert data["attempts"][0]["success"] is True

    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec")
    async def test_jailbreak_specific_technique(self, mock_exec, tool):
        proc = AsyncMock()
        proc.communicate.return_value = (b'{"attempts":[]}', b"")
        proc.returncode = 0
        mock_exec.return_value = proc
        await tool.execute("jailbreak_test", target="http://llm.local", technique="DAN")
        cmd = mock_exec.call_args[0]
        assert "DAN" in cmd


# -- Binary not found ----------------------------------------------------------

class TestBinaryNotFound:
    @pytest.mark.asyncio
    @patch("tools.base.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_missing_binary(self, mock_exec, tool):
        result = await tool.execute("garak_scan", target="http://llm.local")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"]
