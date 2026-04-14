"""Tests for mobile_audit parsers."""

from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock

from tools.parsers.mobile_audit import (
    parse_apk_decompile,
    parse_static_analysis,
    parse_jadx_decompile,
    parse_drozer_scan,
    parse_frida_hook,
    parse_ssl_pinning,
    parse_ipc_audit,
    parse_keychain_dump,
)


@pytest.fixture
def store():
    return MagicMock()


class TestParseApkDecompile:
    def test_decompiled(self, store):
        raw = "I: decompiled successfully to /tmp/mobile_audit/decompiled"
        entities = parse_apk_decompile(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "mobile_finding"
        assert entities[0]["protocol"] == "apk"
        assert entities[0]["severity"] == "info"

    def test_empty(self, store):
        assert parse_apk_decompile("", store) == []

    def test_no_keyword(self, store):
        assert parse_apk_decompile("waiting...", store) == []


class TestParseStaticAnalysis:
    def test_findings(self, store):
        raw = json.dumps(
            {
                "findings": [
                    {"severity": "high", "description": "Hardcoded API key", "category": "security"},
                    {"severity": "medium", "description": "Debuggable flag set", "category": "config"},
                ]
            }
        )
        entities = parse_static_analysis(raw, store)
        assert len(entities) == 2
        assert entities[0]["type"] == "mobile_finding"
        assert entities[0]["protocol"] == "mobsf"
        assert entities[0]["severity"] == "high"
        assert entities[0]["value"] == "Hardcoded API key"
        assert entities[1]["target"] == "config"

    def test_empty(self, store):
        assert parse_static_analysis(json.dumps({"findings": []}), store) == []

    def test_invalid(self, store):
        assert parse_static_analysis("not json", store) == []


class TestParseJadxDecompile:
    def test_decompiled(self, store):
        raw = "INFO - decompiled 42 classes to /tmp/jadx"
        entities = parse_jadx_decompile(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "mobile_finding"
        assert entities[0]["protocol"] == "jadx"
        assert entities[0]["severity"] == "info"

    def test_empty(self, store):
        assert parse_jadx_decompile("", store) == []

    def test_no_keyword(self, store):
        assert parse_jadx_decompile("starting...", store) == []


class TestParseDrozerScan:
    def test_providers(self, store):
        raw = json.dumps(
            {
                "providers": [
                    {"name": "com.example.provider", "exported": True},
                    {"name": "com.example.internal", "exported": False},
                ]
            }
        )
        entities = parse_drozer_scan(raw, store)
        assert len(entities) == 2
        assert entities[0]["type"] == "mobile_finding"
        assert entities[0]["protocol"] == "drozer"
        assert entities[0]["severity"] == "high"
        assert entities[0]["target"] == "com.example.provider"
        assert entities[1]["severity"] == "info"

    def test_empty(self, store):
        assert parse_drozer_scan(json.dumps({"providers": []}), store) == []

    def test_invalid(self, store):
        assert parse_drozer_scan("not json", store) == []


class TestParseFridaHook:
    def test_hooks(self, store):
        raw = json.dumps(
            {
                "hooks": [
                    {"class_name": "com.example.Crypto", "method": "encrypt", "hooked": True},
                    {"class_name": "com.example.Auth", "method": "verify", "hooked": False},
                ]
            }
        )
        entities = parse_frida_hook(raw, store)
        assert len(entities) == 2
        assert entities[0]["type"] == "mobile_finding"
        assert entities[0]["protocol"] == "frida"
        assert entities[0]["target"] == "com.example.Crypto"
        assert entities[0]["severity"] == "medium"
        assert entities[0]["value"] == "encrypt"
        assert entities[1]["severity"] == "info"

    def test_empty(self, store):
        assert parse_frida_hook(json.dumps({"hooks": []}), store) == []

    def test_invalid(self, store):
        assert parse_frida_hook("{bad", store) == []


class TestParseSslPinning:
    def test_disabled(self, store):
        raw = "SSL pinning disabled for com.example.app"
        entities = parse_ssl_pinning(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "mobile_finding"
        assert entities[0]["protocol"] == "objection"
        assert entities[0]["severity"] == "high"

    def test_bypassed(self, store):
        raw = "Certificate pinning bypassed successfully"
        entities = parse_ssl_pinning(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "high"

    def test_info(self, store):
        raw = "No pinning detected"
        entities = parse_ssl_pinning(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "info"

    def test_empty(self, store):
        assert parse_ssl_pinning("", store) == []


class TestParseIpcAudit:
    def test_components(self, store):
        raw = json.dumps(
            {
                "components": [
                    {"type": "activity", "name": "com.example.LoginActivity", "exported": True},
                    {"type": "service", "name": "com.example.BackgroundService", "exported": False},
                ]
            }
        )
        entities = parse_ipc_audit(raw, store)
        assert len(entities) == 2
        assert entities[0]["type"] == "mobile_finding"
        assert entities[0]["protocol"] == "drozer"
        assert entities[0]["check"] == "ipc_audit"
        assert entities[0]["severity"] == "high"
        assert entities[0]["value"] == "activity"
        assert entities[1]["severity"] == "info"

    def test_empty(self, store):
        assert parse_ipc_audit(json.dumps({"components": []}), store) == []

    def test_invalid(self, store):
        assert parse_ipc_audit("not json", store) == []


class TestParseKeychainDump:
    def test_entries(self, store):
        raw = json.dumps(
            {
                "entries": [
                    {"alias": "api_key", "type": "SecretKey", "accessible": True},
                    {"alias": "cert", "type": "Certificate", "accessible": False},
                ]
            }
        )
        entities = parse_keychain_dump(raw, store)
        assert len(entities) == 2
        assert entities[0]["type"] == "mobile_finding"
        assert entities[0]["protocol"] == "objection"
        assert entities[0]["check"] == "keychain_dump"
        assert entities[0]["target"] == "api_key"
        assert entities[0]["severity"] == "high"
        assert entities[0]["value"] == "SecretKey"
        assert entities[1]["severity"] == "info"

    def test_empty(self, store):
        assert parse_keychain_dump(json.dumps({"entries": []}), store) == []

    def test_invalid(self, store):
        assert parse_keychain_dump("not json", store) == []
