"""Tests for grpc_audit parsers."""

from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock

from tools.parsers.grpc_audit import (
    parse_grpc_reflection,
    parse_grpc_describe,
    parse_grpc_call,
    parse_grpc_fuzz,
    parse_grpc_auth_test,
    parse_grpc_tls_check,
    parse_protoscan,
)


@pytest.fixture
def store():
    return MagicMock()


class TestParseReflection:
    def test_services(self, store):
        raw = "grpc.health.v1.Health\nmy.service.v1.Api\n"
        entities = parse_grpc_reflection(raw, store)
        assert len(entities) == 2
        assert entities[0]["type"] == "grpc_finding"
        assert entities[0]["service"] == "grpc.health.v1.Health"
        assert entities[1]["service"] == "my.service.v1.Api"

    def test_empty(self, store):
        assert parse_grpc_reflection("", store) == []


class TestParseDescribe:
    def test_description(self, store):
        raw = "rpc GetUser (.UserReq) returns (.UserResp)\nrpc ListUsers (.Empty) returns (.UserList)\n"
        entities = parse_grpc_describe(raw, store)
        assert len(entities) == 1
        assert "GetUser" in entities[0]["value"]

    def test_empty(self, store):
        assert parse_grpc_describe("", store) == []


class TestParseCall:
    def test_json_response(self, store):
        raw = json.dumps({"id": "1", "name": "admin"})
        entities = parse_grpc_call(raw, store)
        assert len(entities) == 1
        assert "admin" in entities[0]["value"]

    def test_text_response(self, store):
        entities = parse_grpc_call("Some text response", store)
        assert len(entities) == 1

    def test_empty(self, store):
        assert parse_grpc_call("", store) == []


class TestParseFuzz:
    def test_results(self, store):
        raw = json.dumps(
            {"results": [{"service": "my.Api", "method": "GetUser", "severity": "high", "message": "crash on input"}]}
        )
        entities = parse_grpc_fuzz(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "high"

    def test_empty_results(self, store):
        assert parse_grpc_fuzz(json.dumps({"results": []}), store) == []

    def test_invalid(self, store):
        assert parse_grpc_fuzz("not json", store) == []


class TestParseAuthTest:
    def test_auth_bypass(self, store):
        raw = '{"id":"1","name":"admin"}'
        entities = parse_grpc_auth_test(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "critical"

    def test_permission_denied(self, store):
        raw = "PermissionDenied: token expired"
        entities = parse_grpc_auth_test(raw, store)
        assert entities[0]["severity"] == "info"

    def test_empty(self, store):
        assert parse_grpc_auth_test("", store) == []


class TestParseTLSCheck:
    def test_tls_enforced(self, store):
        raw = "grpc.health.v1.Health\n"
        entities = parse_grpc_tls_check(raw, store)
        assert len(entities) == 1
        assert entities[0]["severity"] == "info"

    def test_tls_failed(self, store):
        raw = "Failed to dial target: connection refused"
        entities = parse_grpc_tls_check(raw, store)
        assert entities[0]["severity"] == "high"

    def test_empty(self, store):
        assert parse_grpc_tls_check("", store) == []


class TestParseProtoscan:
    def test_endpoints(self, store):
        raw = json.dumps({"endpoints": [{"host": "10.0.0.1:50051", "service": "my.Api"}]})
        entities = parse_protoscan(raw, store)
        assert len(entities) == 1
        assert entities[0]["target"] == "10.0.0.1:50051"

    def test_empty(self, store):
        assert parse_protoscan(json.dumps({"endpoints": []}), store) == []

    def test_invalid(self, store):
        assert parse_protoscan("not json", store) == []
