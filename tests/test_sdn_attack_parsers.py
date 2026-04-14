"""Tests for sdn_attack parsers."""

from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock

from tools.parsers.sdn_attack import (
    parse_sdn_controller_enum,
    parse_netconf_exploit,
    parse_network_policy,
    parse_yang_model,
    parse_restconf,
    parse_openflow,
)


@pytest.fixture
def store():
    return MagicMock()


class TestParseSDNControllerEnum:
    def test_controllers(self, store):
        raw = json.dumps(
            {
                "controllers": [
                    {"host": "10.0.0.1", "type": "OpenDaylight", "severity": "medium"},
                    {"host": "10.0.0.2", "type": "ONOS", "severity": "low"},
                ]
            }
        )
        entities = parse_sdn_controller_enum(raw, store)
        assert len(entities) == 2
        assert entities[0]["type"] == "sdn_finding"
        assert entities[0]["protocol"] == "sdn"
        assert entities[0]["target"] == "10.0.0.1"
        assert entities[0]["value"] == "OpenDaylight"
        assert entities[1]["target"] == "10.0.0.2"

    def test_empty(self, store):
        assert parse_sdn_controller_enum(json.dumps({"controllers": []}), store) == []

    def test_invalid(self, store):
        assert parse_sdn_controller_enum("not json", store) == []


class TestParseNETCONFExploit:
    def test_vulnerabilities(self, store):
        raw = json.dumps(
            {
                "vulnerabilities": [
                    {"target": "10.0.0.1", "severity": "critical", "description": "Default credentials accepted"},
                ]
            }
        )
        entities = parse_netconf_exploit(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "sdn_finding"
        assert entities[0]["protocol"] == "netconf"
        assert entities[0]["severity"] == "critical"
        assert entities[0]["value"] == "Default credentials accepted"

    def test_empty(self, store):
        assert parse_netconf_exploit(json.dumps({"vulnerabilities": []}), store) == []

    def test_invalid(self, store):
        assert parse_netconf_exploit("not json", store) == []


class TestParseNetworkPolicy:
    def test_policy_issues(self, store):
        raw = json.dumps(
            {
                "policy_issues": [
                    {"controller": "odl-1", "severity": "high", "description": "Overly permissive ACL on port 80"},
                    {"controller": "odl-1", "severity": "medium", "description": "No rate limiting on northbound API"},
                ]
            }
        )
        entities = parse_network_policy(raw, store)
        assert len(entities) == 2
        assert entities[0]["protocol"] == "sdn"
        assert entities[0]["check"] == "network_policy_audit"
        assert entities[0]["target"] == "odl-1"

    def test_empty(self, store):
        assert parse_network_policy(json.dumps({"policy_issues": []}), store) == []

    def test_invalid(self, store):
        assert parse_network_policy("{bad", store) == []


class TestParseYANGModel:
    def test_models(self, store):
        raw = json.dumps(
            {
                "models": [
                    {"target": "10.0.0.1", "module": "ietf-interfaces", "severity": "info"},
                    {"target": "10.0.0.1", "module": "openconfig-network-instance"},
                ]
            }
        )
        entities = parse_yang_model(raw, store)
        assert len(entities) == 2
        assert entities[0]["protocol"] == "yang"
        assert entities[0]["value"] == "ietf-interfaces"
        assert entities[1]["severity"] == "info"  # default

    def test_empty(self, store):
        assert parse_yang_model(json.dumps({"models": []}), store) == []

    def test_invalid(self, store):
        assert parse_yang_model("", store) == []


class TestParseRESTCONF:
    def test_endpoints(self, store):
        raw = json.dumps(
            {
                "endpoints": [
                    {
                        "url": "https://10.0.0.1:8181/restconf/data",
                        "severity": "medium",
                        "path": "/restconf/data",
                        "description": "Unauthenticated read",
                    },
                ]
            }
        )
        entities = parse_restconf(raw, store)
        assert len(entities) == 1
        assert entities[0]["protocol"] == "restconf"
        assert entities[0]["target"] == "https://10.0.0.1:8181/restconf/data"
        assert entities[0]["value"] == "Unauthenticated read"

    def test_empty(self, store):
        assert parse_restconf(json.dumps({"endpoints": []}), store) == []

    def test_invalid(self, store):
        assert parse_restconf("not json", store) == []


class TestParseOpenFlow:
    def test_issues(self, store):
        raw = json.dumps(
            {
                "issues": [
                    {"target": "10.0.0.5", "severity": "high", "description": "No TLS on OpenFlow channel"},
                    {"switch": "sw-02", "severity": "critical", "message": "Default flow table allows all"},
                ]
            }
        )
        entities = parse_openflow(raw, store)
        assert len(entities) == 2
        assert entities[0]["protocol"] == "openflow"
        assert entities[0]["target"] == "10.0.0.5"
        assert entities[0]["value"] == "No TLS on OpenFlow channel"
        assert entities[1]["target"] == "sw-02"
        assert entities[1]["value"] == "Default flow table allows all"

    def test_empty(self, store):
        assert parse_openflow(json.dumps({"issues": []}), store) == []

    def test_invalid(self, store):
        assert parse_openflow("not json", store) == []
