"""Tests for recon_pipeline parsers (mixed JSON-object + JSONL inputs)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from tools.parsers.recon_pipeline import (
    parse_asset_correlate,
    parse_attack_graph,
    parse_full_pipeline,
    parse_nuclei,
    parse_screenshot,
    parse_subdomain_httpx,
    parse_tech_detect,
)


@pytest.fixture
def store():
    return MagicMock()


class TestFullPipeline:
    def test_subdomains(self, store):
        raw = json.dumps(
            {
                "subdomains": [
                    {"subdomain": "api.example.com", "ips": ["1.2.3.4"], "status": 200, "technologies": ["nginx"]}
                ],
                "technologies": {"nginx": 1},
            }
        )
        entities = parse_full_pipeline(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "recon_asset"
        assert entities[0]["check"] == "subdomain"
        assert entities[0]["target"] == "api.example.com"
        assert "nginx" in entities[0]["value"]

    def test_invalid(self, store):
        assert parse_full_pipeline("not json", store) == []


class TestSubdomainHttpx:
    def test_jsonl(self, store):
        raw = "\n".join(
            [
                json.dumps({"url": "https://a.example", "status_code": 200, "title": "A"}),
                json.dumps({"url": "https://b.example", "status_code": 403, "title": "B"}),
            ]
        )
        entities = parse_subdomain_httpx(raw, store)
        assert len(entities) == 2
        assert entities[0]["target"] == "https://a.example"
        assert "status=200" in entities[0]["value"]

    def test_skips_non_json_lines(self, store):
        raw = "warming up...\n" + json.dumps({"url": "https://a.example", "status_code": 200})
        assert len(parse_subdomain_httpx(raw, store)) == 1


class TestNuclei:
    def test_findings(self, store):
        raw = json.dumps(
            {
                "template-id": "CVE-2021-44228",
                "info": {"name": "Log4Shell", "severity": "critical"},
                "matched-at": "https://x.example",
                "host": "x.example",
            }
        )
        entities = parse_nuclei(raw, store)
        assert entities[0]["type"] == "recon_finding"
        assert entities[0]["severity"] == "critical"
        assert entities[0]["target"] == "https://x.example"
        assert entities[0]["title"] == "Log4Shell"
        assert entities[0]["check"] == "CVE-2021-44228"


class TestScreenshot:
    def test_screenshots(self, store):
        raw = json.dumps({"screenshots": [{"url": "https://x", "status": "live", "path": "/shots/x.png"}]})
        entities = parse_screenshot(raw, store)
        assert entities[0]["check"] == "screenshot"
        assert entities[0]["target"] == "https://x"
        assert "live" in entities[0]["value"]


class TestAssetCorrelate:
    def test_assets(self, store):
        raw = json.dumps(
            {
                "assets": [
                    {"type": "subdomain", "host": "a.example", "technologies": ["react"], "source": "subfinder"}
                ],
                "correlations": [],
            }
        )
        entities = parse_asset_correlate(raw, store)
        assert entities[0]["check"] == "asset:subdomain"
        assert entities[0]["target"] == "a.example"
        assert "react" in entities[0]["value"]


class TestAttackGraph:
    def test_nodes(self, store):
        raw = json.dumps({"nodes": [{"id": "n1", "category": "cdn_waf", "label": "cloudflare"}], "edges": []})
        entities = parse_attack_graph(raw, store)
        assert entities[0]["type"] == "recon_finding"
        assert entities[0]["target"] == "n1"
        assert entities[0]["value"] == "cdn_waf"

    def test_invalid(self, store):
        assert parse_attack_graph("{", store) == []


class TestTechDetect:
    def test_tech_list(self, store):
        raw = json.dumps({"url": "https://x", "tech": ["nginx", "php"]})
        entities = parse_tech_detect(raw, store)
        assert entities[0]["check"] == "tech_detect"
        assert "nginx" in entities[0]["value"]
        assert "php" in entities[0]["value"]
