"""Tests for Phase 3 tools — JWT, SSRF, Auth, Rate Limit, GraphQL, TechniqueLibrary."""
from __future__ import annotations

import json
import pathlib
import tempfile

import pytest
import pytest_asyncio

from tools.base import BasePentestTool
from tools.jwt_tool import JwtTool
from tools.ssrf_detect import SsrfDetectTool
from tools.auth_test import AuthTestTool
from tools.rate_limit import RateLimitTool
from tools.graphql_test import GraphqlTestTool
from knowledge.technique_library import Technique, TechniqueLibrary


# ── BasePentestTool ──────────────────────────────────────────────────────────

class TestBasePentestTool:
    def test_unknown_action(self):
        class FakeTool(BasePentestTool):
            name = "fake"
            ACTIONS = {"alpha": {}, "beta": {}}

        t = FakeTool()
        msg = t._unknown_action("gamma")
        assert "Unknown action: gamma" in msg
        assert "alpha" in msg
        assert "beta" in msg

    def test_target_store_default_none(self):
        t = BasePentestTool()
        assert t._target_store is None

    @pytest.mark.asyncio
    async def test_execute_raises_not_implemented(self):
        t = BasePentestTool()
        with pytest.raises(NotImplementedError):
            await t.execute("any")

    @pytest.mark.asyncio
    async def test_run_returns_stdout(self):
        t = BasePentestTool()
        t.name = "test"
        result = await t._run(
            action="echo", cmd=["echo", "hello"], timeout=5, target_hint="test",
        )
        assert result == "hello"

    @pytest.mark.asyncio
    async def test_run_timeout(self):
        t = BasePentestTool()
        t.name = "test"
        result = await t._run(
            action="sleep", cmd=["sleep", "30"], timeout=1, target_hint="test",
        )
        assert "timed out" in result


# ── JwtTool ──────────────────────────────────────────────────────────────────

class TestJwtTool:
    def test_instantiation(self):
        t = JwtTool()
        assert t.name == "jwt_tool"
        assert t._target_store is None

    def test_actions_defined(self):
        t = JwtTool()
        assert "jwt_decode" in t.ACTIONS
        assert "jwt_alg_none" in t.ACTIONS
        assert "jwt_crack" in t.ACTIONS
        assert "jwt_tamper" in t.ACTIONS

    @pytest.mark.asyncio
    async def test_unknown_action(self):
        t = JwtTool()
        result = await t.execute("nonexistent")
        assert "Unknown action" in result

    @pytest.mark.asyncio
    async def test_jwt_decode_no_token(self):
        """jwt_decode with empty token should still produce output (not crash)."""
        t = JwtTool()
        # Empty token will run python3 -c with an empty string — should error gracefully
        result = await t.execute("jwt_decode", token="", timeout=10)
        assert isinstance(result, str)


# ── SsrfDetectTool ───────────────────────────────────────────────────────────

class TestSsrfDetect:
    def test_instantiation(self):
        t = SsrfDetectTool()
        assert t.name == "ssrf_detect"

    def test_actions_defined(self):
        t = SsrfDetectTool()
        expected = {"ssrf_basic", "ssrf_cloud_meta", "ssrf_callback", "ssrf_generate_payloads"}
        assert set(t.ACTIONS.keys()) == expected

    @pytest.mark.asyncio
    async def test_unknown_action(self):
        t = SsrfDetectTool()
        result = await t.execute("bogus")
        assert "Unknown action" in result

    @pytest.mark.asyncio
    async def test_generate_payloads(self):
        t = SsrfDetectTool()
        result = await t.execute(
            "ssrf_generate_payloads",
            url="http://example.com/api?url=FUZZ",
            inject_param="FUZZ",
        )
        data = json.loads(result)
        assert "payloads" in data
        assert len(data["payloads"]) > 0
        assert "full_urls" in data
        assert any("127.0.0.1" in u for u in data["full_urls"])


# ── AuthTestTool ─────────────────────────────────────────────────────────────

class TestAuthTest:
    def test_instantiation(self):
        t = AuthTestTool()
        assert t.name == "auth_test"

    def test_actions_defined(self):
        t = AuthTestTool()
        expected = {
            "idor_check", "privesc_horizontal", "privesc_vertical",
            "session_fixation", "token_replay",
        }
        assert set(t.ACTIONS.keys()) == expected

    @pytest.mark.asyncio
    async def test_unknown_action(self):
        t = AuthTestTool()
        result = await t.execute("bogus")
        assert "Unknown action" in result


# ── RateLimitTool ────────────────────────────────────────────────────────────

class TestRateLimit:
    def test_instantiation(self):
        t = RateLimitTool()
        assert t.name == "rate_limit"

    def test_actions_defined(self):
        t = RateLimitTool()
        expected = {"rate_detect", "rate_bypass_headers", "rate_bypass_path"}
        assert set(t.ACTIONS.keys()) == expected

    @pytest.mark.asyncio
    async def test_unknown_action(self):
        t = RateLimitTool()
        result = await t.execute("bogus")
        assert "Unknown action" in result


# ── GraphqlTestTool ──────────────────────────────────────────────────────────

class TestGraphqlTest:
    def test_instantiation(self):
        t = GraphqlTestTool()
        assert t.name == "graphql_test"

    def test_actions_defined(self):
        t = GraphqlTestTool()
        expected = {"gql_introspect", "gql_depth_test", "gql_batch", "gql_field_suggest"}
        assert set(t.ACTIONS.keys()) == expected

    @pytest.mark.asyncio
    async def test_unknown_action(self):
        t = GraphqlTestTool()
        result = await t.execute("bogus")
        assert "Unknown action" in result


# ── TechniqueLibrary ─────────────────────────────────────────────────────────

class TestTechniqueLibrary:
    @pytest.fixture
    def lib(self, tmp_path):
        db = tmp_path / "techniques.db"
        library = TechniqueLibrary(db)
        yield library
        library.close()

    def test_add_and_search(self, lib):
        tech = Technique(
            tool="sqlmap", action="sqli_detect", target_type="web",
            description="Blind boolean SQLi found", payload="' AND 1=1 --",
            tags=["sqli", "blind"],
        )
        tid = lib.add(tech)
        assert tid > 0
        assert tech.id == tid

        results = lib.search(tool="sqlmap")
        assert len(results) == 1
        assert results[0].tool == "sqlmap"
        assert results[0].action == "sqli_detect"
        assert results[0].tags == ["sqli", "blind"]

    def test_search_by_tag(self, lib):
        lib.add(Technique(tool="nmap", action="nmap_scan", tags=["recon", "network"]))
        lib.add(Technique(tool="nikto", action="nikto_scan", tags=["web", "vuln"]))

        results = lib.search(tag="network")
        assert len(results) == 1
        assert results[0].tool == "nmap"

    def test_search_by_target_type(self, lib):
        lib.add(Technique(tool="ssrf", action="ssrf_basic", target_type="web"))
        lib.add(Technique(tool="nmap", action="nmap_scan", target_type="network"))

        results = lib.search(target_type="web")
        assert len(results) == 1
        assert results[0].tool == "ssrf"

    def test_search_success_only(self, lib):
        lib.add(Technique(tool="hydra", action="brute", success=True))
        lib.add(Technique(tool="hydra", action="brute", success=False))

        results = lib.search(tool="hydra", success_only=True)
        assert len(results) == 1
        assert results[0].success is True

        results = lib.search(tool="hydra", success_only=False)
        assert len(results) == 2

    def test_waf_bypasses(self, lib):
        lib.add(Technique(
            tool="xss", action="xss_scan", waf_bypass="Cloudflare",
            description="Bypass via double encoding", success=True,
        ))
        lib.add(Technique(tool="xss", action="xss_scan", waf_bypass=""))

        results = lib.get_waf_bypasses()
        assert len(results) == 1
        assert results[0].waf_bypass == "Cloudflare"

        results = lib.get_waf_bypasses("Cloudflare")
        assert len(results) == 1

        results = lib.get_waf_bypasses("ModSecurity")
        assert len(results) == 0

    def test_stats(self, lib):
        lib.add(Technique(tool="nmap", action="scan", target_type="network"))
        lib.add(Technique(tool="nmap", action="vuln", target_type="network"))
        lib.add(Technique(tool="sqlmap", action="sqli", target_type="web", success=False))

        stats = lib.stats()
        assert stats["total"] == 3
        assert stats["by_tool"]["nmap"] == 2
        assert stats["by_tool"]["sqlmap"] == 1
        assert stats["by_target_type"]["network"] == 2
        assert stats["by_target_type"]["web"] == 1

    def test_to_dict(self):
        t = Technique(
            id=1, tool="nmap", action="scan", target_type="network",
            description="SYN scan", payload="nmap -sS", waf_bypass="",
            success=True, tags=["recon"],
        )
        d = t.to_dict()
        assert d["id"] == 1
        assert d["tool"] == "nmap"
        assert d["tags"] == ["recon"]

    def test_get_by_tool(self, lib):
        lib.add(Technique(tool="jwt", action="decode", success=True))
        lib.add(Technique(tool="jwt", action="crack", success=False))

        results = lib.get_by_tool("jwt")
        assert len(results) == 2

        results = lib.get_by_tool("jwt", action="crack")
        assert len(results) == 1

    def test_limit(self, lib):
        for i in range(10):
            lib.add(Technique(tool="test", action=f"a{i}"))
        results = lib.search(tool="test", limit=3)
        assert len(results) == 3


# ── Parser Registration ──────────────────────────────────────────────────────

class TestPhase3Parsers:
    def test_parser_map_has_jwt_entries(self):
        from tools.parsers import PARSER_MAP
        assert ("jwt_tool", "jwt_decode") in PARSER_MAP
        assert ("jwt_tool", "jwt_crack") in PARSER_MAP

    def test_parser_map_has_ssrf_entries(self):
        from tools.parsers import PARSER_MAP
        assert ("ssrf_detect", "ssrf_basic") in PARSER_MAP
        assert ("ssrf_detect", "ssrf_cloud_meta") in PARSER_MAP
        assert ("ssrf_detect", "ssrf_callback") in PARSER_MAP

    def test_parser_map_has_auth_entries(self):
        from tools.parsers import PARSER_MAP
        assert ("auth_test", "idor_check") in PARSER_MAP
        assert ("auth_test", "session_fixation") in PARSER_MAP

    def test_parser_map_has_graphql_entries(self):
        from tools.parsers import PARSER_MAP
        assert ("graphql_test", "gql_introspect") in PARSER_MAP
        assert ("graphql_test", "gql_batch") in PARSER_MAP


# ── Phase Map Registration ───────────────────────────────────────────────────

class TestPhase3PhaseMap:
    def test_jwt_actions_in_phase_map(self):
        from enforcement.phases import TOOL_PHASE_MAP, KillChainPhase
        assert TOOL_PHASE_MAP["jwt_decode"] == KillChainPhase.VULN_ASSESSMENT
        assert TOOL_PHASE_MAP["jwt_crack"] == KillChainPhase.EXPLOITATION

    def test_ssrf_actions_in_phase_map(self):
        from enforcement.phases import TOOL_PHASE_MAP, KillChainPhase
        assert TOOL_PHASE_MAP["ssrf_basic"] == KillChainPhase.VULN_ASSESSMENT
        assert TOOL_PHASE_MAP["ssrf_callback"] == KillChainPhase.VULN_ASSESSMENT

    def test_auth_actions_in_phase_map(self):
        from enforcement.phases import TOOL_PHASE_MAP, KillChainPhase
        assert TOOL_PHASE_MAP["idor_check"] == KillChainPhase.VULN_ASSESSMENT
        assert TOOL_PHASE_MAP["privesc_vertical"] == KillChainPhase.VULN_ASSESSMENT

    def test_rate_limit_actions_in_phase_map(self):
        from enforcement.phases import TOOL_PHASE_MAP, KillChainPhase
        assert TOOL_PHASE_MAP["rate_detect"] == KillChainPhase.VULN_ASSESSMENT

    def test_graphql_actions_in_phase_map(self):
        from enforcement.phases import TOOL_PHASE_MAP, KillChainPhase
        assert TOOL_PHASE_MAP["gql_introspect"] == KillChainPhase.ENUMERATION
        assert TOOL_PHASE_MAP["gql_depth_test"] == KillChainPhase.VULN_ASSESSMENT


# ── Scope Map Registration ───────────────────────────────────────────────────

class TestPhase3ScopeMap:
    def test_ssrf_scope_entries(self):
        from enforcement.scope import _TOOL_TARGET_ARG
        assert _TOOL_TARGET_ARG["ssrf_basic"] == "url"
        assert _TOOL_TARGET_ARG["ssrf_cloud_meta"] is None

    def test_auth_scope_entries(self):
        from enforcement.scope import _TOOL_TARGET_ARG
        assert _TOOL_TARGET_ARG["idor_check"] == "url"
        assert _TOOL_TARGET_ARG["session_fixation"] == "url"

    def test_graphql_scope_entries(self):
        from enforcement.scope import _TOOL_TARGET_ARG
        assert _TOOL_TARGET_ARG["gql_introspect"] == "url"

    def test_jwt_scope_entries(self):
        from enforcement.scope import _TOOL_TARGET_ARG
        assert _TOOL_TARGET_ARG["jwt_decode"] is None


# ── Parser Functional Tests ──────────────────────────────────────────────────

class TestPhase3ParserFunctions:
    def test_jwt_parser_json(self):
        from tools.parsers.jwt_tool import parse_jwt_decode
        raw = json.dumps({
            "header": {"alg": "HS256"},
            "payload": {"sub": "1234", "admin": True},
            "analysis": ["weak secret"],
        })
        entities = parse_jwt_decode(raw, None)
        assert len(entities) == 1
        assert entities[0]["type"] == "jwt_info"
        assert entities[0]["algorithm"] == "HS256"
        assert "sub" in entities[0]["claims"]

    def test_jwt_parser_found(self):
        from tools.parsers.jwt_tool import parse_jwt_decode
        raw = "FOUND: secret123\nFOUND: password"
        entities = parse_jwt_decode(raw, None)
        assert len(entities) == 2
        assert entities[0]["type"] == "jwt_secret"
        assert entities[0]["secret"] == "secret123"

    def test_ssrf_parser_vulnerable(self):
        from tools.parsers.ssrf_detect import parse_ssrf
        raw = json.dumps({"vulnerable": True, "callback_url": "http://x", "hits": [{}]})
        entities = parse_ssrf(raw, None)
        assert len(entities) == 1
        assert entities[0]["type"] == "ssrf_finding"

    def test_ssrf_parser_list(self):
        from tools.parsers.ssrf_detect import parse_ssrf
        raw = json.dumps([
            {"payload": "http://127.0.0.1", "status": 200},
            {"payload": "http://[::1]", "status": 403},
        ])
        entities = parse_ssrf(raw, None)
        assert len(entities) == 1
        assert entities[0]["payload"] == "http://127.0.0.1"

    def test_auth_parser_idor(self):
        from tools.parsers.auth_test import parse_auth_test
        raw = json.dumps({"vulnerable": True, "url": "/api/user/1", "results": []})
        entities = parse_auth_test(raw, None)
        assert len(entities) == 1
        assert entities[0]["vuln_type"] == "IDOR/BOLA"

    def test_auth_parser_session_fixation(self):
        from tools.parsers.auth_test import parse_auth_test
        raw = json.dumps({"fixed_cookies": ["session_id"]})
        entities = parse_auth_test(raw, None)
        assert len(entities) == 1
        assert entities[0]["vuln_type"] == "session_fixation"

    def test_graphql_parser_introspection(self):
        from tools.parsers.graphql_test import parse_graphql
        raw = json.dumps({"introspection_enabled": True, "type_count": 42})
        entities = parse_graphql(raw, None)
        assert len(entities) == 1
        assert entities[0]["finding"] == "introspection_enabled"

    def test_graphql_parser_batch(self):
        from tools.parsers.graphql_test import parse_graphql
        raw = json.dumps({"batch_accepted": True, "batch_size": 10})
        entities = parse_graphql(raw, None)
        assert len(entities) == 1
        assert entities[0]["finding"] == "batch_queries_accepted"

    def test_graphql_parser_suggestions(self):
        from tools.parsers.graphql_test import parse_graphql
        raw = json.dumps({
            "field_suggestions": [
                {"typo": "pasword", "suggestions": ["Did you mean 'password'?"]}
            ]
        })
        entities = parse_graphql(raw, None)
        assert len(entities) == 1
        assert entities[0]["type"] == "graphql_field"

    def test_parser_handles_invalid_json(self):
        from tools.parsers.ssrf_detect import parse_ssrf
        from tools.parsers.auth_test import parse_auth_test
        from tools.parsers.graphql_test import parse_graphql
        assert parse_ssrf("not json", None) == []
        assert parse_auth_test("not json", None) == []
        assert parse_graphql("not json", None) == []
