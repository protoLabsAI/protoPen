"""Tests for traffic_analysis tool — pure-Python logic, no subprocess calls."""

from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.traffic_analysis import (
    TrafficAnalysisTool,
    _aggregate_syn_scan,
    _parse_http_stream,
    _parse_mitm_dump_text,
    _parse_tshark_conv,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def tool(tmp_path):
    t = TrafficAnalysisTool(workspace=str(tmp_path / "workspace"))
    return t


# ── Helper function tests ─────────────────────────────────────────────────────


class TestParseTsharkConv:
    def test_empty(self):
        assert _parse_tshark_conv("") == []

    def test_header_only(self):
        raw = "TCP Conversations\nFilter:<No Filter>\n                                               |<-      | |      ->| |<->     |\n"
        assert _parse_tshark_conv(raw) == []

    def test_single_flow(self):
        raw = "192.168.1.100:54321 <->   10.0.0.1:80        47 4130 12 9280"
        flows = _parse_tshark_conv(raw)
        assert len(flows) == 1
        assert flows[0]["src"] == "192.168.1.100"
        assert flows[0]["src_port"] == 54321
        assert flows[0]["dst"] == "10.0.0.1"
        assert flows[0]["dst_port"] == 80
        assert flows[0]["frames_ab"] == 47
        assert flows[0]["bytes_ab"] == 4130

    def test_multiple_flows(self):
        raw = (
            "10.0.0.1:443   <->   10.0.0.2:50000    10 1000 5 500\n"
            "10.0.0.1:80    <->   10.0.0.3:50001    3  300  2 200\n"
        )
        flows = _parse_tshark_conv(raw)
        assert len(flows) == 2


class TestAggregateSynScan:
    def test_no_scan(self):
        raw = "192.168.1.1,10.0.0.1,80\n192.168.1.1,10.0.0.1,443\n"
        result = _aggregate_syn_scan(raw)
        assert result["scanners"] == {}

    def test_detects_scan(self):
        # 20 unique ports from same src → same dst should trigger
        lines = "\n".join(f"192.168.1.100,10.0.0.1,{p}" for p in range(1, 25))
        result = _aggregate_syn_scan(lines)
        assert "192.168.1.100→10.0.0.1" in result["scanners"]
        assert len(result["scanners"]["192.168.1.100→10.0.0.1"]) == 24

    def test_empty_input(self):
        result = _aggregate_syn_scan("")
        assert result["scanners"] == {}
        assert result["total_syn_senders"] == 0


class TestParseHttpStream:
    def test_non_http(self):
        assert _parse_http_stream("file", "SSH-2.0-OpenSSH_8.2p1") is None

    def test_get_request(self):
        content = "GET /login HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
        session = _parse_http_stream("192.168.1.1.1234-10.0.0.1.80", content)
        assert session is not None
        assert session["method"] == "GET"
        assert session["uri"] == "/login"
        assert session["host"] == "example.com"
        assert session["authorization"] == "Basic dXNlcjpwYXNz"

    def test_post_request(self):
        content = (
            'POST /api/auth HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{"user":"admin"}'
        )
        session = _parse_http_stream("file", content)
        assert session is not None
        assert session["method"] == "POST"
        assert session["content_type"] == "application/json"
        assert "admin" in session["body_preview"]

    def test_empty_content(self):
        assert _parse_http_stream("file", "") is None


class TestParseMitmDumpText:
    def test_extracts_urls(self):
        # Create a fake dump with embedded URLs
        content = b"garbage\x00https://example.com/path?q=1\x00morebinary\x00https://api.test.io/endpoint\x00end"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dump") as f:
            f.write(content)
            path = Path(f.name)
        try:
            flows = _parse_mitm_dump_text(path)
            urls = {fl["url"] for fl in flows}
            assert "https://example.com/path?q=1" in urls
            assert "https://api.test.io/endpoint" in urls
        finally:
            path.unlink()

    def test_no_urls(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dump") as f:
            f.write(b"\x00\x01\x02binary garbage\x03")
            path = Path(f.name)
        try:
            flows = _parse_mitm_dump_text(path)
            assert flows == []
        finally:
            path.unlink()


# ── TrafficAnalysisTool unit tests ────────────────────────────────────────────


class TestToolProperties:
    def test_name(self, tool):
        assert tool.name == "traffic_analysis"

    def test_description(self, tool):
        desc = tool.description
        assert "pcap_capture" in desc
        assert "cleartext_harvest" in desc
        assert "tls_intercept" in desc

    def test_parameters_schema(self, tool):
        params = tool.parameters
        assert params["type"] == "object"
        actions = params["properties"]["action"]["enum"]
        assert set(actions) == {
            "pcap_capture",
            "pcap_parse",
            "session_reconstruct",
            "cleartext_harvest",
            "tls_intercept",
        }

    @pytest.mark.asyncio
    async def test_unknown_action(self):
        t = TrafficAnalysisTool(workspace="/tmp/test_ta")
        result = await t.execute(action="bogus_action")
        assert "Unknown action" in result
        assert "bogus_action" in result


class TestPcapParse:
    @pytest.mark.asyncio
    async def test_missing_file_param(self, tool):
        result = await tool.execute(action="pcap_parse")
        data = json.loads(result)
        assert "error" in data

    @pytest.mark.asyncio
    async def test_nonexistent_file(self, tool):
        result = await tool.execute(action="pcap_parse", pcap_file="/nonexistent/file.pcap")
        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_valid_file_calls_tshark(self, tool, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap content")

        async def fake_run(*args, **kwargs):
            return ("", "", 0)

        with patch.object(tool, "_run", side_effect=fake_run):
            result = await tool.execute(action="pcap_parse", pcap_file=str(pcap), analysis_type="flows")
        data = json.loads(result)
        assert data["action"] == "pcap_parse"
        assert data["pcap_file"] == str(pcap)
        assert "flows" in data


class TestCleartextHarvest:
    @pytest.mark.asyncio
    async def test_missing_file_param(self, tool):
        result = await tool.execute(action="cleartext_harvest")
        data = json.loads(result)
        assert "error" in data

    @pytest.mark.asyncio
    async def test_no_credentials_found(self, tool, tmp_path):
        pcap = tmp_path / "empty.pcap"
        pcap.write_bytes(b"")

        async def fake_run(*args, **kwargs):
            return ("", "", 0)

        with patch.object(tool, "_run", side_effect=fake_run):
            result = await tool.execute(action="cleartext_harvest", pcap_file=str(pcap))
        data = json.loads(result)
        assert data["action"] == "cleartext_harvest"
        assert data["credential_count"] == 0
        assert data["findings"] == []

    @pytest.mark.asyncio
    async def test_http_basic_decoded(self, tool, tmp_path):
        pcap = tmp_path / "creds.pcap"
        pcap.write_bytes(b"")

        cred_b64 = base64.b64encode(b"admin:secretpass").decode()
        tshark_outputs = {
            "http.authorization": f"192.168.1.100|10.0.0.1|example.com|Basic {cred_b64}\n",
        }

        call_count = 0

        async def fake_run(*args, **kwargs):
            nonlocal call_count
            # Return Basic auth output on first call, empty for all others
            if call_count == 0:
                call_count += 1
                return (tshark_outputs["http.authorization"], "", 0)
            call_count += 1
            return ("", "", 0)

        with patch.object(tool, "_run", side_effect=fake_run):
            result = await tool.execute(action="cleartext_harvest", pcap_file=str(pcap))
        data = json.loads(result)
        assert data["credential_count"] >= 1
        cred = data["findings"][0]
        assert cred["protocol"] == "HTTP Basic Auth"
        assert "admin:secretpass" in cred["credentials"]

    @pytest.mark.asyncio
    async def test_ftp_credentials(self, tool, tmp_path):
        pcap = tmp_path / "ftp.pcap"
        pcap.write_bytes(b"")

        ftp_output = "192.168.1.50|10.0.0.5|USER|ftpuser\n192.168.1.50|10.0.0.5|PASS|ftppassword123\n"

        async def fake_run(*args, **kwargs):
            # Return FTP output on appropriate call
            cmd_args = list(args)
            if "ftp.request.command" in " ".join(str(a) for a in cmd_args):
                return (ftp_output, "", 0)
            return ("", "", 0)

        with patch.object(tool, "_run", side_effect=fake_run):
            result = await tool.execute(action="cleartext_harvest", pcap_file=str(pcap))
        data = json.loads(result)
        ftp_findings = [f for f in data["findings"] if f["protocol"] == "FTP"]
        assert len(ftp_findings) == 1
        assert ftp_findings[0]["username"] == "ftpuser"
        assert ftp_findings[0]["password"] == "ftppassword123"

    @pytest.mark.asyncio
    async def test_snmp_deduplication(self, tool, tmp_path):
        pcap = tmp_path / "snmp.pcap"
        pcap.write_bytes(b"")

        # Duplicate community strings from same pair — should deduplicate
        snmp_output = (
            "10.0.0.1|10.0.0.2|public\n10.0.0.1|10.0.0.2|public\n10.0.0.1|10.0.0.2|public\n10.0.0.3|10.0.0.2|private\n"
        )

        async def fake_run(*args, **kwargs):
            if "snmp" in " ".join(str(a) for a in args):
                return (snmp_output, "", 0)
            return ("", "", 0)

        with patch.object(tool, "_run", side_effect=fake_run):
            result = await tool.execute(action="cleartext_harvest", pcap_file=str(pcap))
        data = json.loads(result)
        snmp_findings = [f for f in data["findings"] if f["protocol"] == "SNMP"]
        # Should deduplicate to 2 unique (src, dst, community) tuples
        assert len(snmp_findings) == 2


class TestSessionReconstruct:
    @pytest.mark.asyncio
    async def test_missing_file_param(self, tool):
        result = await tool.execute(action="session_reconstruct")
        data = json.loads(result)
        assert "error" in data

    @pytest.mark.asyncio
    async def test_runs_tcpflow(self, tool, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"pcap data")
        out_dir = tmp_path / "sessions"
        out_dir.mkdir()

        # Write a fake HTTP stream file
        stream_file = out_dir / "192.168.001.100.54321-010.000.000.001.00080"
        stream_file.write_text(
            "GET /secret HTTP/1.1\r\nHost: internal.corp\r\nAuthorization: Basic YWRtaW46cGFzcw==\r\n\r\n"
        )

        async def fake_run(*args, **kwargs):
            return ("", "", 0)

        with patch.object(tool, "_run", side_effect=fake_run):
            result = await tool.execute(
                action="session_reconstruct",
                pcap_file=str(pcap),
                output_dir=str(out_dir),
            )
        data = json.loads(result)
        assert data["action"] == "session_reconstruct"
        assert len(data["http_sessions"]) >= 1
        session = data["http_sessions"][0]
        assert session["method"] == "GET"
        assert session["uri"] == "/secret"
        assert session["authorization"] == "Basic YWRtaW46cGFzcw=="


class TestTlsIntercept:
    @pytest.mark.asyncio
    async def test_missing_target_ip(self, tool):
        result = await tool.execute(
            action="tls_intercept",
            interface="eth0",
            gateway_ip="192.168.1.1",
        )
        data = json.loads(result)
        assert "error" in data
        assert "target_ip" in data["error"]

    @pytest.mark.asyncio
    async def test_missing_gateway_ip(self, tool):
        result = await tool.execute(
            action="tls_intercept",
            interface="eth0",
            target_ip="192.168.1.50",
        )
        data = json.loads(result)
        assert "error" in data
        assert "gateway_ip" in data["error"]


# ── Parser tests ──────────────────────────────────────────────────────────────


class TestParsers:
    def _make_store(self):
        store = MagicMock()
        store.add_credential = MagicMock(return_value=1)
        store.upsert_host = MagicMock(return_value=1)
        return store

    def test_cleartext_harvest_parser_calls_store(self):
        from tools.parsers.traffic_analysis import parse_cleartext_harvest

        raw = json.dumps(
            {
                "findings": [
                    {
                        "protocol": "FTP",
                        "src_ip": "192.168.1.100",
                        "dst_ip": "10.0.0.5",
                        "username": "admin",
                        "password": "secret",
                    }
                ]
            }
        )
        store = self._make_store()
        entities = parse_cleartext_harvest(raw, store)
        assert len(entities) == 1
        assert entities[0]["type"] == "credential"
        assert entities[0]["protocol"] == "FTP"
        store.add_credential.assert_called_once()
        call_kwargs = store.add_credential.call_args[1]
        assert "FTP" in call_kwargs["source"]

    def test_pcap_parse_parser_upserts_hosts(self):
        from tools.parsers.traffic_analysis import parse_pcap_parse

        raw = json.dumps(
            {
                "flows": {
                    "tcp": [
                        {
                            "src": "10.0.0.1",
                            "dst": "10.0.0.2",
                            "src_port": 443,
                            "dst_port": 50000,
                            "frames_ab": 10,
                            "bytes_ab": 1000,
                            "frames_ba": 5,
                            "bytes_ba": 500,
                        }
                    ],
                    "udp": [],
                }
            }
        )
        store = self._make_store()
        entities = parse_pcap_parse(raw, store)
        assert len(entities) == 2  # src and dst
        ips = {e["ip"] for e in entities}
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips
        assert store.upsert_host.call_count == 2
        # Verify no unsupported kwargs
        for call in store.upsert_host.call_args_list:
            assert "source" not in call[1]

    def test_session_reconstruct_parser_records_auth_headers(self):
        from tools.parsers.traffic_analysis import parse_session_reconstruct

        raw = json.dumps(
            {
                "http_sessions": [
                    {
                        "filename": "test",
                        "method": "GET",
                        "uri": "/admin",
                        "host": "internal.corp",
                        "authorization": "Basic YWRtaW46cGFzcw==",
                        "content_type": "",
                        "body_preview": "",
                    },
                    {
                        "filename": "test2",
                        "method": "GET",
                        "uri": "/public",
                        "host": "public.corp",
                        "authorization": "",
                        "content_type": "",
                        "body_preview": "",
                    },
                ]
            }
        )
        store = self._make_store()
        entities = parse_session_reconstruct(raw, store)
        # Only the session with authorization header should be ingested
        assert len(entities) == 1
        assert entities[0]["host"] == "internal.corp"
        store.add_credential.assert_called_once()

    def test_parser_invalid_json(self):
        from tools.parsers.traffic_analysis import parse_cleartext_harvest

        store = self._make_store()
        result = parse_cleartext_harvest("not json {{", store)
        assert result == []
        store.add_credential.assert_not_called()

    def test_parser_empty_string(self):
        from tools.parsers.traffic_analysis import parse_pcap_parse

        store = self._make_store()
        result = parse_pcap_parse("", store)
        assert result == []
