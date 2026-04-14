"""LangGraph tool adapters for protoPen.

Wraps tool classes as LangChain @tool functions.
All business logic stays in the original classes — these are thin adapters.

Tools are grouped into three domains:
  - Security Intel: cve_search, security_feeds, github_trending, browser, security_memory, etc.
  - Pentest:        portapack, flipper, marauder, blackarch, engagement, device_manager, ...
  - Blue Team:      cis_audit, net_monitor, hardening_check, ir_toolkit, purple_team
"""

from typing import Optional

from langchain_core.tools import tool

import json
import os

from tools.cve_search import CVESearchTool
from tools.security_feeds import SecurityFeedsTool
from tools.github_trending import GitHubTrendingTool
from tools.security_memory import SecurityMemoryTool
from tools.browser import BrowserTool
from tools.lab_monitor import LabMonitorTool

# Pentest tool imports
from tools.device_manager import DeviceManager
from tools.portapack import PortaPackTool
from tools.flipper import FlipperTool
from tools.marauder import MarauderTool
from tools.blackarch import BlackArchTool
from tools.engagement import EngagementManager
from tools.target_intel import TargetIntelTool
from knowledge.target_store import TargetStore
from tools.dns_enum import DnsEnumTool
from tools.subdomain_discovery import SubdomainDiscoveryTool
from tools.osint_recon import OsintReconTool
from tools.web_enum import WebEnumTool
from tools.service_enum import ServiceEnumTool
from tools.ssl_audit import SslAuditTool
from tools.api_enum import ApiEnumTool
from tools.vuln_scan import VulnScanTool
from tools.sql_test import SqlTestTool
from tools.web_vuln import WebVulnTool
from tools.cve_match import CveMatchTool
from tools.msf_exploit import MsfExploitTool
from tools.credential_attack import CredentialAttackTool
from tools.hashcat_rules import HashcatRulesTool
from knowledge.chain_planner import suggest_next_steps, format_suggestions
from knowledge.target_profile import TargetProfile
from playbooks.tool import execute_playbook_action
from tools.priv_esc import PrivEscTool
from tools.lateral_move import LateralMoveTool
from tools.data_exfil import DataExfilTool
from tools.persistence import PersistenceTool
from tools.cleanup import CleanupTool
from tools.jwt_tool import JwtTool
from tools.ssrf_detect import SsrfDetectTool
from tools.auth_test import AuthTestTool
from tools.rate_limit import RateLimitTool
from tools.graphql_test import GraphqlTestTool
from knowledge.technique_library import TechniqueLibrary

# Phase 4 — Blue Team / Defensive
from tools.cis_audit import CisAuditTool
from tools.net_monitor import NetMonitorTool
from tools.hardening_check import HardeningCheckTool
from tools.ir_toolkit import IrToolkitTool
from tools.purple_team import PurpleTeamTool

# Container/K8s audit
from tools.container_audit import ContainerAuditTool

# WebSocket testing
from tools.websocket_test import WebSocketTestTool


# Rabbit Hole bridge — only loaded when RABBIT_HOLE_URL is set
_rabbit_hole_bridge = None
if os.environ.get("RABBIT_HOLE_URL"):
    from tools.rabbit_hole_bridge import RabbitHoleBridgeTool
    _rabbit_hole_bridge = RabbitHoleBridgeTool()

# Instantiate underlying tool classes (stateless singletons)
_cve_search = CVESearchTool()
_security_feeds = SecurityFeedsTool()
_github_trending = GitHubTrendingTool()
_browser = BrowserTool()
_lab_monitor = LabMonitorTool()

# ─── Pentest singletons (lazy — created on first get_pentest_tools() call) ───
_device_manager: DeviceManager | None = None
_portapack: PortaPackTool | None = None
_flipper: FlipperTool | None = None
_marauder: MarauderTool | None = None
_blackarch: BlackArchTool | None = None
_engagement: EngagementManager | None = None
_target_store: TargetStore | None = None
_target_intel: TargetIntelTool | None = None
_dns_enum: DnsEnumTool | None = None
_subdomain_discovery: SubdomainDiscoveryTool | None = None
_osint_recon: OsintReconTool | None = None
_web_enum: WebEnumTool | None = None
_service_enum: ServiceEnumTool | None = None
_ssl_audit: SslAuditTool | None = None
_api_enum: ApiEnumTool | None = None
_vuln_scan: VulnScanTool | None = None
_sql_test: SqlTestTool | None = None
_web_vuln: WebVulnTool | None = None
_cve_match: CveMatchTool | None = None
_msf_exploit: MsfExploitTool | None = None
_credential_attack: CredentialAttackTool | None = None
_hashcat_rules: HashcatRulesTool | None = None
_priv_esc: PrivEscTool | None = None
_lateral_move: LateralMoveTool | None = None
_data_exfil: DataExfilTool | None = None
_persistence: PersistenceTool | None = None
_cleanup: CleanupTool | None = None
_jwt_tool: JwtTool | None = None
_ssrf_detect: SsrfDetectTool | None = None
_auth_test: AuthTestTool | None = None
_rate_limit: RateLimitTool | None = None
_graphql_test: GraphqlTestTool | None = None
_technique_library: TechniqueLibrary | None = None

# Phase 4 — Blue Team / Defensive singletons
_cis_audit: CisAuditTool | None = None
_net_monitor: NetMonitorTool | None = None
_hardening_check: HardeningCheckTool | None = None
_ir_toolkit: IrToolkitTool | None = None
_purple_team: PurpleTeamTool | None = None

# Container/K8s audit singleton
_container_audit: ContainerAuditTool | None = None

# WebSocket testing singleton
_websocket_test: WebSocketTestTool | None = None


# Discord tools — only loaded when DISCORD_BOT_TOKEN is set
_discord_feed_tool = None
if os.environ.get("DISCORD_BOT_TOKEN"):
    from tools.discord_feed import DiscordFeedTool
    _discord_feed_tool = DiscordFeedTool()

    @tool
    async def discord_feed(
        action: str,
        channel_id: str = "",
        guild_id: str = "",
        limit: int = 50,
        after: str = "",
        content: str = "",
        title: str = "",
    ) -> str:
        """Read Discord channels and publish research digests.

        READING (requires channel_id):
        - scan: Read recent messages and extract classified URLs
        - history: Get raw message history
        - channels: List channels in a server (guild_id required)
        - digest: Scan a channel and produce a structured link digest

        PUBLISHING (NO channel_id needed — uses pre-configured webhook):
        - publish: Post content to #protolabs-research via webhook.
          Just provide 'content' and optionally 'title'. The webhook is auto-configured.
        """
        return await _discord_feed_tool.execute(
            action=action, channel_id=channel_id, guild_id=guild_id,
            limit=limit, after=after, content=content, title=title,
        )


@tool
async def cve_search(
    action: str,
    query: str = "",
    cve_id: str = "",
    severity: str = "",
    product: str = "",
    days: int = 7,
    limit: int = 10,
) -> str:
    """Search the NVD CVE database for vulnerabilities.

    - search: Search CVEs by keyword, product, or CVSS score
    - get: Get detailed info for a specific CVE ID
    - recent: Get recently published/modified CVEs
    """
    return await _cve_search.execute(
        action=action, query=query, cve_id=cve_id,
        severity=severity, product=product, days=days, limit=limit,
    )


@tool
async def security_feeds(
    action: str,
    source: str = "",
    query: str = "",
    limit: int = 20,
) -> str:
    """Aggregate security advisory feeds from well-known sources.

    - scan: Fetch and parse recent entries from security RSS/Atom feeds
    - sources: List available feed sources
    - search: Search feed entries by keyword
    """
    return await _security_feeds.execute(
        action=action, source=source, query=query, limit=limit,
    )


@tool
async def github_trending(
    action: str,
    query: str = "",
    topic: str = "",
    language: str = "",
    min_stars: int = 100,
    created_after: str = "",
    repos: str = "",
    limit: int = 10,
    sort: str = "stars",
) -> str:
    """Search GitHub for trending and notable AI/ML repositories.

    - search: Search repos by query with star/activity filters
    - recent_repos: Find recently created repos with high engagement
    - releases: Check latest releases for tracked repos
    """
    return await _github_trending.execute(
        action=action, query=query, topic=topic, language=language,
        min_stars=min_stars, created_after=created_after, repos=repos,
        limit=limit, sort=sort,
    )


@tool
async def browser(
    action: str,
    url: str = "",
    selector: str = "",
    text: str = "",
    query: str = "",
) -> str:
    """Automate a web browser. Actions: open, snapshot, screenshot, click, fill, find, type, wait.

    Returns accessibility tree snapshots by default (token-efficient).
    Use 'open' first, then 'snapshot' to read page content.
    """
    return await _browser.execute(
        action=action, url=url, selector=selector, text=text, query=query,
    )


def create_security_memory_tool(store=None):
    """Factory: creates security_memory tool with injected KnowledgeStore."""
    from knowledge.store import KnowledgeStore
    _tool = SecurityMemoryTool(store or KnowledgeStore())

    @tool
    async def security_memory(
        action: str,
        query: str = "",
        cve_id: str = "",
        title: str = "",
        description: str = "",
        severity: str = "",
        cvss_score: float = 0.0,
        cvss_vector: str = "",
        affected_products: str = "",
        exploit_available: bool = False,
        exploit_maturity: str = "",
        tags: str = "",
        source: str = "",
        source_url: str = "",
        platform: str = "",
        exploit_type: str = "",
        verified: bool = False,
        content: str = "",
        source_type: str = "",
        topic: str = "",
        intel_type: str = "indicator",
        target_relevance: str = "",
        url: str = "",
        cve_ids: str = "",
        published_at: str = "",
        notes: str = "",
        name: str = "",
        keywords: str = "",
        priority: int = 2,
        filter_table: str = "",
        k: int = 10,
        search_mode: str = "hybrid",
    ) -> str:
        """Persistent security knowledge store with hybrid search.

        - store_cve: Save a CVE with metadata and analysis
        - store_exploit: Save an exploit or PoC
        - store_advisory: Save a vendor/CERT advisory
        - store_threat_intel: Save a threat intelligence finding
        - store_digest: Save a security intelligence digest
        - search: Hybrid search (vector + keyword) across all stored knowledge
        - get_topics: List tracked security topics
        - add_topic: Add a new security topic to track
        - stats: Show knowledge base statistics
        """
        return await _tool.execute(
            action=action, query=query, cve_id=cve_id, title=title,
            description=description, severity=severity, cvss_score=cvss_score,
            cvss_vector=cvss_vector, affected_products=affected_products,
            exploit_available=exploit_available, exploit_maturity=exploit_maturity,
            tags=tags, source=source, source_url=source_url, platform=platform,
            exploit_type=exploit_type, verified=verified, content=content,
            source_type=source_type, topic=topic, intel_type=intel_type,
            target_relevance=target_relevance, url=url, cve_ids=cve_ids,
            published_at=published_at, notes=notes, name=name,
            keywords=keywords, priority=priority, filter_table=filter_table,
            k=k, search_mode=search_mode,
        )

    return security_memory


def create_lab_bench_tool():
    """Factory: creates lab_bench tool (called at runtime when /lab on)."""
    from tools.lab_bench import LabBenchTool
    _tool = LabBenchTool()

    @tool
    async def lab_bench(
        action: str,
        experiment: str = "",
        template: str = "dpo_qwen_0.8b",
        key: str = "",
        value: str = "",
        description: str = "",
        gpu: str = "1",
        time_budget: int = 300,
        tail: int = 50,
    ) -> str:
        """Run autonomous training experiments on tiny Qwen models.

        Uses LLaMA-Factory with LoRA DPO training on local GPU.
        Workflow: init -> edit config -> run -> keep/discard -> repeat.
        """
        return await _tool.execute(
            action=action, experiment=experiment, template=template,
            key=key, value=value, description=description,
            gpu=gpu, time_budget=time_budget, tail=tail,
        )

    return lab_bench


@tool
async def lab_monitor(
    action: str,
    path: str = "",
    sha: str = "",
    days: int = 7,
    since: str = "",
    limit: int = 20,
) -> str:
    """Monitor protoLabsAI/lab for new experiments, docs, and changes.

    - recent_commits: Get commits since last check (or last N days)
    - read_file: Read a file from the repo (README, experiment index, etc.)
    - experiments: List active experiments from the lab index
    - diff: Show what changed in a specific commit
    - watch_paths: Show which paths are monitored
    - changes_since: Get all changes to watched paths since a date
    """
    return await _lab_monitor.execute(
        action=action, path=path, sha=sha,
        days=days, since=since, limit=limit,
    )


if _rabbit_hole_bridge is not None:
    @tool
    async def rabbit_hole_bridge(
        action: str,
        query: str = "",
        arxiv_id: str = "",
        model_id: str = "",
        text: str = "",
        focus_entity: str = "",
        paper_ids: Optional[list[str]] = None,
        model_ids: Optional[list[str]] = None,
        limit: int = 10,
    ) -> str:
        """Ship research data to rabbit-hole.io's knowledge graph.

        - search_graph: Check what's already in the graph (query required)
        - ingest_paper: Send a stored paper to the graph (arxiv_id required)
        - ingest_model: Send a stored model release to the graph (model_id required)
        - ingest_text: Extract entities from free text and ingest (text required)
        - ingest_batch: Send multiple papers/models at once (paper_ids and/or model_ids)
        """
        return await _rabbit_hole_bridge.execute(
            action=action, query=query, arxiv_id=arxiv_id, model_id=model_id,
            text=text, focus_entity=focus_entity, paper_ids=paper_ids,
            model_ids=model_ids, limit=limit,
        )


def get_security_tools(knowledge_store=None):
    """Get security-domain tools as LangChain tool objects."""
    tools = [
        cve_search,
        security_feeds,
        github_trending,
        browser,
        lab_monitor,
        create_security_memory_tool(knowledge_store),
    ]
    if _discord_feed_tool is not None:
        tools.insert(0, discord_feed)
    if _rabbit_hole_bridge is not None:
        tools.append(rabbit_hole_bridge)
    return tools


# Backward-compat aliases
get_research_tools = get_security_tools
get_all_tools = get_security_tools


# ─────────────────────────────────────────────────────────────────────────────
# Pentest tool adapters
# ─────────────────────────────────────────────────────────────────────────────

def _init_pentest_singletons():
    """Lazy-init pentest singletons from engagement-config.json."""
    global _device_manager, _portapack, _flipper, _marauder, _blackarch, _engagement
    global _target_store, _target_intel

    if _device_manager is not None:
        return  # already initialised

    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "engagement-config.json")
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)
    else:
        config = {"devices": {}, "engagement": {}}

    _device_manager = DeviceManager(config.get("devices", {}))
    _target_store = TargetStore()
    _engagement = EngagementManager(config)
    _engagement.target_store = _target_store
    _target_intel = TargetIntelTool(_target_store)
    _blackarch = BlackArchTool(
        wifi_interface=config.get("devices", {}).get("wifi_adapter", {}).get("interface", "wlan1"),
        monitor_interface=config.get("devices", {}).get("wifi_adapter", {}).get("monitor_interface", "wlan1mon"),
    )
    _blackarch._target_store = _target_store

    global _dns_enum, _subdomain_discovery, _osint_recon
    global _web_enum, _service_enum, _ssl_audit, _api_enum
    _dns_enum = DnsEnumTool()
    _dns_enum._target_store = _target_store
    _subdomain_discovery = SubdomainDiscoveryTool()
    _subdomain_discovery._target_store = _target_store
    _osint_recon = OsintReconTool()
    _osint_recon._target_store = _target_store
    _web_enum = WebEnumTool()
    _web_enum._target_store = _target_store
    _service_enum = ServiceEnumTool()
    _service_enum._target_store = _target_store
    _ssl_audit = SslAuditTool()
    _ssl_audit._target_store = _target_store
    _api_enum = ApiEnumTool()
    _api_enum._target_store = _target_store

    global _vuln_scan, _sql_test, _web_vuln, _cve_match
    _vuln_scan = VulnScanTool()
    _vuln_scan._target_store = _target_store
    _sql_test = SqlTestTool()
    _sql_test._target_store = _target_store
    _web_vuln = WebVulnTool()
    _web_vuln._target_store = _target_store
    _cve_match = CveMatchTool()
    _cve_match._target_store = _target_store

    global _msf_exploit, _credential_attack, _hashcat_rules
    _msf_exploit = MsfExploitTool()
    _msf_exploit._target_store = _target_store
    _credential_attack = CredentialAttackTool()
    _credential_attack._target_store = _target_store
    _hashcat_rules = HashcatRulesTool()
    _hashcat_rules._target_store = _target_store

    global _priv_esc, _lateral_move, _data_exfil, _persistence, _cleanup
    _priv_esc = PrivEscTool()
    _priv_esc._target_store = _target_store
    _lateral_move = LateralMoveTool()
    _lateral_move._target_store = _target_store
    _data_exfil = DataExfilTool()
    _data_exfil._target_store = _target_store
    _persistence = PersistenceTool()
    _persistence._target_store = _target_store
    _cleanup = CleanupTool()
    _cleanup._target_store = _target_store

    global _jwt_tool, _ssrf_detect, _auth_test, _rate_limit, _graphql_test, _technique_library
    _jwt_tool = JwtTool()
    _jwt_tool._target_store = _target_store
    _ssrf_detect = SsrfDetectTool()
    _ssrf_detect._target_store = _target_store
    _auth_test = AuthTestTool()
    _auth_test._target_store = _target_store
    _rate_limit = RateLimitTool()
    _rate_limit._target_store = _target_store
    _graphql_test = GraphqlTestTool()
    _graphql_test._target_store = _target_store
    _technique_library = TechniqueLibrary()

    global _cis_audit, _net_monitor, _hardening_check, _ir_toolkit, _purple_team
    _cis_audit = CisAuditTool()
    _net_monitor = NetMonitorTool()
    _hardening_check = HardeningCheckTool()
    _ir_toolkit = IrToolkitTool()
    _purple_team = PurpleTeamTool()

    global _container_audit
    _container_audit = ContainerAuditTool()

    global _websocket_test
    _websocket_test = WebSocketTestTool()


@tool
def device_manager(
    action: str,
    device: str = "",
) -> str:
    """Manage USB device connections (PortaPack, Flipper, Marauder, WiFi adapter).

    - list: List known devices and their config
    - connect: Connect to a device by name
    - disconnect: Disconnect a device
    - status: Get connection status for all devices
    - health: Run health check on a specific device
    """
    _init_pentest_singletons()

    if action == "list":
        return json.dumps(_device_manager.list_devices(), indent=2)
    elif action == "connect":
        conn = _device_manager.connect(device)
        return f"Connected to {device} on {conn.port}" if conn else f"Failed to connect to {device}"
    elif action == "disconnect":
        _device_manager.disconnect(device)
        return f"Disconnected {device}"
    elif action == "status":
        statuses = _device_manager.all_status()
        return "\n".join(f"{s.name}: {'✓' if s.connected else '✗'} {s.port or ''}" for s in statuses)
    elif action == "health":
        s = _device_manager.health_check(device)
        return f"{s.name}: connected={s.connected} port={s.port} error={s.error}"
    return f"Unknown action: {action}"


@tool
async def portapack(
    action: str,
    app: str = "",
    frequency: int = 0,
    x: int = 0,
    y: int = 0,
    button: int = 0,
    command: str = "",
    path: str = "",
    lat: float = 0,
    lon: float = 0,
    altitude: int = 0,
    speed: int = 0,
) -> str:
    """Control PortaPack H4M via Mayhem serial shell (RF 1MHz–6GHz).

    - list_apps: List available Mayhem apps
    - start_app: Launch an app by name
    - set_frequency: Tune to a frequency in Hz
    - radio_info: Get current radio state
    - read_screen: Get accessibility tree of current screen
    - tap: Tap screen at x,y coordinates
    - press_button: Press a hardware button (0-5)
    - screenshot: Capture screen framebuffer
    - system_info: Get heap/CPU stats
    - file_list: List files on SD card at path
    - inject_gps: Inject GPS coordinates (lat, lon, altitude, speed)
    - send_command: Send raw serial command
    """
    _init_pentest_singletons()
    global _portapack
    if _portapack is None:
        conn = _device_manager.connections.get("portapack")
        if conn is None:
            return "Error: PortaPack not connected. Use device_manager connect first."
        _portapack = PortaPackTool(conn)

    return await _portapack.execute(
        action=action, app=app, frequency=frequency, x=x, y=y,
        button=button, command=command, path=path,
        lat=lat, lon=lon, altitude=altitude, speed=speed,
    )


@tool
async def flipper(
    action: str,
    command: str = "",
    frequency: int = 433920000,
    modulation: str = "AM650",
    path: str = "",
    key_type: str = "",
    data: str = "",
    protocol: str = "RAW",
    raw_data: str = "",
) -> str:
    """Control Flipper Zero via serial CLI.

    RF: subghz_rx, subghz_tx, subghz_decode_raw, subghz_tx_from_file
    RFID: rfid_read, rfid_emulate
    IR: ir_rx, ir_tx_raw
    Storage: storage_list, storage_read, storage_stat, storage_mkdir
    System: device_info, power_info, send_command
    """
    _init_pentest_singletons()
    global _flipper
    if _flipper is None:
        conn = _device_manager.connections.get("flipper")
        if conn is None:
            return "Error: Flipper not connected. Use device_manager connect first."
        _flipper = FlipperTool(conn)

    return await _flipper.execute(
        action=action, command=command, frequency=frequency,
        modulation=modulation, path=path, key_type=key_type,
        data=data, protocol=protocol, raw_data=raw_data,
    )


@tool
async def marauder(
    action: str,
    scan_type: str = "ap",
    indices: str = "",
    channel: int = 0,
    list_type: str = "ap",
    sniff_type: str = "pmkid",
    use_deauth: bool = False,
    spam_type: str = "all",
    ssid: str = "",
    count: int = 20,
    html_path: str = "",
    command: str = "",
) -> str:
    """Control WiFi Marauder on Flipper Zero (ESP32 WiFi attacks).

    Scanning: scan, stop, list_results, select, select_all, set_channel, clear_list
    Attacks: deauth, beacon_spam, probe_flood, rickroll
    Sniffing: sniff (pmkid, deauth, beacon, raw)
    BLE: bt_spam_all, sour_apple, swift_pair, samsung_ble_spam
    Advanced: evil_portal, karma, ssid_add, ssid_generate
    System: info, send_command
    """
    _init_pentest_singletons()
    global _marauder
    if _marauder is None:
        conn = _device_manager.connections.get("marauder")
        if conn is None:
            return "Error: Marauder not connected. Use device_manager connect first."
        _marauder = MarauderTool(conn)

    return await _marauder.execute(
        action=action, scan_type=scan_type, indices=indices,
        channel=channel, list_type=list_type, sniff_type=sniff_type,
        use_deauth=use_deauth, spam_type=spam_type, ssid=ssid,
        count=count, html_path=html_path, command=command,
    )


@tool
async def blackarch(
    action: str,
    target: str = "",
    ports: str = "",
    scripts: str = "",
    interface: str = "",
    command: str = "",
    timeout: int = 120,
) -> str:
    """Run BlackArch security tools (nmap, aircrack, bettercap, tshark, etc).

    - nmap_scan: Network scan with optional port/script filters
    - airmon_start: Enable monitor mode on WiFi adapter
    - airmon_stop: Disable monitor mode
    - bettercap_recon: Network recon via bettercap
    - shell_exec: Run an allowed security tool command (destructive commands blocked)
    """
    _init_pentest_singletons()
    return await _blackarch.execute(
        action=action, target=target, ports=ports, scripts=scripts,
        interface=interface, command=command, timeout=timeout,
    )


@tool
async def engagement(
    action: str,
    name: str = "",
    scope: str = "",
    mode: str = "",
    tool_name: str = "",
    severity: str = "",
    category: str = "",
    title: str = "",
    description: str = "",
) -> str:
    """Manage pentest engagements — mode enforcement, logging, reporting.

    - start: Start a new engagement (name + scope required)
    - end: End current engagement and save findings
    - set_mode: Set mode (passive/active/redteam)
    - check_permission: Check if a tool action is allowed in current mode
    - log_finding: Log a finding (severity, category, title, description)
    - report: Generate engagement report
    - status: Show current engagement state
    """
    _init_pentest_singletons()
    return await _engagement.execute(
        action=action, name=name, scope=scope, mode=mode,
        tool_name=tool_name, severity=severity, category=category,
        title=title, description=description,
    )


@tool
async def target_intel(
    action: str,
    ip: str = "",
    mac: str = "",
    hostname: str = "",
    os_fingerprint: str = "",
    vendor: str = "",
    device_type: str = "",
    host_id: int = 0,
    port: int = 0,
    protocol: str = "",
    service: str = "",
    banner: str = "",
    bssid: str = "",
    ssid: str = "",
    channel: int = 0,
    rssi: int = 0,
    encryption: str = "",
    frequency_hz: int = 0,
    modulation: str = "",
    data_hex: str = "",
    source_device: str = "",
    decoded_text: str = "",
    name: str = "",
    tag_type: str = "",
    uid: str = "",
    label: str = "",
    username: str = "",
    password: str = "",
    hash_type: str = "",
    source: str = "",
    scan_tool: str = "",
    scan_action: str = "",
    scan_session_id: int = 0,
    engagement_name: str = "",
    ip_prefix: str = "",
    since: str = "",
) -> str:
    """Query and manage the target intelligence database.

    Tracks hosts, WiFi APs/stations, RF signals, BLE devices, RFID/NFC tags,
    open ports, and credentials across all sensor platforms.

    - upsert_host: Add or update a host (by IP and/or MAC)
    - query_hosts: Search hosts by IP prefix, device type, or time
    - get_host: Get full detail for a host by ID (including ports)
    - upsert_port: Add or update a port on a host
    - upsert_wifi_network: Add or update a WiFi AP (by BSSID)
    - upsert_wifi_station: Add or update a WiFi client (by MAC)
    - add_rf_signal: Record an RF signal capture
    - upsert_ble_device: Add or update a BLE device (by MAC)
    - upsert_rfid_nfc_tag: Add or update an RFID/NFC tag (by type+UID)
    - add_credential: Record a harvested credential
    - start_scan: Start a scan session (tool + action)
    - end_scan: End a scan session
    - stats: Get counts for all entity types
    - diff: Show new entities since a timestamp
    """
    _init_pentest_singletons()
    return await _target_intel.execute(
        action=action, ip=ip, mac=mac, hostname=hostname,
        os=os_fingerprint, vendor=vendor, device_type=device_type,
        host_id=host_id, port=port, protocol=protocol,
        service=service, banner=banner, bssid=bssid, ssid=ssid,
        channel=channel, rssi=rssi, encryption=encryption,
        frequency_hz=frequency_hz, modulation=modulation,
        data_hex=data_hex, source_device=source_device,
        decoded_text=decoded_text, name=name, tag_type=tag_type,
        uid=uid, label=label, username=username, password=password,
        hash_type=hash_type, source=source, tool=scan_tool,
        scan_action=scan_action, scan_session_id=scan_session_id,
        engagement=engagement_name, ip_prefix=ip_prefix, since=since,
    )


@tool
async def dns_enum(
    action: str,
    target: str = "",
    record_type: str = "A",
    nameserver: str = "",
    wordlist: str = "",
    timeout: int = 30,
) -> str:
    """DNS enumeration — dig, nslookup, zone transfers, reverse lookups, subdomain brute force.

    - dig_query: Query DNS records (A, AAAA, MX, NS, TXT, SOA, ANY)
    - nslookup: Standard nslookup query
    - zone_transfer: Attempt AXFR zone transfer
    - reverse_lookup: Reverse DNS lookup
    - dns_brute: Subdomain brute force via dnsrecon
    """
    _init_pentest_singletons()
    return await _dns_enum.execute(
        action=action, target=target, record_type=record_type,
        nameserver=nameserver, wordlist=wordlist, timeout=timeout,
    )


@tool
async def subdomain_discovery(
    action: str,
    target: str = "",
    timeout: int = 120,
) -> str:
    """Subdomain enumeration via subfinder and amass passive mode.

    - subfinder: Fast passive subdomain discovery
    - amass_passive: Comprehensive passive subdomain enumeration
    """
    _init_pentest_singletons()
    return await _subdomain_discovery.execute(
        action=action, target=target, timeout=timeout,
    )


@tool
async def osint_recon(
    action: str,
    target: str = "",
    source: str = "all",
    limit: int = 500,
    timeout: int = 120,
) -> str:
    """OSINT reconnaissance — theHarvester and whois lookups.

    - theharvester: Harvest emails, subdomains, IPs from public sources
    - whois_lookup: Domain registration lookup
    """
    _init_pentest_singletons()
    return await _osint_recon.execute(
        action=action, target=target, source=source,
        limit=limit, timeout=timeout,
    )


@tool
async def web_enum(
    action: str,
    url: str = "",
    wordlist: str = "",
    extensions: str = "",
    threads: int = 10,
    recursive: bool = False,
    depth: int = 2,
    timeout: int = 120,
) -> str:
    """Web content enumeration — directory brute force, vhost discovery, parameter fuzzing.

    - gobuster_dir: Directory enumeration with gobuster
    - gobuster_vhost: Virtual host discovery
    - ffuf_fuzz: Content discovery with ffuf (supports recursion)
    - ffuf_param: Parameter fuzzing with ffuf
    """
    _init_pentest_singletons()
    return await _web_enum.execute(
        action=action, url=url, wordlist=wordlist, extensions=extensions,
        threads=threads, recursive=recursive, depth=depth, timeout=timeout,
    )


@tool
async def service_enum(
    action: str,
    target: str = "",
    share: str = "",
    username: str = "",
    password: str = "",
    timeout: int = 120,
) -> str:
    """Service enumeration — enum4linux, SMB share listing, RPC queries.

    - enum4linux_full: Full Windows/Samba enumeration
    - smb_shares: List SMB shares
    - smb_list: List files in an SMB share
    - rpc_info: Get RPC server info
    - rpc_users: Enumerate domain users via RPC
    """
    _init_pentest_singletons()
    return await _service_enum.execute(
        action=action, target=target, share=share,
        username=username, password=password, timeout=timeout,
    )


@tool
async def ssl_audit(
    action: str,
    target: str = "",
    timeout: int = 180,
) -> str:
    """SSL/TLS audit via testssl.sh — protocols, ciphers, vulnerabilities, certificates.

    - ssl_full_audit: Complete SSL/TLS analysis
    - ssl_protocols: Check supported protocols
    - ssl_ciphers: Enumerate cipher suites
    - ssl_vulnerabilities: Check for known SSL vulns (BEAST, POODLE, etc.)
    - ssl_certificates: Certificate chain analysis
    """
    _init_pentest_singletons()
    return await _ssl_audit.execute(
        action=action, target=target, timeout=timeout,
    )


@tool
async def api_enum(
    action: str,
    url: str = "",
    wordlist: str = "",
    methods: str = "GET,POST,PUT,DELETE,PATCH",
    timeout: int = 60,
) -> str:
    """API enumeration — Swagger/OpenAPI discovery, endpoint brute force, method checking.

    - swagger_scan: Check common Swagger/OpenAPI paths
    - endpoint_brute: API endpoint brute force via ffuf
    - method_check: Test which HTTP methods are allowed
    """
    _init_pentest_singletons()
    return await _api_enum.execute(
        action=action, url=url, wordlist=wordlist,
        methods=methods, timeout=timeout,
    )


@tool
async def priv_esc(
    action: str,
    timeout: int = 300,
) -> str:
    """Privilege escalation enumeration — linpeas, sudo checks, SUID discovery.

    - linpeas: Run linpeas for Linux privesc enumeration
    - sudo_check: List sudo privileges for current user
    - suid_find: Find SUID binaries
    - kernel_exploits: Suggest kernel exploits
    """
    _init_pentest_singletons()
    return await _priv_esc.execute(action=action, timeout=timeout)


@tool
async def lateral_move(
    action: str,
    target: str = "",
    username: str = "",
    password: str = "",
    domain: str = ".",
    hash: str = "",
    socks_port: str = "1080",
    timeout: int = 60,
) -> str:
    """Lateral movement — psexec, wmiexec, evil-winrm, SSH pivoting.

    - psexec: PsExec via impacket
    - wmiexec: WMI execution via impacket
    - evil_winrm: Evil-WinRM shell
    - pth_winrm: Pass-the-hash via evil-winrm
    - ssh_pivot: SSH SOCKS proxy for pivoting
    """
    _init_pentest_singletons()
    return await _lateral_move.execute(
        action=action, target=target, username=username,
        password=password, domain=domain, hash=hash,
        socks_port=socks_port, timeout=timeout,
    )


@tool
async def data_exfil(
    action: str,
    target: str = "",
    username: str = "",
    password: str = "",
    share: str = "",
    remote_path: str = "",
    local_path: str = "/tmp/exfil",
    url: str = "",
    timeout: int = 120,
) -> str:
    """Data exfiltration — controlled file extraction for evidence collection.

    - scp_download: Download file via SCP
    - smb_download: Download file from SMB share
    - http_exfil: Download file via HTTP/HTTPS
    """
    _init_pentest_singletons()
    return await _data_exfil.execute(
        action=action, target=target, username=username,
        password=password, share=share, remote_path=remote_path,
        local_path=local_path, url=url, timeout=timeout,
    )


@tool
async def persistence(
    action: str,
    pubkey: str = "",
    schedule: str = "",
    command: str = "",
    timeout: int = 30,
) -> str:
    """Persistence — establish persistence for authorized engagement testing.

    - add_ssh_key: Add SSH public key for persistence
    - add_cron: Add cron job for persistence
    - check_persistence: Check existing persistence mechanisms
    """
    _init_pentest_singletons()
    return await _persistence.execute(
        action=action, pubkey=pubkey, schedule=schedule,
        command=command, timeout=timeout,
    )


@tool
async def cleanup(
    action: str,
    key_fingerprint: str = "",
    pattern: str = "",
    file_paths: str = "",
    timeout: int = 30,
) -> str:
    """Cleanup — remove engagement artifacts and persistence from targets.

    - remove_ssh_key: Remove a planted SSH key
    - remove_cron: Remove a planted cron job
    - remove_files: Remove specified files
    - cleanup_report: Generate cleanup status report
    """
    _init_pentest_singletons()
    return await _cleanup.execute(
        action=action, key_fingerprint=key_fingerprint,
        pattern=pattern, file_paths=file_paths, timeout=timeout,
    )


@tool
async def playbook(
    action: str,
    name: str = "",
    variables: str = "",
) -> str:
    """Playbook system — run predefined tool sequences.

    - list: List available playbooks
    - run: Run a playbook by name (pass variables as JSON)
    - status: Get active playbook status
    """
    _init_pentest_singletons()

    async def _dispatch(tool_name: str, action_name: str, params: dict) -> str:
        """Dispatch a tool call from the playbook runner."""
        from tools.lg_tools import get_pentest_tools
        for t in get_pentest_tools():
            if t.name == tool_name:
                return await t.ainvoke({"action": action_name, **params})
        return f"Error: Tool '{tool_name}' not found"

    return await execute_playbook_action(
        action=action, name=name, variables=variables,
        dispatch_fn=_dispatch,
    )


@tool
def chain_planner(
    target: str,
) -> str:
    """Recommend next tool actions based on accumulated target intelligence.

    Analyzes the target's profile in the knowledge store and suggests
    the most productive next steps based on discovered services, vulns, and data.
    """
    _init_pentest_singletons()

    if not _target_store:
        return "Error: Target store not initialized."

    # Build profile from target store
    profile = TargetProfile(ip=target)

    # Populate from stored data
    stored_ports = _target_store.get_ports(target)
    if stored_ports:
        for port_info in stored_ports:
            if isinstance(port_info, dict):
                profile.add_port(**port_info)
            else:
                profile.add_port(port=port_info)

    entities = _target_store.get_entities(target)
    for entity in entities:
        etype = entity.get("type", "")
        if etype == "subdomain":
            profile.subdomains.append(entity.get("subdomain", ""))
        elif etype == "web_path":
            profile.web_paths.append(entity)
        elif etype == "user":
            profile.users.append(entity.get("username", ""))
        elif etype == "share":
            profile.shares.append(entity.get("name", ""))
        elif etype == "credential":
            profile.credentials.append(entity)
        elif etype == "vulnerability":
            profile.vulnerabilities.append(entity)
        elif etype == "ssl_finding":
            profile.ssl_findings.append(entity)

    summary = profile.summary()
    suggestions = suggest_next_steps(profile)
    recommendation = format_suggestions(suggestions)

    return f"{summary}\n\n{recommendation}"


@tool
async def msf_exploit(
    action: str,
    target: str = "",
    query: str = "",
    module: str = "",
    port: str = "",
    payload: str = "",
    lhost: str = "",
    lport: str = "4444",
    format: str = "raw",
    timeout: int = 300,
) -> str:
    """Metasploit Framework — module search, exploit execution, payload generation.

    - msf_search: Search Metasploit modules
    - msf_info: Get info on a Metasploit module
    - msf_run: Run an exploit module against a target
    - msf_payload: Generate a payload with msfvenom
    """
    _init_pentest_singletons()
    return await _msf_exploit.execute(
        action=action, target=target, query=query, module=module,
        port=port, payload=payload, lhost=lhost, lport=lport,
        format=format, timeout=timeout,
    )


@tool
async def credential_attack(
    action: str,
    target: str = "",
    service: str = "ssh",
    username: str = "",
    password: str = "",
    wordlist: str = "",
    userlist: str = "",
    combolist: str = "",
    threads: int = 4,
    timeout: int = 600,
) -> str:
    """Credential attacks — hydra brute force, password spraying, combo lists.

    - hydra_brute: Brute force a single user with a password list
    - hydra_spray: Password spray a single password across user list
    - hydra_combo: Combo list attack (user:pass format)
    """
    _init_pentest_singletons()
    return await _credential_attack.execute(
        action=action, target=target, service=service,
        username=username, password=password, wordlist=wordlist,
        userlist=userlist, combolist=combolist, threads=threads,
        timeout=timeout,
    )


@tool
async def hashcat_rules(
    action: str,
    hash: str = "",
    hashfile: str = "",
    wordlist: str = "",
    rulefile: str = "/usr/share/hashcat/rules/best64.rule",
    mode: str = "0",
    format: str = "",
    timeout: int = 600,
) -> str:
    """Hash cracking — hashcat, john the ripper, hash identification.

    - hash_identify: Identify hash type
    - hashcat_dict: Dictionary attack with hashcat
    - hashcat_rules: Rule-based attack with hashcat
    - john_crack: Crack hashes with john the ripper
    - john_show: Show cracked passwords from john pot
    """
    _init_pentest_singletons()
    return await _hashcat_rules.execute(
        action=action, hash=hash, hashfile=hashfile,
        wordlist=wordlist, rulefile=rulefile, mode=mode,
        format=format, timeout=timeout,
    )


@tool
async def vuln_scan(
    action: str,
    target: str = "",
    ports: str = "",
    tags: str = "",
    timeout: int = 300,
) -> str:
    """Vulnerability scanning — nikto, nuclei templates, nmap NSE vuln scripts.

    - nikto_scan: Nikto web server vulnerability scan
    - nuclei_scan: Nuclei scan with default templates
    - nuclei_tagged: Nuclei scan with specific template tags
    - nse_vuln: Nmap NSE vuln category scripts
    """
    _init_pentest_singletons()
    return await _vuln_scan.execute(
        action=action, target=target, ports=ports,
        tags=tags, timeout=timeout,
    )


@tool
async def sql_test(
    action: str,
    url: str = "",
    database: str = "",
    timeout: int = 300,
) -> str:
    """SQL injection testing via sqlmap.

    - sqli_detect: SQL injection detection scan
    - sqli_forms: Scan form parameters for SQLi
    - sqli_dbs: Enumerate databases via confirmed SQLi
    - sqli_tables: Enumerate tables in a database
    """
    _init_pentest_singletons()
    return await _sql_test.execute(
        action=action, url=url, database=database, timeout=timeout,
    )


@tool
async def web_vuln(
    action: str,
    url: str = "",
    timeout: int = 180,
) -> str:
    """Web vulnerability testing — XSS (dalfox), CORS misconfiguration, open redirect.

    - xss_scan: XSS vulnerability scan with dalfox
    - cors_check: Check CORS misconfiguration
    - redirect_check: Check for open redirect
    """
    _init_pentest_singletons()
    return await _web_vuln.execute(
        action=action, url=url, timeout=timeout,
    )


@tool
async def cve_match(
    action: str,
    target: str = "",
    query: str = "",
    ports: str = "",
    timeout: int = 120,
) -> str:
    """CVE matching — searchsploit, nmap vulners NSE, nuclei CVE templates.

    - cve_search: Search exploitdb for known CVEs/exploits
    - cve_nmap: NSE vulners script against discovered services
    - cve_nuclei: Nuclei CVE templates against target
    """
    _init_pentest_singletons()
    return await _cve_match.execute(
        action=action, target=target, query=query,
        ports=ports, timeout=timeout,
    )


@tool
async def jwt_tool(
    action: str,
    token: str = "",
    secret: str = "",
    wordlist: str = "",
    new_claims: str = "{}",
    timeout: int = 60,
) -> str:
    """JWT analysis — decode, algorithm-none attack, crack weak secrets, tamper claims.

    - jwt_decode: Decode a JWT and analyze header/payload
    - jwt_alg_none: Test algorithm-none vulnerability
    - jwt_crack: Brute force JWT secret with wordlist
    - jwt_tamper: Modify JWT claims and re-sign
    """
    _init_pentest_singletons()
    return await _jwt_tool.execute(
        action=action, token=token, secret=secret,
        wordlist=wordlist, new_claims=new_claims, timeout=timeout,
    )


@tool
async def ssrf_detect(
    action: str,
    url: str = "",
    inject_param: str = "FUZZ",
    callback_host: str = "",
    callback_port: int = 8888,
    wait_seconds: int = 5,
    timeout: int = 60,
) -> str:
    """SSRF detection — payload injection, callback server, cloud metadata checks.

    - ssrf_basic: Test URL parameter for SSRF with common payloads
    - ssrf_cloud_meta: Check if cloud metadata endpoints are accessible
    - ssrf_callback: Blind SSRF detection via callback server
    - ssrf_generate_payloads: Generate SSRF bypass payloads
    """
    _init_pentest_singletons()
    return await _ssrf_detect.execute(
        action=action, url=url, inject_param=inject_param,
        callback_host=callback_host, callback_port=callback_port,
        wait_seconds=wait_seconds, timeout=timeout,
    )


@tool
async def auth_test(
    action: str,
    url: str = "",
    admin_url: str = "",
    login_url: str = "",
    headers: str = "{}",
    user_a_headers: str = "{}",
    user_b_headers: str = "{}",
    low_priv_headers: str = "{}",
    login_data: str = "{}",
    test_ids: str = "[1,2,3,100,999]",
    id_param: str = "FUZZ",
    delay: int = 5,
    timeout: int = 60,
) -> str:
    """Authentication & authorization testing — BOLA/IDOR, privilege escalation, session testing.

    - idor_check: Test for IDOR/BOLA by iterating object IDs
    - privesc_horizontal: Test horizontal privilege escalation
    - privesc_vertical: Test vertical privilege escalation
    - session_fixation: Test for session fixation
    - token_replay: Test token replay attacks
    """
    _init_pentest_singletons()
    return await _auth_test.execute(
        action=action, url=url, admin_url=admin_url,
        login_url=login_url, headers=headers,
        user_a_headers=user_a_headers, user_b_headers=user_b_headers,
        low_priv_headers=low_priv_headers, login_data=login_data,
        test_ids=test_ids, id_param=id_param, delay=delay, timeout=timeout,
    )


@tool
async def rate_limit(
    action: str,
    url: str = "",
    headers: str = "{}",
    count: int = 50,
    interval: float = 0.1,
    spoof_ip: str = "1.2.3.4",
    timeout: int = 120,
) -> str:
    """Rate limit testing — detect and test bypass techniques.

    - rate_detect: Detect rate limiting by sending sequential requests
    - rate_bypass_headers: Test rate limit bypass via IP spoofing headers
    - rate_bypass_path: Test rate limit bypass via URL path manipulation
    """
    _init_pentest_singletons()
    return await _rate_limit.execute(
        action=action, url=url, headers=headers,
        count=count, interval=interval, spoof_ip=spoof_ip, timeout=timeout,
    )


@tool
async def graphql_test(
    action: str,
    url: str = "",
    headers: str = "{}",
    query: str = "{ __typename }",
    field: str = "__typename",
    type_name: str = "Query",
    max_depth: int = 20,
    batch_size: int = 10,
    timeout: int = 60,
) -> str:
    """GraphQL security testing — introspection, depth/complexity fuzzing, batch query abuse.

    - gql_introspect: Test if introspection is enabled and extract schema
    - gql_depth_test: Test query depth limits
    - gql_batch: Test batch query support (potential DoS vector)
    - gql_field_suggest: Extract field names via suggestion mechanism
    """
    _init_pentest_singletons()
    return await _graphql_test.execute(
        action=action, url=url, headers=headers, query=query,
        field=field, type_name=type_name, max_depth=max_depth,
        batch_size=batch_size, timeout=timeout,
    )


@tool
def technique_library(
    action: str,
    tool_name: str = "",
    action_name: str = "",
    target_type: str = "",
    description: str = "",
    payload: str = "",
    waf_bypass: str = "",
    success: bool = True,
    tags: str = "",
    tag: str = "",
    waf_product: str = "",
    limit: int = 20,
) -> str:
    """Store and retrieve successful attack techniques for reuse.

    - add: Record a successful technique (tool_name, action_name, description, payload required)
    - search: Search techniques by tool, target type, or tag
    - waf_bypasses: Get WAF bypass techniques (optional waf_product filter)
    - stats: Get technique library statistics
    """
    _init_pentest_singletons()
    import json as _json
    from knowledge.technique_library import Technique

    if action == "add":
        tech = Technique(
            tool=tool_name, action=action_name, target_type=target_type,
            description=description, payload=payload, waf_bypass=waf_bypass,
            success=success,
            tags=[t.strip() for t in tags.split(",") if t.strip()] if tags else [],
        )
        tid = _technique_library.add(tech)
        return _json.dumps({"id": tid, "status": "stored"})
    elif action == "search":
        results = _technique_library.search(
            tool=tool_name, action=action_name, target_type=target_type,
            tag=tag, success_only=success, limit=limit,
        )
        return _json.dumps([t.to_dict() for t in results], indent=2)
    elif action == "waf_bypasses":
        results = _technique_library.get_waf_bypasses(waf_product)
        return _json.dumps([t.to_dict() for t in results], indent=2)
    elif action == "stats":
        return _json.dumps(_technique_library.stats(), indent=2)
    return f"Unknown action: {action}"


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 — Blue Team / Defensive tools
# ─────────────────────────────────────────────────────────────────────────────

@tool
async def cis_audit(
    action: str,
    target: str = "localhost",
    port: int = 443,
    expected_ports: str = "[22,80,443]",
    timeout: int = 60,
) -> str:
    """Defensive CIS benchmark scanning and configuration auditing.

    - ssh_audit: Audit SSH configuration against CIS benchmarks
    - tls_audit: Audit TLS/SSL (protocol version, cipher strength, cert expiry)
    - firewall_audit: Audit firewall rules and default policies
    - patch_check: Check for pending security patches and updates
    - port_baseline: Compare open ports against expected baseline
    """
    _init_pentest_singletons()
    return await _cis_audit.execute(
        action=action, target=target, port=port,
        expected_ports=expected_ports, timeout=timeout,
    )


@tool
async def net_monitor(
    action: str,
    target: str = "",
    network: str = "192.168.1.0/24",
    interface: str = "eth0",
    duration: int = 30,
    known_hosts: str = "[]",
    baseline_services: str = "[]",
    expected_ports: str = "[22,80,443]",
    allowed_protocols: str = '["eth","ip","tcp","udp","dns","http","tls"]',
    timeout: int = 120,
) -> str:
    """Network monitoring — traffic baselines, host anomaly detection, DNS monitoring.

    - traffic_baseline: Capture passive traffic baseline (hosts, protocols, ports)
    - host_discovery: Discover hosts and flag unknown ones against baseline
    - service_diff: Compare current services against baseline, flag changes
    - dns_monitor: Monitor DNS traffic for exfiltration, tunneling, suspicious queries
    - protocol_anomaly: Detect unexpected protocols on the network
    """
    _init_pentest_singletons()
    return await _net_monitor.execute(
        action=action, target=target, network=network,
        interface=interface, duration=duration,
        known_hosts=known_hosts, baseline_services=baseline_services,
        expected_ports=expected_ports, allowed_protocols=allowed_protocols,
        timeout=timeout,
    )


@tool
async def hardening_check(
    action: str,
    target: str = "localhost",
    timeout: int = 30,
) -> str:
    """Per-service hardening validation with specific remediation steps.

    - ssh_harden: Validate SSH hardening against security baseline
    - nginx_harden: Validate Nginx hardening (headers, TLS, info leaks)
    - apache_harden: Validate Apache hardening (info disclosure, directory listing)
    - docker_harden: Validate Docker daemon and container hardening
    - k8s_harden: Validate Kubernetes pod security (privileged, root, limits)
    """
    _init_pentest_singletons()
    return await _hardening_check.execute(
        action=action, target=target, timeout=timeout,
    )


@tool
async def ir_toolkit(
    action: str,
    log_path: str = "/var/log",
    pattern: str = "",
    keyword: str = "",
    iocs: str = "[]",
    attack_type: str = "",
    compromised_hosts: str = "[]",
    timeout: int = 60,
) -> str:
    """Incident response — log correlation, IOC matching, timeline reconstruction.

    - log_search: Search logs for a pattern across multiple log files
    - ioc_scan: Scan logs for known IOCs (IPs, domains, hashes, user agents)
    - auth_log_analyze: Analyze auth logs for brute force and compromise indicators
    - timeline_build: Build chronological timeline of events from multiple log sources
    - containment_recommend: Generate containment recommendations for an attack type
    """
    _init_pentest_singletons()
    return await _ir_toolkit.execute(
        action=action, log_path=log_path, pattern=pattern,
        keyword=keyword, iocs=iocs, attack_type=attack_type,
        compromised_hosts=compromised_hosts, timeout=timeout,
    )


@tool
async def purple_team(
    action: str,
    red_results: str = "[]",
    blue_results: str = "[]",
    exercise_name: str = "Purple Team Exercise",
    target_scope: str = "",
) -> str:
    """Purple team mode — correlate red-team attacks with blue-team detections.

    - coverage_matrix: Generate MITRE ATT&CK coverage matrix from red/blue results
    - detection_gap: Identify attacks that succeeded without corresponding alerts
    - exercise_report: Generate combined purple team exercise report with rating
    """
    _init_pentest_singletons()
    return await _purple_team.execute(
        action=action, red_results=red_results, blue_results=blue_results,
        exercise_name=exercise_name, target_scope=target_scope,
    )


@tool
async def container_audit(
    action: str,
    target: str = "localhost",
    image: str = "",
    path: str = ".",
    severity: str = "HIGH,CRITICAL",
    benchmark: str = "cis-1.8",
    exploit_name: str = "",
    timeout: int = 120,
) -> str:
    """Container & Kubernetes security auditing and escape detection.

    - kube_hunter: Scan K8s cluster for security weaknesses (remote)
    - kube_hunter_internal: In-cluster kube-hunter scan
    - kube_bench: CIS Kubernetes Benchmark checks (local node)
    - kube_bench_target: CIS benchmark for specific K8s distro (eks, gke, etc.)
    - deepce: Detect container escape vectors from inside a container
    - cdk_evaluate: Evaluate container for exploitation opportunities
    - cdk_exploit: Run a specific CDK exploit by name
    - trivy_image: Scan container image for CVEs
    - trivy_k8s: Scan K8s cluster resources for misconfigs and CVEs
    - trivy_fs: Scan filesystem/project for dependency vulnerabilities
    """
    _init_pentest_singletons()
    return await _container_audit.execute(
        action=action, target=target, image=image, path=path,
        severity=severity, benchmark=benchmark,
        exploit_name=exploit_name, timeout=timeout,
    )


@tool
async def websocket_test(
    action: str,
    url: str = "ws://localhost:8080",
    origin: str = "",
    auth_token: str = "",
    categories: str = "",
    timeout: int = 60,
) -> str:
    """WebSocket security testing — authentication bypass, CSWSH, injection.

    - auth_bypass: Test WebSocket endpoint for authentication bypass
    - cswsh: Test for Cross-Site WebSocket Hijacking via Origin validation
    - injection: Test WebSocket messages for injection vulns (sqli, xss, command_injection, path_traversal)
    """
    _init_pentest_singletons()
    return await _websocket_test.execute(
        action=action, url=url, origin=origin,
        auth_token=auth_token, categories=categories,
        timeout=timeout,
    )


def get_engagement_manager() -> EngagementManager:
    """Return the EngagementManager singleton (lazy-inits if needed)."""
    _init_pentest_singletons()
    return _engagement


def get_pentest_tools():
    """Get pentest-domain tools as LangChain tool objects."""
    return [
        device_manager,
        portapack,
        flipper,
        marauder,
        blackarch,
        engagement,
        target_intel,
        # Phase 2 — Recon
        dns_enum,
        subdomain_discovery,
        osint_recon,
        # Phase 2 — Enumeration
        web_enum,
        service_enum,
        ssl_audit,
        api_enum,
        # Phase 2 — Vuln Assessment
        vuln_scan,
        sql_test,
        web_vuln,
        cve_match,
        # Phase 2 — Exploitation
        msf_exploit,
        credential_attack,
        hashcat_rules,
        # Phase 2 — Post-Exploitation + Lateral Movement
        priv_esc,
        lateral_move,
        data_exfil,
        persistence,
        cleanup,
        # Phase 2 — Playbook system
        playbook,
        # Phase 2 — Intelligence
        chain_planner,
        # Phase 3 — Web App Testing
        jwt_tool,
        ssrf_detect,
        auth_test,
        rate_limit,
        graphql_test,
        # Phase 3 — Knowledge
        technique_library,
        # Phase 4 — Blue Team / Defensive
        cis_audit,
        net_monitor,
        hardening_check,
        ir_toolkit,
        purple_team,
        # Container/K8s audit
        container_audit,
        # WebSocket testing
        websocket_test,
    ]


def get_combined_tools(knowledge_store=None):
    """Get all tools (security + pentest) as LangChain tool objects."""
    return get_security_tools(knowledge_store) + get_pentest_tools()
