"""LangGraph tool adapters for protoPen.

Wraps tool classes as LangChain @tool functions.
All business logic stays in the original classes — these are thin adapters.

Tools are grouped into two domains:
  - Security Intel: cve_search, security_feeds, github_trending, browser, security_memory, etc.
  - Pentest:        portapack, flipper, marauder, blackarch, engagement, device_manager
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
    _dns_enum = DnsEnumTool()
    _dns_enum._target_store = _target_store
    _subdomain_discovery = SubdomainDiscoveryTool()
    _subdomain_discovery._target_store = _target_store
    _osint_recon = OsintReconTool()
    _osint_recon._target_store = _target_store


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
    ]


def get_combined_tools(knowledge_store=None):
    """Get all tools (security + pentest) as LangChain tool objects."""
    return get_security_tools(knowledge_store) + get_pentest_tools()
