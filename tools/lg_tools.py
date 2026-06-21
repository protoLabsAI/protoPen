"""LangGraph tool adapters for protoPen.

Wraps tool classes as LangChain @tool functions.
All business logic stays in the original classes — these are thin adapters.

Tools are grouped into three domains:
  - Security Intel: cve_search, security_feeds, github_trending, browser, security_memory, etc.
  - Pentest:        portapack, flipper, marauder, blackarch, engagement, device_manager, ...
  - Blue Team:      cis_audit, net_monitor, hardening_check, ir_toolkit, purple_team
"""

from typing import Annotated, Optional

from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState

from graph.state import WAIT_YIELD_MARKER as _WAIT_YIELD_MARKER, session_id_from_state

import asyncio
import json
import os
import re
import threading

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
from tools.maigret import MaigretTool
from tools.phoneinfoga import PhoneInfogaTool
from tools.holehe import HoleheTool
from tools.external_recon import ExternalReconTool
from tools.perimeter_audit import PerimeterAuditTool
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
from tools.lan_scan import LanScanTool
from tools.data_exfil import DataExfilTool
from tools.persistence import PersistenceTool
from tools.cleanup import CleanupTool
from tools.opsec import OpsecTool
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

# Tier 2 — CI/CD, IPv6, IoT, AD
from tools.cicd_audit import CICDAuditTool
from tools.ipv6_attack import IPv6AttackTool
from tools.iot_protocol import IoTProtocolTool
from tools.iot_audit import IoTAuditTool
from tools.ad_attack import ADAttackTool

# Tier 3 — LLM, Telecom, Evasion, Phishing, gRPC, Auth
from tools.llm_audit import LLMAuditTool
from tools.telecom_attack import TelecomAttackTool
from tools.evasion import EvasionTool
from tools.phishing import PhishingTool
from tools.grpc_audit import GRPCAuditTool
from tools.auth_audit import AuthAuditTool

# Tier 4 — Mobile, Supply Chain, Serverless, SPA, SDN, Recon
from tools.mobile_audit import MobileAuditTool
from tools.supply_chain import SupplyChainTool
from tools.serverless_audit import ServerlessAuditTool
from tools.spa_test import SPATestTool
from tools.sdn_attack import SDNAttackTool
from tools.recon_pipeline import ReconPipelineTool
from tools.orchestrator import EngagementOrchestratorTool
from tools.wifi_intel import WiFiIntelTool
from tools.traffic_analysis import TrafficAnalysisTool


# Instantiate underlying tool classes (stateless singletons)
_cve_search = CVESearchTool()
_security_feeds = SecurityFeedsTool()
_github_trending = GitHubTrendingTool()
_browser = BrowserTool()
_lab_monitor = LabMonitorTool()

# ─── Pentest singletons (lazy — created on first get_pentest_tools() call) ───
# Guards the lazy init so concurrent first-callers (the operator routes run via
# asyncio.to_thread) can't observe a half-built set of singletons.
_pentest_init_lock = threading.Lock()
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
_maigret: MaigretTool | None = None
_phoneinfoga: PhoneInfogaTool | None = None
_holehe: HoleheTool | None = None
_external_recon: ExternalReconTool | None = None
_perimeter_audit: PerimeterAuditTool | None = None
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
_lan_scan: LanScanTool | None = None
_data_exfil: DataExfilTool | None = None
_persistence: PersistenceTool | None = None
_cleanup: CleanupTool | None = None
_opsec: OpsecTool | None = None
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

# Tier 2 singletons
_cicd_audit: CICDAuditTool | None = None
_ipv6_attack: IPv6AttackTool | None = None
_iot_protocol: IoTProtocolTool | None = None
_iot_audit: IoTAuditTool | None = None
_ad_attack: ADAttackTool | None = None

# Tier 3 singletons
_llm_audit: LLMAuditTool | None = None
_telecom_attack: TelecomAttackTool | None = None
_evasion: EvasionTool | None = None
_phishing: PhishingTool | None = None
_grpc_audit: GRPCAuditTool | None = None
_auth_audit: AuthAuditTool | None = None

# Tier 4 singletons
_mobile_audit: MobileAuditTool | None = None
_supply_chain: SupplyChainTool | None = None
_serverless_audit: ServerlessAuditTool | None = None
_spa_test: SPATestTool | None = None
_sdn_attack: SDNAttackTool | None = None
_recon_pipeline: ReconPipelineTool | None = None

# Orchestrator singleton
_orchestrator_tool: EngagementOrchestratorTool | None = None

# WiFi Intel singleton
_wifi_intel: WiFiIntelTool | None = None

# Traffic analysis singleton
_traffic_analysis: TrafficAnalysisTool | None = None


# Discord tools — loaded when a bot token (reading: scan/history/channels/digest)
# OR a publish webhook is configured. Publishing posts via DISCORD_ALERT_WEBHOOK
# (or legacy DISCORD_WEBHOOK_URL) and needs no bot, so a webhook-only setup still
# lets the agent publish.
_discord_feed_tool = None
if (
    os.environ.get("DISCORD_BOT_TOKEN")
    or os.environ.get("DISCORD_ALERT_WEBHOOK")
    or os.environ.get("DISCORD_WEBHOOK_URL")
):
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
            action=action,
            channel_id=channel_id,
            guild_id=guild_id,
            limit=limit,
            after=after,
            content=content,
            title=title,
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
        action=action,
        query=query,
        cve_id=cve_id,
        severity=severity,
        product=product,
        days=days,
        limit=limit,
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
        action=action,
        source=source,
        query=query,
        limit=limit,
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
        action=action,
        query=query,
        topic=topic,
        language=language,
        min_stars=min_stars,
        created_after=created_after,
        repos=repos,
        limit=limit,
        sort=sort,
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
        action=action,
        url=url,
        selector=selector,
        text=text,
        query=query,
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
            action=action,
            query=query,
            cve_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_products=affected_products,
            exploit_available=exploit_available,
            exploit_maturity=exploit_maturity,
            tags=tags,
            source=source,
            source_url=source_url,
            platform=platform,
            exploit_type=exploit_type,
            verified=verified,
            content=content,
            source_type=source_type,
            topic=topic,
            intel_type=intel_type,
            target_relevance=target_relevance,
            url=url,
            cve_ids=cve_ids,
            published_at=published_at,
            notes=notes,
            name=name,
            keywords=keywords,
            priority=priority,
            filter_table=filter_table,
            k=k,
            search_mode=search_mode,
        )

    return security_memory


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
        action=action,
        path=path,
        sha=sha,
        days=days,
        since=since,
        limit=limit,
    )


# ── Scheduler tools (ported from protoAgent) ──────────────────────────────────
# Bound to the live LocalScheduler via set_scheduler() at server startup; the
# @tool bodies read the module global lazily so they work even though the graph
# is built before the scheduler is created.

_scheduler_backend = None  # SchedulerBackend (LocalScheduler) — set by server.py


def set_scheduler(scheduler) -> None:
    """Wire the live scheduler so the agent's schedule_* tools can reach it."""
    global _scheduler_backend
    _scheduler_backend = scheduler


@tool
async def schedule_task(prompt: str, when: str, job_id: str | None = None) -> str:
    """Schedule a future task. The agent receives ``prompt`` as a new turn when
    the schedule fires.

    Use for anything to do later: reminders, recurring sweeps ("every Monday,
    summarize last week's findings"), one-off check-ins ("at 3pm, re-scan the
    new subnet").

    Args:
        prompt: Self-contained text the agent receives when the schedule fires —
            it has no memory of this scheduling moment.
        when: A 5-field cron expression (``"0 9 * * 1-5"`` = weekdays 9am) or an
            ISO-8601 datetime (``"2026-05-01T15:00:00"`` = once at 3pm UTC).
            Use ``current_time`` to compute exact times.
        job_id: Optional id for the job; auto-generated if omitted.
    """
    if _scheduler_backend is None:
        return "Error: scheduler is not available."
    try:
        job = await asyncio.to_thread(_scheduler_backend.add_job, prompt, when, job_id=job_id)
    except ValueError as exc:
        return f"Error: {exc}"
    except Exception as exc:  # noqa: BLE001
        return f"Error: scheduler add_job failed: {exc}"
    return f"Scheduled job {job.id} next at {job.next_fire}."


@tool
async def list_schedules() -> str:
    """List the current scheduled jobs. One per line with id, next-fire, schedule,
    and a prompt preview. Returns ``"No scheduled jobs."`` when empty."""
    if _scheduler_backend is None:
        return "Error: scheduler is not available."
    jobs = await asyncio.to_thread(_scheduler_backend.list_jobs)
    if not jobs:
        return "No scheduled jobs."
    lines = []
    for j in jobs:
        preview = (j.prompt or "")[:80]
        lines.append(f"{j.id}  next={j.next_fire}  schedule={j.schedule!r}  {preview}")
    return "\n".join(lines)


@tool
async def cancel_schedule(job_id: str) -> str:
    """Cancel a scheduled job by id (from ``schedule_task`` or ``list_schedules``)."""
    if _scheduler_backend is None:
        return "Error: scheduler is not available."
    if not job_id or not job_id.strip():
        return "Error: job_id is required."
    try:
        ok = await asyncio.to_thread(_scheduler_backend.cancel_job, job_id)
    except Exception as exc:  # noqa: BLE001
        return f"Error: scheduler cancel_job failed: {exc}"
    return f"Canceled {job_id}." if ok else f"Error: cancel failed or no such job {job_id}."


_WAIT_MAX_SECONDS = 30 * 24 * 60 * 60  # 30d — past this, schedule_task is the right tool


@tool
async def wait(seconds: int, then: str, state: Annotated[dict, InjectedState] = None) -> str:
    """Yield this turn and get re-invoked later — instead of busy-waiting.

    Use when there is nothing to do until some time passes: a scan/exploit is
    running, a payload needs to land, a rate-limit window must elapse. Calling
    ``wait`` ENDS the current turn immediately (it does not block) and schedules
    a one-shot resume into THIS SAME conversation — you wake up later with the
    full history intact and the ``then`` instruction as your new prompt. This is
    strictly better than looping/polling, which burns the recursion budget.

    Args:
        seconds: How long to yield for, in seconds (>= 1). Capped at 30 days; for
            longer or recurring waits use ``schedule_task``.
        then: Self-contained instruction for what to do when you resume — e.g.
            "check whether the nmap scan in /tmp/scan.txt finished and analyze it".
    """
    if _scheduler_backend is None:
        return "Error: scheduler unavailable; cannot wait. Do the work now or report you can't."
    try:
        secs = int(seconds)
    except (TypeError, ValueError):
        return "Error: 'seconds' must be an integer number of seconds."
    if secs < 1:
        return "Error: 'seconds' must be >= 1."
    secs = min(secs, _WAIT_MAX_SECONDS)
    if not then or not then.strip():
        return "Error: 'then' (what to do on resume) is required."

    from datetime import UTC, datetime, timedelta

    resume_at = (datetime.now(UTC) + timedelta(seconds=secs)).isoformat()
    session_id = session_id_from_state(state)
    try:
        job = await asyncio.to_thread(_scheduler_backend.add_job, then, resume_at, context_id=(session_id or None))
    except Exception as exc:  # noqa: BLE001
        return f"Error: could not schedule the resume: {exc}"
    # The leading marker lets WaitYieldMiddleware end the turn on a *successful*
    # wait (an "Error:" return above does NOT yield — you see it and react).
    return (
        f"{_WAIT_YIELD_MARKER} for {secs}s — this turn is ending now. You will be "
        f"re-invoked at {resume_at} (job {job.id}) to: {then}"
    )


# ── Task-tracker tools (beads / `br`) ─────────────────────────────────────────
# The agent's durable to-do list for long-running, multi-step work — distinct
# from schedule_task (time-based future turns) and subagent delegation (one-shot).
# Bound to a BeadsService + project dir via set_beads() at server startup; bodies
# read the globals lazily so they work with a graph built before wiring.

_beads_service = None  # operator_api.beads.BeadsService
_beads_project_path = ""  # directory holding the .beads/ store


def set_beads(service, project_path: str) -> None:
    """Wire the live beads task tracker for the agent's task tools."""
    global _beads_service, _beads_project_path
    _beads_service = service
    _beads_project_path = project_path or ""


def _beads_unavailable() -> str | None:
    if _beads_service is None or not _beads_project_path:
        return "Error: task tracker (beads) is not available."
    return None


def get_beads_handle():
    """Return ``(service, project_path)`` for read-only introspection (e.g. the
    goal ``task`` verifier). Either may be falsy when the tracker isn't wired."""
    return _beads_service, _beads_project_path


def _fmt_task(issue: dict) -> str:
    return f"{issue.get('id', '?')} [{issue.get('status', '?')}] p{issue.get('priority', '?')} {issue.get('title', '')}".rstrip()


@tool
async def create_task(title: str, description: str = "", priority: int = 2, task_type: str = "task") -> str:
    """Track a long-running or multi-step task in the persistent tracker (beads).

    Use this to remember intent across turns — e.g. "monitor 10.0.0.0/24 for new
    hosts", "finish the web-app assessment", "follow up on the SMB finding". This
    is durable to-do tracking, distinct from schedule_task (fires a future turn at
    a set time) and from delegating a one-shot subagent. Manage tasks afterwards
    with list_tasks / update_task / close_task.

    Args:
        title: Short imperative summary of the task.
        description: Optional detail — scope, acceptance criteria, next steps.
        priority: 0 (highest) … 4 (lowest); default 2.
        task_type: task | feature | bug | epic | chore (default "task").
    """
    err = _beads_unavailable()
    if err:
        return err
    if not title.strip():
        return "Error: title is required."
    try:
        issue = await asyncio.to_thread(
            _beads_service.create,
            _beads_project_path,
            {"title": title, "description": description, "priority": priority, "type": task_type},
        )
    except Exception as exc:  # noqa: BLE001
        return f"Error: could not create task: {exc}"
    return f"Created task {issue.get('id', '?')} — {issue.get('title', title)}"


@tool
async def list_tasks(status: str = "") -> str:
    """List tracked tasks. Optionally filter by status (open, in_progress, blocked,
    closed). Use to recall outstanding work before deciding what to do next.
    Returns "No tasks." when empty.

    Args:
        status: Optional status filter; empty = all tasks.
    """
    err = _beads_unavailable()
    if err:
        return err
    try:
        issues = await asyncio.to_thread(_beads_service.list, _beads_project_path)
    except Exception as exc:  # noqa: BLE001
        return f"Error: could not list tasks: {exc}"
    if status.strip():
        issues = [i for i in issues if str(i.get("status", "")) == status.strip()]
    if not issues:
        return "No tasks." if not status.strip() else f"No tasks with status {status!r}."
    return "\n".join(_fmt_task(i) for i in issues[:50])


@tool
async def update_task(task_id: str, status: str = "", priority: int | None = None) -> str:
    """Advance or re-prioritize a tracked task — set its status (open →
    in_progress → closed, or blocked) and/or its priority.

    Args:
        task_id: The task id from create_task / list_tasks (e.g. "protopen-15t").
        status: New status — open | in_progress | blocked | closed.
        priority: New priority 0 (highest) … 4 (lowest).
    """
    err = _beads_unavailable()
    if err:
        return err
    if not task_id.strip():
        return "Error: task_id is required."
    update: dict = {}
    if status.strip():
        update["status"] = status.strip()
    if priority is not None:
        update["priority"] = priority
    if not update:
        return "Error: nothing to update — provide status and/or priority."
    try:
        issue = await asyncio.to_thread(_beads_service.update, _beads_project_path, task_id, update)
    except Exception as exc:  # noqa: BLE001
        return f"Error: could not update task: {exc}"
    return f"Updated {issue.get('id', task_id)} → status={issue.get('status', '?')} p{issue.get('priority', '?')}"


@tool
async def close_task(task_id: str, reason: str = "") -> str:
    """Mark a tracked task done/closed once its work is complete.

    Args:
        task_id: The task id to close.
        reason: Optional short note on the outcome.
    """
    err = _beads_unavailable()
    if err:
        return err
    if not task_id.strip():
        return "Error: task_id is required."
    try:
        await asyncio.to_thread(_beads_service.close, _beads_project_path, task_id, reason or None)
    except Exception as exc:  # noqa: BLE001
        return f"Error: could not close task: {exc}"
    return f"Closed task {task_id}." + (f" ({reason})" if reason else "")


# ── Goal mode (autonomy) ──────────────────────────────────────────────────────
# Lets the agent commit to a multi-turn goal: after the turn, the server's goal
# loop re-invokes it with a continuation prompt until a verifier passes. Bound to
# the GoalController via set_goal_controller() at startup; the body reads the
# global lazily (graph is built before wiring) and the session_id from the
# per-turn contextvar the server sets.

_goal_controller = None  # graph.goals.controller.GoalController — set by server.py


def set_goal_controller(controller) -> None:
    """Wire the goal controller so the agent's set_goal tool can set goals."""
    global _goal_controller
    _goal_controller = controller


@tool
async def set_goal(
    condition: str,
    verifier: str = "llm",
    severity: str = "",
    category: str = "",
    min_count: int = 1,
    target: str = "",
) -> str:
    """Commit to an autonomous goal — keep working across turns until a verifier
    confirms it's met (or the iteration budget runs out).

    Use when the operator asks for an outcome that needs several turns: "find a
    critical vuln on the target", "enumerate the subnet", "close out the web
    assessment". After you set a goal you'll be re-invoked automatically with a
    continuation prompt after each turn until it's met. Maintain a running
    ``<goal_plan>...</goal_plan>`` checklist each turn; emit
    ``<goal_unachievable reason="..."/>`` to give up if it's impossible/out of scope.

    Args:
        condition: Plain-language description of the finish line.
        verifier: How completion is checked —
            "findings" (≥ min_count engagement findings; pair with severity/category),
            "targets" (≥ min_count discovered hosts; ``category`` filters host text),
            "task" (a tracked beads task is done — scope with ``target``), or
            "llm" (an evaluator judges the condition — the default, for fuzzy goals).
        severity: For verifier="findings": minimum severity
            (info|low|medium|high|critical).
        category: For "findings": finding-category substring. For "targets":
            free-text host filter (ip/hostname/os/device_type/…).
        min_count: Minimum matching findings/hosts required (default 1).
        target: For verifier="task": which task must be done — a task id
            (e.g. "protopen-15t", exact) or a title substring. Omit to require that
            *every* tracked task is done.
    """
    if _goal_controller is None:
        return "Error: goal mode is not available."
    from graph.goals.context import get_current_session

    session_id = get_current_session()
    if not session_id:
        return "Error: no active session to attach the goal to."
    if not condition.strip():
        return "Error: condition is required."

    # Only agent-safe verifier types (ADR 0028): all read-only / LLM-judge, never
    # shell or eval. Validated against the single source of truth so this can't
    # drift to accidentally expose a code-execution verifier to the model.
    from graph.goals.verifiers import AGENT_SAFE_VERIFIERS

    vtype = (verifier or "llm").strip().lower()
    if vtype not in AGENT_SAFE_VERIFIERS:
        allowed = "|".join(sorted(AGENT_SAFE_VERIFIERS))
        return f"Error: unknown or unsafe verifier {vtype!r} (use {allowed})."

    spec: dict = {"type": vtype}
    if vtype == "findings":
        if severity.strip():
            spec["severity"] = severity.strip().lower()
        if category.strip():
            spec["category"] = category.strip()
        spec["min"] = max(1, int(min_count or 1))
    elif vtype == "targets":
        if category.strip():
            spec["query"] = category.strip()
        spec["min"] = max(1, int(min_count or 1))
    elif vtype == "task" and target.strip():
        # A beads id (prefix-hash, e.g. "protopen-15t") → exact match; anything
        # else is treated as a title substring.
        ref = target.strip()
        spec["id" if re.fullmatch(r"[a-z][a-z0-9]*-[a-z0-9]+", ref) else "title"] = ref

    try:
        state = await asyncio.to_thread(_goal_controller.start_goal, session_id, condition.strip(), spec)
    except Exception as exc:  # noqa: BLE001
        return f"Error: could not set goal: {exc}"
    return (
        f"Goal set ({vtype}): {state.condition}. I'll keep working across turns "
        f"until the verifier passes (max {state.max_iterations} iterations)."
    )


@tool
async def request_user_input(prompt: str, fields: list[dict] | None = None, title: str = "") -> str:
    """Pause and ask the operator for input, then STOP and wait — do not continue
    until they respond.

    Use when you genuinely need a human decision or a value only the operator can
    provide: a missing parameter, a choice between options, confirmation of scope.
    Prefer asking over guessing. After you call this tool, end your turn — you'll
    be re-invoked with the operator's answer on this same session.

    Only available in interactive sessions. In a headless/autonomous run there is
    no operator to answer; this tool will tell you to proceed on your best
    judgment instead of pausing — do not wait in that case.

    Args:
        prompt: The question or instruction shown to the operator.
        fields: Optional structured form — a list of field dicts
            ``{"id","label","type","enum"?,"required"?,"description"?}`` where type
            is string|number|integer|boolean|textarea. Omit for a free-text answer.
        title: Optional short heading for the card.
    """
    from graph.goals.context import get_current_session
    from graph.hitl_context import hitl_allowed, request_pending_hitl

    if not hitl_allowed():
        return (
            "No operator is available in this autonomous/headless run — do not wait. "
            "Proceed using your best judgment and note any assumption in your output."
        )

    session_id = get_current_session()
    if not session_id:
        return "Error: no active session — cannot request operator input."

    if fields:
        steps: list[dict] = []
        for f in fields:
            if not isinstance(f, dict) or not f.get("id"):
                continue
            step: dict = {
                "id": str(f["id"]),
                "label": str(f.get("label") or f["id"]),
                "type": str(f.get("type") or "string"),
            }
            if isinstance(f.get("enum"), list):
                step["enum"] = f["enum"]
            if f.get("required"):
                step["required"] = True
            if f.get("description"):
                step["description"] = str(f["description"])
            steps.append(step)
        payload = {
            "kind": "form",
            "title": title or "Input requested",
            "description": prompt,
            "steps": steps,
        }
    else:
        payload = {"kind": "question", "title": title or "Input requested", "question": prompt}

    request_pending_hitl(session_id, payload)
    return "Paused — awaiting the operator's response. Do not continue; end your turn now."


@tool
async def request_approval(action: str, detail: str = "") -> str:
    """Pause for the operator's approval of a specific action, then STOP and wait.

    Use before an action that needs a human go-ahead — escalating to active
    scanning, a destructive or intrusive step, anything outside the agreed scope.
    The operator sees an Approve / Deny card. After calling this, end your turn —
    you'll be re-invoked with their decision ("approved" or "denied").

    Only available in interactive sessions. In a headless/autonomous run there is
    no operator to approve; this tool returns a no-op instead of pausing — rely on
    the engagement mode (which still hard-blocks out-of-scope actions) rather than
    waiting on approval.

    Args:
        action: Short description of what you want to do (the card title).
        detail: Optional specifics — the exact command/target being approved.
    """
    from graph.goals.context import get_current_session
    from graph.hitl_context import hitl_allowed, request_pending_hitl

    if not hitl_allowed():
        return (
            "No operator is available to approve in this autonomous/headless run — do not wait. "
            "Proceed only within the current engagement mode; it will block anything out of scope."
        )

    session_id = get_current_session()
    if not session_id:
        return "Error: no active session — cannot request approval."

    payload: dict = {"kind": "approval", "title": action or "Approve this action?"}
    if detail:
        payload["detail"] = str(detail)

    request_pending_hitl(session_id, payload)
    return "Paused — awaiting the operator's approval. Do not continue; end your turn now."


def create_memory_curation_tools(store=None):
    """Memory-consolidation tools for the dream subagent (ADR 0054): inspect facts
    by id and prune one at a time. Read-mostly, NO shell / NO raw SQL — so a
    consolidation pass can't corrupt the store."""
    from knowledge.store import KnowledgeStore

    _store = store or KnowledgeStore()

    @tool
    async def memory_list(namespace: str = "", limit: int = 50) -> str:
        """List durable semantic facts, each prefixed with its #id so you can target
        one for forget_memory. Newest first. ``namespace`` empty = the global bucket."""
        ns = namespace.strip() or None
        facts = await asyncio.to_thread(_store.list_facts, ns, max(1, min(int(limit or 50), 500)))
        if not facts:
            return "No stored facts."
        lines = [f"#{f['id']}  {(f['content'] or '')[:200]}" for f in facts]
        return f"{len(facts)} fact(s):\n" + "\n".join(lines)

    @tool
    async def forget_memory(fact_id: str, reason: str = "") -> str:
        """Delete exactly ONE durable fact by its id (from memory_list) — for pruning a
        stale, superseded, or duplicate fact. No wildcard/bulk delete. Give a brief reason."""
        fid = (fact_id or "").strip().lstrip("#")
        if not fid:
            return "Error: fact_id is required (see memory_list for #ids)."
        ok = await asyncio.to_thread(_store.delete_fact, fid)
        if not ok:
            return f"No fact deleted for id {fid!r} (already gone or unknown id)."
        return f"Forgot fact {fid} ({reason.strip() or 'no reason given'})."

    return [memory_list, forget_memory]


@tool
async def recent_activity(limit: int = 30) -> str:
    """Read-only digest of recent tool activity (the audit log) — what the agent
    has been doing lately. For the dream pass to mine repeated work; no side effects."""
    n = max(1, min(int(limit or 30), 200))
    try:
        from audit import audit_logger

        entries = await asyncio.to_thread(audit_logger.get_recent, n)
    except Exception:
        # Audit subsystem unavailable (e.g. its log dir isn't writable) — never
        # raise into the turn; the digest is best-effort.
        return "No recent activity available."
    if not entries:
        return "No recent activity."
    from collections import Counter

    counts = Counter(e.get("tool", "?") for e in entries)
    rollup = ", ".join(f"{t}×{c}" for t, c in counts.most_common(10))
    lines = [
        f"- {e.get('ts', '')[:19]} {e.get('tool', '?')} "
        f"[{'ok' if e.get('success') else 'FAIL'}] {(e.get('result_summary') or '')[:80]}"
        for e in entries[:limit]
    ]
    return f"Recent activity ({len(entries)} calls) — {rollup}\n" + "\n".join(lines)


def get_security_tools(knowledge_store=None):
    """Get security-domain tools as LangChain tool objects."""
    tools = [
        cve_search,
        security_feeds,
        github_trending,
        browser,
        lab_monitor,
        create_security_memory_tool(knowledge_store),
        *create_memory_curation_tools(knowledge_store),
        recent_activity,
        schedule_task,
        list_schedules,
        cancel_schedule,
        wait,
        create_task,
        list_tasks,
        update_task,
        close_task,
        set_goal,
        request_user_input,
        request_approval,
    ]
    if _discord_feed_tool is not None:
        tools.insert(0, discord_feed)
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
        return  # already initialised — fast path, no lock

    with _pentest_init_lock:
        # Re-check under the lock: another thread may have finished init while we
        # waited. ``_device_manager`` is assigned last (below), so seeing it set
        # guarantees every other singleton is already built.
        if _device_manager is not None:
            return
        _init_pentest_singletons_locked()


def _init_pentest_singletons_locked():
    global _device_manager, _portapack, _flipper, _marauder, _blackarch, _engagement
    global _target_store, _target_intel

    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "engagement-config.json")
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)
    else:
        config = {"devices": {}, "engagement": {}}

    # Built into a local and published to the global LAST (see below), so the
    # ``_device_manager is not None`` guard implies every singleton is ready.
    device_mgr = DeviceManager(config.get("devices", {}))
    _target_store = TargetStore()
    _engagement = EngagementManager(config)
    _engagement.target_store = _target_store
    _target_intel = TargetIntelTool(_target_store)
    _blackarch = BlackArchTool(
        wifi_interface=config.get("devices", {}).get("wifi_adapter", {}).get("interface", "wlan1"),
        monitor_interface=config.get("devices", {}).get("wifi_adapter", {}).get("monitor_interface", "wlan1mon"),
    )
    _blackarch._target_store = _target_store

    global _dns_enum, _subdomain_discovery, _osint_recon, _maigret, _phoneinfoga, _holehe
    global _web_enum, _service_enum, _ssl_audit, _api_enum
    global _external_recon, _perimeter_audit
    _dns_enum = DnsEnumTool()
    _dns_enum._target_store = _target_store
    _subdomain_discovery = SubdomainDiscoveryTool()
    _subdomain_discovery._target_store = _target_store
    _osint_recon = OsintReconTool()
    _osint_recon._target_store = _target_store
    _maigret = MaigretTool()
    _maigret._target_store = _target_store
    _phoneinfoga = PhoneInfogaTool()
    _phoneinfoga._target_store = _target_store
    _holehe = HoleheTool()
    _holehe._target_store = _target_store
    _external_recon = ExternalReconTool()
    _external_recon._target_store = _target_store
    _perimeter_audit = PerimeterAuditTool()
    _perimeter_audit._target_store = _target_store
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
    global _lan_scan
    _lan_scan = LanScanTool()
    _lan_scan._target_store = _target_store
    _data_exfil = DataExfilTool()
    _data_exfil._target_store = _target_store
    _persistence = PersistenceTool()
    _persistence._target_store = _target_store
    _cleanup = CleanupTool()
    _cleanup._target_store = _target_store
    global _opsec
    _opsec = OpsecTool()

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

    global _cicd_audit
    _cicd_audit = CICDAuditTool()

    global _ipv6_attack
    _ipv6_attack = IPv6AttackTool()

    global _iot_protocol
    _iot_protocol = IoTProtocolTool()

    global _iot_audit
    _iot_audit = IoTAuditTool()
    _iot_audit._target_store = _target_store

    global _ad_attack
    _ad_attack = ADAttackTool()

    global _llm_audit
    _llm_audit = LLMAuditTool()

    global _telecom_attack
    _telecom_attack = TelecomAttackTool()

    global _evasion
    _evasion = EvasionTool()

    global _phishing
    _phishing = PhishingTool()

    global _grpc_audit
    _grpc_audit = GRPCAuditTool()

    global _auth_audit
    _auth_audit = AuthAuditTool()

    global _mobile_audit
    _mobile_audit = MobileAuditTool()

    global _supply_chain
    _supply_chain = SupplyChainTool()

    global _serverless_audit
    _serverless_audit = ServerlessAuditTool()

    global _spa_test
    _spa_test = SPATestTool()

    global _sdn_attack
    _sdn_attack = SDNAttackTool()

    global _recon_pipeline
    _recon_pipeline = ReconPipelineTool()

    # Wire the target store into the BasePentestTool subclasses created above
    # (container/websocket/cicd/ipv6/iot + Tier 3/4) that lacked it, so their
    # registered parsers (tools/parsers) actually ingest findings at runtime —
    # BasePentestTool._run calls ingest_output, which no-ops without a store.
    for _t in (
        _container_audit,
        _websocket_test,
        _cicd_audit,
        _ipv6_attack,
        _iot_protocol,
        _ad_attack,
        _llm_audit,
        _telecom_attack,
        _evasion,
        _phishing,
        _grpc_audit,
        _auth_audit,
        _mobile_audit,
        _supply_chain,
        _serverless_audit,
        _spa_test,
        _sdn_attack,
        _recon_pipeline,
    ):
        _t._target_store = _target_store

    global _wifi_intel
    wifi_cfg = config.get("devices", {}).get("wifi_adapter", {})
    _wifi_intel = WiFiIntelTool(
        interface=wifi_cfg.get("interface", "wlan1"),
        monitor_interface=wifi_cfg.get("monitor_interface", "wlan1mon"),
    )
    _wifi_intel._target_store = _target_store

    global _traffic_analysis
    _traffic_analysis = TrafficAnalysisTool()
    _traffic_analysis._target_store = _target_store

    # Orchestrator — wired with engagement manager and a dispatch closure
    global _orchestrator_tool

    async def _orchestrator_dispatch(tool_name: str, action_name: str, params: dict) -> str:
        """Dispatch tool calls from the orchestrator pipeline."""
        from tools.lg_tools import get_pentest_tools

        for t in get_pentest_tools():
            if t.name == tool_name:
                return await t.ainvoke({"action": action_name, **params})
        return f"Error: Tool '{tool_name}' not found in pentest tools"

    _orchestrator_tool = EngagementOrchestratorTool(
        engagement_mgr=_engagement,
        dispatch_fn=_orchestrator_dispatch,
    )

    # Publish the init-complete sentinel LAST: every other singleton is now built,
    # so a concurrent caller that sees ``_device_manager`` set gets a ready set.
    _device_manager = device_mgr


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
        action=action,
        app=app,
        frequency=frequency,
        x=x,
        y=y,
        button=button,
        command=command,
        path=path,
        lat=lat,
        lon=lon,
        altitude=altitude,
        speed=speed,
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
    timeout: int = 10,
) -> str:
    """Control Flipper Zero via serial CLI.

    RF: subghz_rx, subghz_tx, subghz_decode_raw, subghz_tx_from_file, subghz_bruteforce
    NFC: nfc_detect, nfc_field, nfc_emulate
    RFID: rfid_read, rfid_emulate
    BLE: ble_scan, bt_info
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
        action=action,
        command=command,
        frequency=frequency,
        modulation=modulation,
        path=path,
        key_type=key_type,
        data=data,
        protocol=protocol,
        raw_data=raw_data,
        timeout=timeout,
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
        action=action,
        scan_type=scan_type,
        indices=indices,
        channel=channel,
        list_type=list_type,
        sniff_type=sniff_type,
        use_deauth=use_deauth,
        spam_type=spam_type,
        ssid=ssid,
        count=count,
        html_path=html_path,
        command=command,
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
        action=action,
        target=target,
        ports=ports,
        scripts=scripts,
        interface=interface,
        command=command,
        timeout=timeout,
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
    note: str = "",
    authorized_by: str = "",
    rules_of_engagement: str = "",
) -> str:
    """Manage pentest engagements — mode enforcement, logging, reporting.

    - start: Start a new engagement (name + scope required)
    - end: End current engagement and save findings
    - set_mode: Set mode (passive/active/redteam)
    - check_permission: Check if a tool action is allowed in current mode
    - log_finding: Log a finding (severity, category, title, description)
    - update: Update active engagement metadata without restarting — accepts any of:
        scope (str): update the target scope
        note (str): append a timestamped note (use for authorization statements,
                    ownership confirmations, RoE changes — anything the agent should
                    be able to cite when deciding whether to proceed with an action)
        authorized_by (str): record who authorized this engagement
        rules_of_engagement (str): record RoE summary / constraints
    - report: Generate engagement report
    - status: Show current engagement state
    """
    _init_pentest_singletons()
    return await _engagement.execute(
        action=action,
        name=name,
        scope=scope,
        mode=mode,
        tool_name=tool_name,
        severity=severity,
        category=category,
        title=title,
        description=description,
        note=note,
        authorized_by=authorized_by,
        rules_of_engagement=rules_of_engagement,
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
        action=action,
        ip=ip,
        mac=mac,
        hostname=hostname,
        os=os_fingerprint,
        vendor=vendor,
        device_type=device_type,
        host_id=host_id,
        port=port,
        protocol=protocol,
        service=service,
        banner=banner,
        bssid=bssid,
        ssid=ssid,
        channel=channel,
        rssi=rssi,
        encryption=encryption,
        frequency_hz=frequency_hz,
        modulation=modulation,
        data_hex=data_hex,
        source_device=source_device,
        decoded_text=decoded_text,
        name=name,
        tag_type=tag_type,
        uid=uid,
        label=label,
        username=username,
        password=password,
        hash_type=hash_type,
        source=source,
        tool=scan_tool,
        scan_action=scan_action,
        scan_session_id=scan_session_id,
        engagement=engagement_name,
        ip_prefix=ip_prefix,
        since=since,
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
        action=action,
        target=target,
        record_type=record_type,
        nameserver=nameserver,
        wordlist=wordlist,
        timeout=timeout,
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
        action=action,
        target=target,
        timeout=timeout,
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
        action=action,
        target=target,
        source=source,
        limit=limit,
        timeout=timeout,
    )


@tool
async def maigret(
    username: str,
    action: str = "search",
    top_sites: int = 500,
    all_sites: bool = False,
    id_type: str = "username",
    site: str = "",
    tags: str = "",
    recursive: bool = False,
    timeout: int = 30,
    max_seconds: int = 300,
) -> str:
    """Maigret OSINT username reconnaissance across 3000+ sites.

    Passive — queries public sites only. Searches a username (or other id type)
    and returns the found public accounts (profile URLs + extracted IDs/bios);
    results are ingested into the target store.

    - top_sites: check the N most popular sites (default 500)
    - all_sites: check all 3000+ sites instead (slower)
    - id_type: username (default), steam_id, vk_id, gaia_id, yandex_public_id, ...
    - site: restrict to a single site by name
    - tags: comma-separated site tags to filter (e.g. 'us,social')
    - recursive: follow usernames/ids extracted from found profiles (deeper)
    """
    _init_pentest_singletons()
    return await _maigret.execute(
        action=action,
        username=username,
        top_sites=top_sites,
        all_sites=all_sites,
        id_type=id_type,
        site=site,
        tags=tags,
        recursive=recursive,
        timeout=timeout,
        max_seconds=max_seconds,
    )


@tool
async def phoneinfoga(
    number: str,
    action: str = "scan",
    timeout: int = 60,
) -> str:
    """PhoneInfoga OSINT phone-number reconnaissance.

    Passive — number metadata + public sources only; nothing is sent to the
    number. Given a number in international format (e.g. '+14155552671'), returns
    country, carrier, and line type, plus an OSINT footprint (search-engine dorks
    and reputation links). Results are ingested into the target store.

    Use the email pivot (holehe) and username pivot (maigret) to cross-reference a
    person across phone / email / handle.
    """
    _init_pentest_singletons()
    return await _phoneinfoga.execute(action=action, number=number, timeout=timeout)


@tool
async def holehe(
    email: str,
    action: str = "search",
    only_used: bool = True,
    timeout: int = 120,
) -> str:
    """holehe OSINT email reconnaissance — which sites have an account for an email.

    Passive — queries public registration/reset flows for 120+ sites; never sends
    mail to the address or logs in. Returns the sites where the email is registered;
    results are ingested into the target store.

    - only_used: report only sites where the email is registered (default true)

    The email pivot that complements maigret (username) and phoneinfoga (number).
    """
    _init_pentest_singletons()
    return await _holehe.execute(action=action, email=email, only_used=only_used, timeout=timeout)


@tool
async def external_recon(
    action: str,
    target: str = "",
    timeout: int = 60,
) -> str:
    """Passive external reconnaissance from an attacker's perspective.

    Actions:
    - wan_ip: Discover the public WAN IP of this network
    - shodan_host: Query Shodan for everything known about an IP (requires SHODAN_API_KEY)
    - shodan_search: Search Shodan with a query string (e.g. 'org:\"ISP\" port:22')
    - censys_host: Query Censys for services on an IP (requires CENSYS_API_ID/SECRET)
    - bgp_asn: BGP/ASN/WHOIS ownership, prefixes, abuse contacts for an IP
    - cert_transparency: crt.sh certificate transparency — discover all subdomains/hostnames
    - dns_security: Check SPF, DKIM, DMARC, CAA, DNSSEC posture for a domain
    - cloud_exposure: Check for exposed S3/Azure/GCS buckets tied to a domain
    - full_external: Run all external recon phases (WAN IP → Shodan → BGP → certs → DNS → cloud)
    """
    _init_pentest_singletons()
    return await _external_recon.execute(
        action=action,
        target=target,
        timeout=timeout,
    )


@tool
async def perimeter_audit(
    action: str,
    target: str = "",
    interface: str = "eth0",
    external_ip: str = "",
    pivot_host: str = "",
    ports: str = "",
    timeout: int = 60,
) -> str:
    """Network perimeter and router/CPE audit — UPnP, default creds, RouterSploit, WAN exposure.

    Actions:
    - router_fingerprint: Banner grab, web UI title, SNMP fingerprint of gateway router
    - upnp_discover: Discover all UPnP devices via SSDP broadcast
    - upnp_portmap: List existing UPnP port forwarding rules (potential WAN exposure)
    - upnp_add_portmap: Test whether IGD accepts unauthenticated port mapping additions
    - default_creds: Test common router default credentials (admin/admin, etc.)
    - routersploit_scan: RouterSploit autopwn scan against router
    - wan_portscan: Scan WAN IP from external vantage — runs parallel SYN+ACK scans, reports ALL
      port states (open/filtered/closed). REQUIRES external pivot for public IPs (set via
      PIVOT_HOST env var — do NOT pass the target IP as pivot_host).
    - tcp_probe: Deep TCP flag analysis on specific ports (comma-separated in 'ports' param, default
      4567,7547,9443). Uses hping3 SYN probes + nmap -sA/-sF/-sN battery to distinguish:
      FIN+ACK (IP-allowlisted ISP management), RST (closed), SYN+ACK (open), silence (firewall drop).
      REQUIRES external pivot for public IPs. Run when Shodan shows a port indexed but nmap
      reports filtered — the flags reveal whether it's a firewall or an IP-allowlisted service.
      NOTE: pivot_host is auto-resolved from PIVOT_HOST env — do not pass target IP as pivot_host.
    - acs_fingerprint: Probe ISP/CPE management ports (7547 CWMP, 4567 ACS, 9443, etc.) and
      correlate with rDNS/ASN to identify ISP and management platform. Reveals TR-069 ACS
      and proprietary management planes (Lumen, Comcast, AT&T, Verizon, Cox).
      REQUIRES external pivot for public IPs.
    - dns_rebind_check: Check if router blocks DNS rebinding attacks
    - firewall_egress: Test which outbound ports pass through the firewall
    - full_perimeter: Run all perimeter checks in parallel (includes tcp_probe + acs_fingerprint
      when external_ip or pivot_host is provided)
    """
    _init_pentest_singletons()
    return await _perimeter_audit.execute(
        action=action,
        target=target,
        interface=interface,
        external_ip=external_ip,
        pivot_host=pivot_host,
        ports=ports,
        timeout=timeout,
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
        action=action,
        url=url,
        wordlist=wordlist,
        extensions=extensions,
        threads=threads,
        recursive=recursive,
        depth=depth,
        timeout=timeout,
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
        action=action,
        target=target,
        share=share,
        username=username,
        password=password,
        timeout=timeout,
    )


@tool
async def lan_scan(
    action: str,
    network: str = "192.168.1.0/24",
    interface: str = "eth0",
    timeout: int = 0,
) -> str:
    """LAN discovery and enumeration (risk level 1 — active probing).

    - arp_sweep: Fast L2 host discovery via ARP (IP, MAC, vendor)
    - netdiscover: Passive/active ARP recon with IP/MAC/vendor table
    - nbtscan: NetBIOS name scan — finds Windows hosts and workgroup names
    - snmp_sweep: UDP/161 sweep with SNMP community string probing
    - mdns_enum: Enumerate mDNS/Bonjour services via avahi-browse
    - smb_discovery: Find SMB hosts, OS fingerprint, SMBv1/v2 security mode
    - full_lan_sweep: Combined ARP discovery + nmap -sV -O --top-ports 100
    """
    _init_pentest_singletons()
    kw: dict = {"action": action, "network": network, "interface": interface}
    if timeout:
        kw["timeout"] = timeout
    return await _lan_scan.execute(**kw)


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
        action=action,
        target=target,
        timeout=timeout,
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
        action=action,
        url=url,
        wordlist=wordlist,
        methods=methods,
        timeout=timeout,
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
        action=action,
        target=target,
        username=username,
        password=password,
        domain=domain,
        hash=hash,
        socks_port=socks_port,
        timeout=timeout,
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
        action=action,
        target=target,
        username=username,
        password=password,
        share=share,
        remote_path=remote_path,
        local_path=local_path,
        url=url,
        timeout=timeout,
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
        action=action,
        pubkey=pubkey,
        schedule=schedule,
        command=command,
        timeout=timeout,
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
        action=action,
        key_fingerprint=key_fingerprint,
        pattern=pattern,
        file_paths=file_paths,
        timeout=timeout,
    )


@tool
async def opsec(
    action: str,
    interface: str = "",
    original_mac: str = "",
    interfaces: list = [],
    mode: str = "active",
) -> str:
    """Opsec management — MAC randomization, interface fingerprint control, nmap opsec profiles.

    - mac_randomize: Randomize MAC address on a network interface before scanning
    - mac_restore: Restore original MAC after engagement (pass interface + original_mac)
    - mac_status: Show current MAC and whether it's randomized or hardware
    - pre_scan_setup: Randomize MAC on all engagement interfaces + print nmap opsec flags
    - post_scan_cleanup: Report MAC state on all interfaces for cleanup
    - nmap_flags: Return opsec-hardened nmap flags for passive/active/redteam mode

    Always run mac_randomize or pre_scan_setup before active scanning.
    Always run mac_restore or post_scan_cleanup after the engagement ends.
    """
    _init_pentest_singletons()
    return await _opsec.execute(
        action=action,
        interface=interface,
        original_mac=original_mac,
        interfaces=interfaces,
        mode=mode,
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

    return await execute_playbook_action(
        action=action,
        name=name,
        variables=variables,
        dispatch_fn=dispatch_pentest_tool,
    )


async def dispatch_pentest_tool(tool_name: str, action_name: str, params: dict) -> str:
    """Dispatch one tool call for the playbook runner — invoke the named pentest
    tool with ``{action, **params}``. Shared by the agent's ``playbook`` tool and
    the operator's manual playbook run so both use identical step semantics."""
    for t in get_pentest_tools():
        if t.name == tool_name:
            return await t.ainvoke({"action": action_name, **params})
    return f"Error: Tool '{tool_name}' not found"


@tool
async def orchestrator(
    action: str,
    name: str = "",
    scope: str = "",
    targets: str = "",
    mode: str = "active",
    scope_type: str = "web",
    playbook: str = "",
    finding_id: str = "",
) -> str:
    """Automated engagement orchestrator — scripted pen test pipeline with agent hand-off.

    Actions:
      run           — Run full automated assessment (recon → scoring → report).
                      Returns scored findings + attack suggestions for agent follow-up.
      probe_finding — Execute attack suggestions for a specific scored finding (finding_id required).
      status        — Current pipeline state and finding counts.

    Typical flow:
      1. orchestrator run  name="audit" targets="app.example.com" mode="active"
      2. Review scored findings — note finding IDs for HIGH/CRITICAL entries
      3. orchestrator probe_finding  finding_id="a3f9c12b"
      4. Log new findings via engagement log_finding
    """
    _init_pentest_singletons()
    return await _orchestrator_tool.execute(
        action=action,
        name=name,
        scope=scope,
        targets=targets,
        mode=mode,
        scope_type=scope_type,
        **{"playbook": playbook} if playbook else {},
        finding_id=finding_id,
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
        action=action,
        target=target,
        query=query,
        module=module,
        port=port,
        payload=payload,
        lhost=lhost,
        lport=lport,
        format=format,
        timeout=timeout,
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
    # Responder params
    interface: str = "eth0",
    duration: int = 300,
    # CME / NTLM relay params
    network: str = "",
    targets: str = "",
    hash: str = "",
) -> str:
    """Credential attacks — hydra brute force, password spraying, combo lists,
    Responder LLMNR/NBT-NS poisoning, CrackMapExec SMB enumeration/spraying/PTH,
    and NTLM relay attacks.

    - hydra_brute: Brute force a single user with a password list
    - hydra_spray: Password spray a single password across user list
    - hydra_combo: Combo list attack (user:pass format)
    - responder: Poison LLMNR/NBT-NS/mDNS and capture NetNTLM hashes
      (interface, duration)
    - crackmapexec_enum: Enumerate SMB hosts, users, shares, groups across a subnet
      (network)
    - crackmapexec_spray: Password spray a target via SMB
      (target, userlist as comma-sep or file path, password)
    - ntlm_relay: Relay NTLM authentications to targets [REDTEAM]
      (targets as comma-sep IPs, duration)
    - crackmapexec_pth: Pass-the-hash via CrackMapExec [REDTEAM]
      (target, username, hash)
    """
    _init_pentest_singletons()
    return await _credential_attack.execute(
        action=action,
        target=target,
        service=service,
        username=username,
        password=password,
        wordlist=wordlist,
        userlist=userlist,
        combolist=combolist,
        threads=threads,
        timeout=timeout,
        interface=interface,
        duration=duration,
        network=network,
        targets=targets,
        hash=hash,
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
        action=action,
        hash=hash,
        hashfile=hashfile,
        wordlist=wordlist,
        rulefile=rulefile,
        mode=mode,
        format=format,
        timeout=timeout,
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
        action=action,
        target=target,
        ports=ports,
        tags=tags,
        timeout=timeout,
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
        action=action,
        url=url,
        database=database,
        timeout=timeout,
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
        action=action,
        url=url,
        timeout=timeout,
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
        action=action,
        target=target,
        query=query,
        ports=ports,
        timeout=timeout,
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
        action=action,
        token=token,
        secret=secret,
        wordlist=wordlist,
        new_claims=new_claims,
        timeout=timeout,
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
        action=action,
        url=url,
        inject_param=inject_param,
        callback_host=callback_host,
        callback_port=callback_port,
        wait_seconds=wait_seconds,
        timeout=timeout,
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
        action=action,
        url=url,
        admin_url=admin_url,
        login_url=login_url,
        headers=headers,
        user_a_headers=user_a_headers,
        user_b_headers=user_b_headers,
        low_priv_headers=low_priv_headers,
        login_data=login_data,
        test_ids=test_ids,
        id_param=id_param,
        delay=delay,
        timeout=timeout,
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
        action=action,
        url=url,
        headers=headers,
        count=count,
        interval=interval,
        spoof_ip=spoof_ip,
        timeout=timeout,
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
        action=action,
        url=url,
        headers=headers,
        query=query,
        field=field,
        type_name=type_name,
        max_depth=max_depth,
        batch_size=batch_size,
        timeout=timeout,
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
            tool=tool_name,
            action=action_name,
            target_type=target_type,
            description=description,
            payload=payload,
            waf_bypass=waf_bypass,
            success=success,
            tags=[t.strip() for t in tags.split(",") if t.strip()] if tags else [],
        )
        tid = _technique_library.add(tech)
        return _json.dumps({"id": tid, "status": "stored"})
    elif action == "search":
        results = _technique_library.search(
            tool=tool_name,
            action=action_name,
            target_type=target_type,
            tag=tag,
            success_only=success,
            limit=limit,
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
        action=action,
        target=target,
        port=port,
        expected_ports=expected_ports,
        timeout=timeout,
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
    known_dhcp_servers: str = "[]",
    timeout: int = 120,
) -> str:
    """Network monitoring — traffic baselines, host anomaly detection, DNS monitoring.

    - traffic_baseline: Capture passive traffic baseline (hosts, protocols, ports)
    - host_discovery: Discover hosts and flag unknown ones against baseline
    - service_diff: Compare current services against baseline, flag changes
    - dns_monitor: Monitor DNS traffic for exfiltration, tunneling, suspicious queries
    - protocol_anomaly: Detect unexpected protocols on the network
    - arp_watch: Detect ARP spoofing/poisoning — duplicate IP-MAC mappings and gratuitous ARP floods
    - responder_detect: Detect Responder/LLMNR poisoning — flag hosts sending LLMNR/NBT-NS responses
    - rogue_dhcp_detect: Detect rogue DHCP servers not in known_dhcp_servers trusted list
    """
    _init_pentest_singletons()
    return await _net_monitor.execute(
        action=action,
        target=target,
        network=network,
        interface=interface,
        duration=duration,
        known_hosts=known_hosts,
        baseline_services=baseline_services,
        expected_ports=expected_ports,
        allowed_protocols=allowed_protocols,
        known_dhcp_servers=known_dhcp_servers,
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
        action=action,
        target=target,
        timeout=timeout,
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
        action=action,
        log_path=log_path,
        pattern=pattern,
        keyword=keyword,
        iocs=iocs,
        attack_type=attack_type,
        compromised_hosts=compromised_hosts,
        timeout=timeout,
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
        action=action,
        red_results=red_results,
        blue_results=blue_results,
        exercise_name=exercise_name,
        target_scope=target_scope,
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
        action=action,
        target=target,
        image=image,
        path=path,
        severity=severity,
        benchmark=benchmark,
        exploit_name=exploit_name,
        timeout=timeout,
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
        action=action,
        url=url,
        origin=origin,
        auth_token=auth_token,
        categories=categories,
        timeout=timeout,
    )


@tool
async def cicd_audit(
    action: str,
    repo_url: str = "",
    path: str = ".",
    timeout: int = 120,
) -> str:
    """CI/CD pipeline security scanning — secret detection, IaC scanning, SAST.

    - trufflehog_scan: Scan git repo history for leaked secrets
    - trufflehog_filesystem: Scan local filesystem for secrets
    - gitleaks_detect: Detect secrets committed to a git repository
    - gitleaks_protect: Scan staged changes for secrets before commit
    - github_actions_audit: Lint GitHub Actions workflows for security issues
    - dependency_check: OWASP dependency-check for vulnerable libraries
    - semgrep_ci: Static analysis security scan with semgrep
    - checkov_iac: Infrastructure-as-code security scan
    """
    _init_pentest_singletons()
    return await _cicd_audit.execute(
        action=action,
        repo_url=repo_url,
        path=path,
        timeout=timeout,
    )


@tool
async def ipv6_attack(
    action: str,
    target: str = "",
    interface: str = "eth0",
    network: str = "",
    router: str = "",
    new_router: str = "",
    timeout: int = 60,
) -> str:
    """IPv6 network attack and discovery — THC-IPv6 suite, nmap IPv6.

    - alive6: Discover alive IPv6 hosts on local link
    - detect_sniffer6: Detect IPv6 sniffers on the network
    - dos_new_ip6: DoS attack against new IPv6 addresses (DAD)
    - fake_router6: Inject fake Router Advertisements for MITM
    - flood_router6: Flood network with Router Advertisements
    - parasite6: ICMPv6 Neighbor Advertisement spoofer
    - redir6: Redirect traffic via ICMPv6 redirect messages
    - nmap_ipv6: IPv6 nmap service version scan
    - thcping6: Send crafted ICMPv6 packets
    """
    _init_pentest_singletons()
    return await _ipv6_attack.execute(
        action=action,
        target=target,
        interface=interface,
        network=network,
        router=router,
        new_router=new_router,
        timeout=timeout,
    )


@tool
async def iot_protocol(
    action: str,
    target: str = "localhost",
    topic: str = "#",
    message: str = "test",
    username: str = "admin",
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    count: int = 100,
    resource: str = "",
    slave_id: int = 1,
    register: int = 0,
    channel: int = 11,
    path: str = "/tmp/zigbee.pcap",
    timeout: int = 30,
) -> str:
    """IoT protocol security testing — MQTT, CoAP, Modbus, BACnet, UPnP, Zigbee.

    - mqtt_discover: Subscribe to all MQTT topics and capture messages
    - mqtt_pub_test: Test MQTT publish permissions
    - mqtt_bruteforce: Brute-force MQTT broker credentials
    - coap_discover: Discover CoAP resources
    - coap_get: Read a CoAP resource
    - modbus_scan: Scan for Modbus TCP devices
    - modbus_read: Read Modbus holding registers
    - bacnet_scan: Scan for BACnet devices
    - upnp_discover: Discover UPnP devices
    - zigbee_sniff: Sniff Zigbee traffic
    """
    _init_pentest_singletons()
    return await _iot_protocol.execute(
        action=action,
        target=target,
        topic=topic,
        message=message,
        username=username,
        wordlist=wordlist,
        count=count,
        resource=resource,
        slave_id=slave_id,
        register=register,
        channel=channel,
        path=path,
        timeout=timeout,
    )


@tool
async def iot_audit(
    action: str,
    target: str = "",
    network: str = "",
    port: int = 80,
    service: str = "http",
    timeout: int = 120,
) -> str:
    """IoT device security audit — discovery, fingerprinting, and vulnerability assessment.

    - device_discovery: nmap IoT port sweep across a CIDR (risk 0)
    - fingerprint: deep OS/service/banner fingerprint on a single host (risk 1)
    - telnet_check: detect open Telnet on 23/2323 — high-severity (risk 0)
    - http_admin_check: enumerate web admin panels, test default accounts (risk 1)
    - mqtt_audit: test MQTT broker for anonymous access via $SYS topic (risk 1)
    - snmp_audit: probe SNMP with default community strings (risk 0)
    - rtsp_discover: find RTSP camera streams, check auth (risk 0)
    - firmware_exposure: banner-grab for firmware version strings (risk 0)
    - default_creds: hydra credential spray with IoT defaults (risk 2 — redteam only)
    - full_iot_audit: orchestrates discovery + all checks against a network (risk 1)
    """
    _init_pentest_singletons()
    return await _iot_audit.execute(
        action=action,
        target=target,
        network=network,
        port=port,
        service=service,
        timeout=timeout,
    )


@tool
async def ad_attack(
    action: str,
    target: str = "",
    domain: str = "",
    username: str = "",
    password: str = "",
    base_dn: str = "",
    filter: str = "(objectClass=*)",
    ca_name: str = "",
    template: str = "",
    wordlist: str = "",
    timeout: int = 120,
) -> str:
    """Active Directory security testing — BloodHound, Certipy, impacket.

    - bloodhound_collect: Collect AD data for BloodHound analysis
    - bloodhound_edges: Collect ACL and trust relationships
    - certipy_find: Enumerate AD Certificate Services templates
    - certipy_vuln: Find vulnerable ADCS certificate templates
    - certipy_req: Request a certificate from a vulnerable template
    - enum4linux_ng: Enumerate SMB/LDAP/RPC information
    - ldapsearch: LDAP search query
    - kerberoast: Extract Kerberoastable service account hashes
    - asreproast: Extract AS-REP roastable user hashes
    - secretsdump: Dump secrets from domain controller
    """
    _init_pentest_singletons()
    return await _ad_attack.execute(
        action=action,
        target=target,
        domain=domain,
        username=username,
        password=password,
        base_dn=base_dn,
        filter=filter,
        ca_name=ca_name,
        template=template,
        wordlist=wordlist,
        timeout=timeout,
    )


@tool
async def llm_audit(
    action: str,
    target: str = "",
    probe: str = "all",
    config_path: str = "",
    output_dir: str = "/tmp/llm_audit",
    payload_set: str = "default",
    corpus_path: str = "",
    num_queries: int = 100,
    technique: str = "all",
    timeout: int = 300,
) -> str:
    """AI/LLM security testing — prompt injection, model abuse, RAG poisoning.

    - garak_scan: Full garak vulnerability scan against LLM endpoint
    - garak_probe: Run specific garak probe
    - promptfoo_eval: Evaluate LLM against red-team test cases
    - promptfoo_redteam: Automated red-team testing of LLM endpoint
    - prompt_inject_test: Test for direct/indirect prompt injection
    - rag_poison_check: Detect RAG poisoning in knowledge base
    - model_extract_test: Test for model weight extraction via API
    - jailbreak_test: Test jailbreak techniques against LLM
    """
    _init_pentest_singletons()
    return await _llm_audit.execute(
        action=action,
        target=target,
        probe=probe,
        config_path=config_path,
        output_dir=output_dir,
        payload_set=payload_set,
        corpus_path=corpus_path,
        num_queries=num_queries,
        technique=technique,
        timeout=timeout,
    )


@tool
async def telecom_attack(
    action: str,
    target: str = "",
    username: str = "admin",
    crack_range: str = "1000-9999",
    extension_range: str = "100-999",
    device_args: str = "rtl=0",
    timeout: int = 60,
) -> str:
    """Telecom security testing — SIP (SIPVicious) + IMSI detection (gr-gsm).

    - sip_enum: SIP device enumeration (svmap)
    - sip_crack: SIP credential cracking (svcrack; numeric crack_range)
    - sip_flood_test: SIP extension enumeration (svwar; extension_range)
    - imsi_detect: GSM base-station / IMSI-catcher scan (device_args)
    """
    _init_pentest_singletons()
    return await _telecom_attack.execute(
        action=action,
        target=target,
        username=username,
        crack_range=crack_range,
        extension_range=extension_range,
        device_args=device_args,
        timeout=timeout,
    )


@tool
async def evasion(
    action: str,
    payload: str = "windows/meterpreter/reverse_tcp",
    lhost: str = "0.0.0.0",
    lport: int = 4444,
    format: str = "exe",
    encoder: str = "x86/shikata_ga_nai",
    iterations: int = 5,
    output_path: str = "/tmp/payload",
    target_pe: str = "",
    input_file: str = "",
    arch: int = 2,
    loader: str = "binary",
    domain: str = "",
    payload_path: str = "",
    timeout: int = 60,
) -> str:
    """Payload evasion and AV bypass — encoding, obfuscation, detection testing.

    - msfvenom_generate: Generate encoded payload with msfvenom
    - veil_generate: AV-evasive payload with Veil-Framework
    - shellter_inject: Inject shellcode into PE files
    - donut_generate: Position-independent shellcode from PE/.NET
    - scarecrow_generate: EDR-evasive loader generation
    - amsi_test: Test payload against AMSI bypass
    - defender_check: Check if Defender detects payload
    - entropy_analysis: Analyze payload entropy
    """
    _init_pentest_singletons()
    return await _evasion.execute(
        action=action,
        payload=payload,
        lhost=lhost,
        lport=lport,
        format=format,
        encoder=encoder,
        iterations=iterations,
        output_path=output_path,
        target_pe=target_pe,
        input_file=input_file,
        arch=arch,
        loader=loader,
        domain=domain,
        payload_path=payload_path,
        timeout=timeout,
    )


@tool
async def phishing(
    action: str,
    target: str = "",
    campaign_name: str = "",
    template: str = "",
    api_key: str = "",
    campaign_id: str = "",
    phishlet: str = "",
    domain: str = "",
    email_file: str = "",
    dkim_selector: str = "default",
    recipient: str = "",
    sender: str = "",
    ehlo_domain: str = "test.local",
    timeout: int = 30,
) -> str:
    """Phishing simulation — GoPhish, Evilginx, email security.

    - gophish_create_campaign: Create GoPhish phishing campaign
    - gophish_results: Get campaign results
    - evilginx_phishlet: Configure Evilginx phishlet
    - evilginx_lures: Create phishing lure URL
    - email_header_analyze: Analyze email headers for spoofing
    - spf_check: Check SPF records
    - dkim_check: Check DKIM records
    - dmarc_check: Check DMARC policy
    - smtp_relay_test: Test SMTP open relay
    """
    _init_pentest_singletons()
    return await _phishing.execute(
        action=action,
        target=target,
        campaign_name=campaign_name,
        template=template,
        api_key=api_key,
        campaign_id=campaign_id,
        phishlet=phishlet,
        domain=domain,
        email_file=email_file,
        dkim_selector=dkim_selector,
        recipient=recipient,
        sender=sender,
        ehlo_domain=ehlo_domain,
        timeout=timeout,
    )


@tool
async def grpc_audit(
    action: str,
    target: str = "",
    service: str = "",
    method: str = "",
    data: str = "{}",
    auth_header: str = "",
    proto_path: str = ".",
    proto_file: str = "",
    count: int = 1000,
    timeout: int = 30,
) -> str:
    """gRPC and protobuf security testing.

    - grpc_reflection: List services via server reflection
    - grpc_describe: Describe service methods
    - grpc_call: Call a gRPC method with data
    - grpc_fuzz: Fuzz gRPC service methods
    - grpc_auth_test: Test auth bypass on gRPC methods
    - grpc_tls_check: Check TLS enforcement
    - grpc_web_test: Test gRPC-Web endpoint
    - protoscan: Scan for exposed protobuf/gRPC endpoints
    """
    _init_pentest_singletons()
    return await _grpc_audit.execute(
        action=action,
        target=target,
        service=service,
        method=method,
        data=data,
        auth_header=auth_header,
        proto_path=proto_path,
        proto_file=proto_file,
        count=count,
        timeout=timeout,
    )


@tool
async def auth_audit(
    action: str,
    target: str = "",
    client_id: str = "",
    redirect_uri: str = "",
    token: str = "",
    saml_response: str = "",
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    rp_id: str = "",
    timeout: int = 30,
) -> str:
    """Modern authentication security testing.

    - oauth_redirect_test: Test OAuth redirect_uri validation
    - oauth_device_code: Test device code flow phishing
    - oidc_discovery: Enumerate OIDC provider config
    - oidc_token_test: Test OIDC token confusion
    - saml_decode: Decode/analyze SAML response
    - saml_inject: Test SAML signature wrapping
    - jwt_scan: JWT vulnerability scan
    - jwt_crack: Crack JWT HMAC secret
    - webauthn_test: Test WebAuthn/passkey relay
    - session_fixation: Test session fixation
    """
    _init_pentest_singletons()
    return await _auth_audit.execute(
        action=action,
        target=target,
        client_id=client_id,
        redirect_uri=redirect_uri,
        token=token,
        saml_response=saml_response,
        wordlist=wordlist,
        rp_id=rp_id,
        timeout=timeout,
    )


@tool
async def mobile_audit(
    action: str,
    target: str = "",
    package_name: str = "",
    script_path: str = "",
    output_dir: str = "/tmp/mobile_audit",
    timeout: int = 120,
) -> str:
    """Mobile app security testing — APK decompilation, static/dynamic analysis.

    - apk_decompile: Decompile APK with apktool
    - static_analysis: Static analysis via MobSF
    - jadx_decompile: Decompile APK to Java source with jadx
    - drozer_scan: Scan app attack surface with drozer
    - frida_hook: Dynamic instrumentation with Frida
    - ssl_pinning_bypass: Bypass SSL pinning with objection
    - ipc_audit: Audit exported IPC components
    - keychain_dump: Dump Android keystore entries
    """
    _init_pentest_singletons()
    return await _mobile_audit.execute(
        action=action,
        target=target,
        package_name=package_name,
        script_path=script_path,
        output_dir=output_dir,
        timeout=timeout,
    )


@tool
async def supply_chain(
    action: str,
    target: str = "",
    package_name: str = "",
    registry: str = "https://registry.npmjs.org",
    packages_file: str = "",
    scan_type: str = "nodejs",
    timeout: int = 120,
) -> str:
    """Supply chain attack testing — dependency confusion, typosquatting, secrets.

    - dependency_confusion_test: Test for dependency confusion attacks
    - typosquat_scan: Scan for typosquatting packages
    - package_provenance_audit: Audit package provenance and integrity
    - postinstall_audit: Audit postinstall scripts for malicious code
    - trufflehog_scan: Scan git repo for leaked secrets
    - gitleaks_scan: Detect hardcoded secrets with gitleaks
    - depscan: Dependency vulnerability scan
    """
    _init_pentest_singletons()
    return await _supply_chain.execute(
        action=action,
        target=target,
        package_name=package_name,
        registry=registry,
        packages_file=packages_file,
        scan_type=scan_type,
        timeout=timeout,
    )


@tool
async def serverless_audit(
    action: str,
    target: str = "",
    event_type: str = "http",
    provider: str = "aws",
    trigger_type: str = "s3",
    profile: str = "default",
    region: str = "us-east-1",
    concurrency: int = 50,
    timeout: int = 120,
) -> str:
    """Serverless/edge function security testing.

    - lambda_inject_test: Test Lambda event injection
    - edge_function_audit: Audit edge function security
    - event_trigger_abuse: Test event trigger abuse vectors
    - tfstate_scan: Scan Terraform state for exposed secrets
    - iac_security_scan: IaC security scan with checkov
    - serverless_misconfig: Detect serverless misconfigurations
    - cold_start_race: Test cold start race conditions
    """
    _init_pentest_singletons()
    return await _serverless_audit.execute(
        action=action,
        target=target,
        event_type=event_type,
        provider=provider,
        trigger_type=trigger_type,
        profile=profile,
        region=region,
        concurrency=concurrency,
        timeout=timeout,
    )


@tool
async def spa_test(
    action: str,
    target: str = "",
    routes_file: str = "",
    store_type: str = "redux",
    timeout: int = 60,
) -> str:
    """SPA client-side security testing.

    - route_bypass: Test client-side route authorization bypass
    - state_inspect: Inspect exposed client-side state
    - postmessage_scan: Scan for insecure postMessage handlers
    - token_leakage_audit: Audit for token leakage in storage/URLs
    - dom_xss_scan: Scan for DOM-based XSS sinks
    - js_source_map_check: Check for exposed JavaScript source maps
    """
    _init_pentest_singletons()
    return await _spa_test.execute(
        action=action,
        target=target,
        routes_file=routes_file,
        store_type=store_type,
        timeout=timeout,
    )


@tool
async def sdn_attack(
    action: str,
    target: str = "",
    port: int = 8181,
    netconf_port: int = 830,
    openflow_port: int = 6653,
    username: str = "admin",
    password: str = "",
    api_key: str = "",
    timeout: int = 60,
) -> str:
    """SDN/network automation security testing.

    - sdn_controller_enum: Enumerate SDN controllers
    - netconf_exploit: Audit NETCONF for vulnerabilities
    - network_policy_audit: Audit SDN network policies
    - yang_model_enum: Enumerate YANG models
    - restconf_test: Test RESTCONF API security
    - openflow_audit: Audit OpenFlow protocol
    """
    _init_pentest_singletons()
    return await _sdn_attack.execute(
        action=action,
        target=target,
        port=port,
        netconf_port=netconf_port,
        openflow_port=openflow_port,
        username=username,
        password=password,
        api_key=api_key,
        timeout=timeout,
    )


@tool
async def recon_pipeline(
    action: str,
    domain: str = "",
    target: str = "",
    targets_file: str = "",
    output_dir: str = "/tmp/recon_pipeline",
    threads: int = 50,
    severity: str = "medium,high,critical",
    timeout: int = 300,
) -> str:
    """Automated recon pipeline — chained reconnaissance orchestration.

    - full_pipeline: Full recon: subdomains -> probing -> scanning
    - subdomain_httpx: Subdomain discovery + HTTP probing
    - nuclei_scan: Nuclei vulnerability scan
    - screenshot_capture: Capture screenshots of web assets
    - asset_correlate: Correlate and deduplicate assets
    - attack_graph_build: Build attack graph from recon data
    - tech_detect: Technology detection on endpoints
    """
    _init_pentest_singletons()
    return await _recon_pipeline.execute(
        action=action,
        domain=domain,
        target=target,
        targets_file=targets_file,
        output_dir=output_dir,
        threads=threads,
        severity=severity,
        timeout=timeout,
    )


@tool
async def wifi_intel(
    action: str,
    interface: str = "wlan1",
    monitor_interface: str = "wlan1mon",
    band: str = "2.4",
    channels: str = "",
    duration: int = 60,
    bssid: str = "",
    bssid_filter: str = "",
    channel: int = 0,
    ssid: str = "",
) -> str:
    """Alfa WiFi adapter control — passive landscape surveys and targeted WPA capture.

    Actions: monitor_start (enable monitor mode), monitor_stop (return to managed mode),
    survey (channel-hopping airodump-ng scan, ingests all APs + stations into target_intel),
    capture_pmkid (hcxdumptool passive PMKID/EAPOL → hashcat .hc22000),
    capture_handshake (targeted WPA handshake via deauth + airodump-ng),
    signal_history (query RSSI history for a BSSID from target_intel),
    export (dump all known WiFi networks from target_intel + list capture files).
    """
    _init_pentest_singletons()
    return await _wifi_intel.execute(
        action=action,
        interface=interface,
        monitor_interface=monitor_interface,
        band=band,
        channels=channels or None,
        duration=duration,
        bssid=bssid,
        bssid_filter=bssid_filter,
        channel=channel,
        ssid=ssid,
    )


@tool
async def traffic_analysis(
    action: str,
    interface: str = "eth0",
    duration: int = 60,
    filter: str = "",
    pcap_file: str = "",
    output_dir: str = "",
    analysis_type: str = "all",
    target_ip: str = "",
    gateway_ip: str = "",
    listen_port: int = 8080,
    packet_count: int = 0,
) -> str:
    """Packet capture and traffic analysis for networks you own or have authorization to test.

    - pcap_capture: Live packet capture to file (tcpdump). Params: interface, duration, filter, packet_count.
    - pcap_parse: Analyse an existing pcap — flows, protocols, suspicious patterns (tshark).
      Params: pcap_file, analysis_type (flows|protocols|suspicious|all).
    - session_reconstruct: Reassemble TCP streams and extract HTTP sessions (tcpflow).
      Params: pcap_file, output_dir.
    - cleartext_harvest: Extract credentials from HTTP Basic auth, FTP, Telnet, MQTT, SNMP.
      Params: pcap_file.
    - tls_intercept: Transparent HTTPS interception via ARP spoof + mitmproxy (own devices only).
      Params: interface, target_ip, gateway_ip, listen_port, duration.
    """
    _init_pentest_singletons()
    return await _traffic_analysis.execute(
        action=action,
        interface=interface,
        duration=duration,
        filter=filter,
        pcap_file=pcap_file,
        output_dir=output_dir,
        analysis_type=analysis_type,
        target_ip=target_ip,
        gateway_ip=gateway_ip,
        listen_port=listen_port,
        packet_count=packet_count,
    )


def get_engagement_manager() -> EngagementManager:
    """Return the EngagementManager singleton (lazy-inits if needed)."""
    _init_pentest_singletons()
    return _engagement


def get_target_store() -> TargetStore:
    """Return the TargetStore singleton (lazy-inits if needed)."""
    _init_pentest_singletons()
    return _target_store


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
        opsec,
        # Phase 2 — Recon (internal + external)
        dns_enum,
        subdomain_discovery,
        osint_recon,
        maigret,
        phoneinfoga,
        holehe,
        external_recon,
        perimeter_audit,
        # Phase 2 — Enumeration
        web_enum,
        service_enum,
        lan_scan,
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
        # Phase 2 — Playbook system + orchestration
        playbook,
        orchestrator,
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
        # Tier 2 — CI/CD, IPv6, IoT, AD
        cicd_audit,
        ipv6_attack,
        iot_protocol,
        iot_audit,
        ad_attack,
        # Tier 3 — LLM, Telecom, Evasion, Phishing, gRPC, Auth
        llm_audit,
        telecom_attack,
        evasion,
        phishing,
        grpc_audit,
        auth_audit,
        # Tier 4 — Mobile, Supply Chain, Serverless, SPA, SDN, Recon
        mobile_audit,
        supply_chain,
        serverless_audit,
        spa_test,
        sdn_attack,
        recon_pipeline,
        # WiFi Intel — Alfa adapter surveys and WPA capture
        wifi_intel,
        # Traffic analysis — packet capture, session reconstruction, credential harvesting
        traffic_analysis,
    ]


def get_combined_tools(knowledge_store=None):
    """Get all tools (security + pentest) as LangChain tool objects."""
    return get_security_tools(knowledge_store) + get_pentest_tools()


# ── Deferred tools (ADR 0005 #3 — progressive tool disclosure) ────────────────

SEARCH_TOOLS_NAME = "search_tools"

# Always exposed to the model when deferral is on: the orchestration/delegation
# tools, the agent's task + schedule management loop, and the search meta-tool
# itself — enough to operate and to *discover* the rest. Everything else (the
# ~70 security/pentest domain tools) is deferred until searched. protoPen has no
# keyless utility tools (current_time/web_search/etc.), so the base is its
# working-loop core. Override via `tools.deferred.keep`.
DEFERRED_BASE_TOOL_NAMES = frozenset(
    {
        "task",
        "run_workflow",
        "save_workflow",
        "save_skill",
        "load_skill",
        "create_task",
        "list_tasks",
        "update_task",
        "close_task",
        "schedule_task",
        "list_schedules",
        "cancel_schedule",
        "wait",
        SEARCH_TOOLS_NAME,
    }
)


def resolve_deferred_keep(configured_keep) -> set[str]:
    """Resolve the always-on tool set for deferral: the configured override (if
    any) else the built-in base. ``search_tools`` is always kept — without it the
    agent could never load anything back."""
    keep = {str(n) for n in (configured_keep or [])} or set(DEFERRED_BASE_TOOL_NAMES)
    keep.add(SEARCH_TOOLS_NAME)
    return keep


def _tool_summary(t) -> str:
    """First non-empty line of a tool's description, truncated."""
    desc = (getattr(t, "description", "") or "").strip()
    first = next((ln.strip() for ln in desc.splitlines() if ln.strip()), "")
    return (first[:119].rstrip() + "…") if len(first) > 120 else first


def build_search_tools_tool(all_tools, keep_names):
    """Build the ``search_tools`` meta-tool over the *deferred* tools.

    It keyword-matches the deferred tools (everything not in ``keep_names``) by
    name + description and returns matches as a backticked bulleted list. The
    ``ToolDeferralMiddleware`` reads those backticked names from the result and
    binds the matched tools on subsequent turns (progressive disclosure).
    """
    keep = set(keep_names)
    catalog = [(t.name, _tool_summary(t)) for t in all_tools if getattr(t, "name", None) and t.name not in keep]

    def _render(pairs, header) -> str:
        lines = [header]
        for name, summary in pairs:
            lines.append(f"- `{name}` — {summary}" if summary else f"- `{name}`")
        return "\n".join(lines)

    @tool
    def search_tools(query: str = "", limit: int = 10) -> str:
        """Find and load additional tools by capability.

        Most tools are not shown up-front, to keep your working context focused.
        When your visible tools don't cover the task, call this with a few
        keywords describing what you need (e.g. "nmap port scan", "crack hashes",
        "search CVEs", "wifi capture"). Matching tools become available to call
        on your next step. Leave ``query`` empty to browse available tools (up to
        ``limit``); raise ``limit`` to see more. Returns ``name — purpose`` lines.
        """
        if not catalog:
            return "No additional tools are available beyond the ones already shown."
        terms = (query or "").lower().split()
        lim = max(1, min(int(limit or 10), 50))
        if not terms:
            header = f"Additional tools (showing {min(lim, len(catalog))} of {len(catalog)}) — now available to call:"
            return _render(catalog[:lim], header)
        scored = []
        for name, summary in catalog:
            hay = f"{name} {summary}".lower()
            score = sum(hay.count(term) for term in terms)
            if score:
                scored.append((score, name, summary))
        if not scored:
            return _render(
                catalog[:lim],
                f'No tool matched "{query}". Here are the available tools (now callable):',
            )
        scored.sort(key=lambda r: (-r[0], r[1]))
        shown = [(n, s) for _, n, s in scored[:lim]]
        return _render(shown, f'Found {len(shown)} tool(s) for "{query}" — now available to call:')

    return search_tools
