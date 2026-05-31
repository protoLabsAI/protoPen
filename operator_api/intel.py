"""Targets, engagement history, and unified intel search for the operator console.

protoPen-specific. The agent captures a lot — discovered hosts/ports/services and
generic findings in the target store, threat intel in the knowledge store, and a
per-engagement audit trail on disk — but only the live engagement was ever
surfaced. This module wraps the existing stores into UI-safe, read-only contracts
so the console can browse targets, review past engagements, and search across
everything captured.

Read-only by design: no store writes, no agent-behaviour change — it just exposes
what's already persisted. Secrets (credential passwords/hashes) are redacted to a
presence flag; the operator surface shows that a credential exists, not its value.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Knowledge tables → a stable "kind" tag for unified search results.
_KNOWLEDGE_KINDS = {
    "cves": "cve",
    "exploits": "exploit",
    "advisories": "advisory",
    "threat_intel": "threat_intel",
    "topics": "topic",
    "digests": "digest",
}


def _host_targets(host: dict) -> list[str]:
    """Strings a finding's ``target`` might use to refer to this host (ip, hostname)."""
    return [str(host.get(k, "")) for k in ("ip", "hostname") if host.get(k)]


def _port_brief(port: dict) -> str:
    svc = str(port.get("service", "") or "")
    num = port.get("port", "")
    return f"{num}/{port.get('protocol', 'tcp')}{f' {svc}' if svc else ''}".strip()


def _host_summary(store: Any, host: dict) -> dict[str, Any]:
    """One row in the targets list: host identity + port/finding rollups."""
    host_id = host.get("id")
    ports = store.get_ports(host_id) if host_id is not None else []
    open_ports = [p for p in ports if str(p.get("state", "open")) == "open"]
    findings = store.findings_for_targets(_host_targets(host)) if host_id is not None else []
    tags = host.get("tags")
    try:
        tags = json.loads(tags) if isinstance(tags, str) else (tags or [])
    except (json.JSONDecodeError, TypeError):
        tags = []
    return {
        "id": host_id,
        "ip": host.get("ip", "") or "",
        "mac": host.get("mac", "") or "",
        "hostname": host.get("hostname", "") or "",
        "os": host.get("os", "") or "",
        "vendor": host.get("vendor", "") or "",
        "device_type": host.get("device_type", "unknown") or "unknown",
        "tags": tags if isinstance(tags, list) else [],
        "first_seen": host.get("first_seen", "") or "",
        "last_seen": host.get("last_seen", "") or "",
        "port_count": len(open_ports),
        "open_ports": [_port_brief(p) for p in open_ports[:12]],
        "finding_count": len(findings),
    }


def list_targets(
    store: Any,
    *,
    query: str = "",
    device_type: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """List discovered hosts (newest-seen first) with port + finding rollups.

    Tolerant of a missing store (returns an empty list) so the console degrades
    gracefully when the target subsystem isn't initialised.
    """
    limit = max(1, min(int(limit or 50), 200))
    if store is None:
        return {"query": query or "", "count": 0, "targets": []}

    hosts = store.search_hosts(query or "", limit=limit)
    if device_type:
        hosts = [h for h in hosts if str(h.get("device_type", "")) == device_type]
    targets = [_host_summary(store, h) for h in hosts]
    return {"query": query or "", "count": len(targets), "targets": targets}


def get_target(store: Any, host_id: int) -> dict[str, Any]:
    """Full profile for one host: identity, ports, findings, redacted credentials.

    Raises ValueError if the host doesn't exist so the route returns 404/400.
    """
    if store is None:
        raise ValueError("target store is not loaded")
    host = store.get_host(int(host_id))
    if not host:
        raise ValueError(f"target {host_id} not found")

    summary = _host_summary(store, host)
    ports = store.get_ports(host_id)
    findings = store.findings_for_targets(_host_targets(host))
    creds = store.credentials_for_host(host_id)

    summary["notes"] = host.get("notes", "") or ""
    summary["ports"] = [
        {
            "port": p.get("port"),
            "protocol": p.get("protocol", "tcp"),
            "state": p.get("state", ""),
            "service": p.get("service", "") or "",
            "banner": p.get("banner", "") or "",
            "last_seen": p.get("last_seen", "") or "",
        }
        for p in ports
    ]
    summary["findings"] = [
        {
            "tool": f.get("tool", "") or "",
            "category": f.get("category", "") or "",
            "severity": f.get("severity", "") or "",
            "title": f.get("title", "") or "",
            "value": f.get("value", "") or "",
            "first_seen": f.get("first_seen", "") or "",
        }
        for f in findings[:200]
    ]
    # Credentials: presence + metadata only; the raw secret is never sent to the UI.
    summary["credentials"] = [
        {
            "username": c.get("username", "") or "",
            "hash_type": c.get("hash_type", "") or "",
            "cracked": bool(c.get("cracked")),
            "has_secret": bool(c.get("password") or c.get("hash_type")),
            "source": c.get("source", "") or "",
            "first_seen": c.get("first_seen", "") or "",
        }
        for c in creds
    ]
    return summary


def _read_engagement_dir(path: Path) -> dict[str, Any] | None:
    """Read one engagement workspace (engagement.json + findings.json) → summary."""
    meta_file = path / "engagement.json"
    if not meta_file.is_file():
        return None
    try:
        meta = json.loads(meta_file.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(meta, dict):
        return None

    findings: list[dict] = []
    findings_file = path / "findings.json"
    if findings_file.is_file():
        try:
            loaded = json.loads(findings_file.read_text())
            if isinstance(loaded, list):
                findings = [f for f in loaded if isinstance(f, dict)]
        except (OSError, json.JSONDecodeError):
            findings = []

    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    ordered = {s: counts[s] for s in _SEVERITY_ORDER if s in counts}
    ordered.update({k: v for k, v in counts.items() if k not in _SEVERITY_ORDER})

    return {
        "name": str(meta.get("name", path.name)),
        "scope": str(meta.get("scope", "") or ""),
        "mode": str(meta.get("mode", "") or ""),
        "started_at": str(meta.get("started_at", "") or ""),
        "ended_at": str(meta.get("ended_at", "") or ""),
        "finding_count": len(findings),
        "finding_counts": ordered,
        "active": False,
    }


def list_engagement_history(
    workspace_root: str,
    *,
    active_name: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """List past engagements from their on-disk workspaces (newest-started first).

    Each ``start()`` writes ``<workspace_root>/<name>/engagement.json`` and ``end()``
    writes ``findings.json`` — this enumerates them read-only. The currently active
    engagement (if any) is flagged via ``active_name``.
    """
    root = Path(workspace_root) if workspace_root else None
    if root is None or not root.is_dir():
        return {"count": 0, "engagements": []}

    engagements: list[dict[str, Any]] = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        summary = _read_engagement_dir(child)
        if summary is None:
            continue
        if active_name and summary["name"] == active_name and not summary["ended_at"]:
            summary["active"] = True
        engagements.append(summary)

    engagements.sort(key=lambda e: e.get("started_at", ""), reverse=True)
    return {"count": len(engagements), "engagements": engagements[: max(1, int(limit or 100))]}


def _knowledge_hits(store: Any, query: str, k: int) -> list[dict[str, Any]]:
    if store is None:
        return []
    try:
        raw = store.hybrid_search(query, k=k) or []
    except Exception:
        return []
    total = len(raw)
    hits = []
    for rank, item in enumerate(raw):
        table = str(item.get("table", ""))
        hits.append(
            {
                "kind": _KNOWLEDGE_KINDS.get(table, table or "knowledge"),
                "source": "knowledge",
                "id": str(item.get("source_id", "")),
                "title": str(item.get("source_id", "")),
                "target": "",
                "preview": str(item.get("preview", ""))[:400],
                "score": round((total - rank) / total, 4) if total else 0.0,
            }
        )
    return hits


def search_intel(
    target_store: Any,
    knowledge_store: Any,
    *,
    query: str,
    k: int = 20,
) -> dict[str, Any]:
    """Unified search across captured intel: hosts, target findings, knowledge.

    Returns rank-tagged hits with a stable ``kind`` and ``source`` so the console
    can render and group them. Each source is capped at ``k`` and the knowledge
    store keeps its hybrid (vector + BM25) ranking; host/finding matches are
    LIKE-based, scored by recency.
    """
    cleaned = (query or "").strip()
    if not cleaned:
        raise ValueError("query is required")
    k = max(1, min(int(k or 20), 50))

    hits: list[dict[str, Any]] = []

    if target_store is not None:
        hosts = target_store.search_hosts(cleaned, limit=k)
        for rank, h in enumerate(hosts):
            label = h.get("hostname") or h.get("ip") or h.get("mac") or "host"
            descr = " · ".join(
                x for x in (h.get("ip"), h.get("os"), h.get("device_type")) if x and x != "unknown"
            )
            hits.append(
                {
                    "kind": "host",
                    "source": "targets",
                    "id": str(h.get("id", "")),
                    "title": str(label),
                    "target": str(h.get("ip", "") or h.get("mac", "")),
                    "preview": descr,
                    "score": round((len(hosts) - rank) / len(hosts), 4) if hosts else 0.0,
                }
            )

        findings = target_store.search_findings(cleaned, limit=k)
        for rank, f in enumerate(findings):
            preview = str(f.get("value", "") or f.get("category", ""))[:400]
            hits.append(
                {
                    "kind": "finding",
                    "source": "targets",
                    "id": str(f.get("id", "")),
                    "title": str(f.get("title", "") or f.get("category", "") or "finding"),
                    "target": str(f.get("target", "") or ""),
                    "preview": preview,
                    "score": round((len(findings) - rank) / len(findings), 4) if findings else 0.0,
                }
            )

    hits.extend(_knowledge_hits(knowledge_store, cleaned, k))

    hits.sort(key=lambda h: h["score"], reverse=True)
    return {"query": cleaned, "count": len(hits), "hits": hits}
