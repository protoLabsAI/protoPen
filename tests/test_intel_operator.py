"""Targets & Intel operator contracts — list/get targets, history, unified search.

Read-only wrappers over the target store + engagement workspaces (operator_api/
intel.py). Secrets are redacted; engagement history is read from on-disk
workspaces with zero agent-behaviour change.
"""

from __future__ import annotations

import json

import pytest

from knowledge.target_store import TargetStore
from operator_api import intel


@pytest.fixture
def store(tmp_path):
    ts = TargetStore(str(tmp_path / "targets.db"))
    hid = ts.upsert_host(ip="192.168.1.10", hostname="gw", os="Linux", device_type="router")
    ts.upsert_port(hid, 22, service="ssh")
    ts.upsert_port(hid, 443, service="https")
    ts.add_findings(
        tool="nmap",
        action="scan",
        entities=[
            {
                "target": "192.168.1.10",
                "title": "weak ssh cipher",
                "severity": "medium",
                "category": "crypto",
                "value": "cbc enabled",
            },
            {"target": "gw", "title": "default creds", "severity": "high", "category": "auth", "value": "admin/admin"},
        ],
    )
    ts.add_credential(username="admin", password="hunter2", source="brute", host_id=hid, cracked=True)
    # A second, unrelated host so device-type filtering is meaningful.
    ts.upsert_host(ip="192.168.1.42", hostname="phone-1", device_type="phone")
    return ts, hid


# ── list_targets ──────────────────────────────────────────────────────────────


def test_list_targets_rollups(store):
    ts, hid = store
    out = intel.list_targets(ts)
    assert out["count"] == 2
    gw = next(t for t in out["targets"] if t["id"] == hid)
    assert gw["port_count"] == 2
    # both findings correlate to the host via ip ("192.168.1.10") and hostname ("gw")
    assert gw["finding_count"] == 2
    assert any("22/tcp" in p for p in gw["open_ports"])


def test_list_targets_query_and_device_filter(store):
    ts, _ = store
    assert intel.list_targets(ts, query="phone")["count"] == 1
    assert intel.list_targets(ts, device_type="router")["count"] == 1
    assert intel.list_targets(ts, device_type="server")["count"] == 0


def test_list_targets_tolerates_missing_store():
    assert intel.list_targets(None)["count"] == 0


# ── get_target ────────────────────────────────────────────────────────────────


def test_get_target_full_profile_redacts_secret(store):
    ts, hid = store
    d = intel.get_target(ts, hid)
    assert len(d["ports"]) == 2
    assert len(d["findings"]) == 2
    cred = d["credentials"][0]
    assert cred["username"] == "admin"
    assert cred["cracked"] is True
    assert cred["has_secret"] is True
    # The raw secret must never be surfaced to the console.
    assert "password" not in cred
    assert "hunter2" not in json.dumps(d)


def test_get_target_not_found_raises(store):
    ts, _ = store
    with pytest.raises(ValueError):
        intel.get_target(ts, 9999)


def test_has_secret_false_when_only_hash_type_label(tmp_path):
    """``hash_type`` is metadata — without a stored password/hash value there is
    no secret, so ``has_secret`` must be False (don't over-report)."""
    ts = TargetStore(str(tmp_path / "t.db"))
    hid = ts.upsert_host(ip="10.0.0.5")
    ts.add_credential(username="svc", password="", hash_type="ntlm", host_id=hid)
    cred = intel.get_target(ts, hid)["credentials"][0]
    assert cred["hash_type"] == "ntlm"
    assert cred["has_secret"] is False


# ── search_intel ──────────────────────────────────────────────────────────────


def test_search_intel_spans_hosts_and_findings(store):
    ts, _ = store
    out = intel.search_intel(ts, None, query="ssh")
    kinds = {h["kind"] for h in out["hits"]}
    assert "finding" in kinds  # "weak ssh cipher"
    # results are score-sorted descending
    scores = [h["score"] for h in out["hits"]]
    assert scores == sorted(scores, reverse=True)


def test_search_intel_host_match(store):
    ts, _ = store
    out = intel.search_intel(ts, None, query="gw")
    assert any(h["kind"] == "host" for h in out["hits"])


def test_search_intel_requires_query(store):
    ts, _ = store
    with pytest.raises(ValueError):
        intel.search_intel(ts, None, query="   ")


def test_search_intel_folds_in_knowledge():
    class _FakeKnowledge:
        def hybrid_search(self, query, k=10, filter_table=None):
            return [{"table": "cves", "source_id": "CVE-2024-1", "preview": "ssh overflow"}]

    out = intel.search_intel(None, _FakeKnowledge(), query="ssh")
    assert any(h["kind"] == "cve" and h["source"] == "knowledge" for h in out["hits"])


# ── list_engagement_history ───────────────────────────────────────────────────


def _write_engagement(root, name, *, mode, started, ended="", findings=None):
    d = root / name
    d.mkdir(parents=True)
    meta = {"name": name, "scope": f"{name}-scope", "mode": mode, "started_at": started}
    if ended:
        meta["ended_at"] = ended
    (d / "engagement.json").write_text(json.dumps(meta))
    if findings is not None:
        (d / "findings.json").write_text(json.dumps(findings))


def test_engagement_history_reads_disk_workspaces(tmp_path):
    root = tmp_path / "engagements"
    _write_engagement(
        root,
        "apt-sim",
        mode="REDTEAM",
        started="2026-05-01T00:00:00Z",
        ended="2026-05-02T00:00:00Z",
        findings=[{"severity": "high"}, {"severity": "high"}, {"severity": "low"}],
    )
    _write_engagement(root, "live-eng", mode="PASSIVE", started="2026-05-30T00:00:00Z")

    out = intel.list_engagement_history(str(root), active_name="live-eng")
    assert out["count"] == 2
    # newest-started first
    assert [e["name"] for e in out["engagements"]] == ["live-eng", "apt-sim"]
    live = next(e for e in out["engagements"] if e["name"] == "live-eng")
    done = next(e for e in out["engagements"] if e["name"] == "apt-sim")
    assert live["active"] is True
    assert done["active"] is False
    assert done["finding_count"] == 3
    assert done["finding_counts"]["high"] == 2


def test_engagement_history_tolerates_missing_and_corrupt(tmp_path):
    assert intel.list_engagement_history("")["count"] == 0
    assert intel.list_engagement_history(str(tmp_path / "nope"))["count"] == 0

    root = tmp_path / "engagements"
    (root / "broken").mkdir(parents=True)
    (root / "broken" / "engagement.json").write_text("{not json")
    (root / "stray-file").mkdir(parents=True)  # dir without engagement.json
    assert intel.list_engagement_history(str(root))["count"] == 0
