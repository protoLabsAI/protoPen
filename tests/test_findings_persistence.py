"""TargetStore.findings table + ingest_output central persistence."""

from __future__ import annotations

import tools.parsers as P
from knowledge.target_store import TargetStore
from tools.parsers import ingest_output


def _store(tmp_path) -> TargetStore:
    return TargetStore(db_path=str(tmp_path / "targets.db"))


def test_add_findings_and_get(tmp_path) -> None:
    store = _store(tmp_path)
    n = store.add_findings(
        tool="supply_chain",
        action="dependency_confusion_test",
        entities=[
            {
                "type": "supply_chain_finding",
                "target": "@acme/x",
                "severity": "critical",
                "value": "internal=1 public=9",
            },
            {"type": "supply_chain_finding", "target": "@acme/y", "severity": "high", "value": "..."},
        ],
    )
    assert n == 2
    rows = store.get_findings(tool="supply_chain")
    assert len(rows) == 2
    assert rows[0]["tool"] == "supply_chain"
    assert rows[0]["action"] == "dependency_confusion_test"
    # Newest first
    assert {r["target"] for r in rows} == {"@acme/x", "@acme/y"}


def test_add_findings_skips_non_dicts(tmp_path) -> None:
    store = _store(tmp_path)
    n = store.add_findings(tool="t", action="a", entities=["not a dict", {"target": "h", "type": "x"}])
    assert n == 1


def test_add_findings_empty(tmp_path) -> None:
    assert _store(tmp_path).add_findings(tool="t", action="a", entities=[]) == 0


def test_get_entities_reads_back_entity_json(tmp_path) -> None:
    store = _store(tmp_path)
    store.add_findings(
        tool="sdn_attack",
        action="sdn_controller_enum",
        entities=[{"type": "sdn_finding", "target": "10.0.0.1", "value": "OpenDaylight", "extra": {"nested": 1}}],
    )
    entities = store.get_entities("10.0.0.1")
    assert len(entities) == 1
    assert entities[0]["type"] == "sdn_finding"
    assert entities[0]["extra"] == {"nested": 1}  # full entity JSON round-trips
    assert store.get_entities("nope") == []


def test_ingest_output_persists_returned_entities(tmp_path) -> None:
    store = _store(tmp_path)
    key = ("faketool", "probe")

    def _parser(raw, _store):
        return [{"type": "fake_finding", "target": "host-1", "severity": "low", "value": raw}]

    P.PARSER_MAP[key] = _parser
    try:
        result = ingest_output("faketool", "probe", "hello", store)
    finally:
        P.PARSER_MAP.pop(key, None)

    assert result and result[0]["target"] == "host-1"
    rows = store.get_findings(tool="faketool")
    assert len(rows) == 1
    assert rows[0]["value"] == "hello"


def test_ingest_output_noop_without_store() -> None:
    assert ingest_output("faketool", "probe", "x", None) == []
