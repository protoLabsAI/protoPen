"""Aux-model routing — one cheap alias for the non-reasoning calls."""

from __future__ import annotations

import yaml

from graph.agent import _resolve_aux_model
from graph.config import LangGraphConfig


def test_resolve_aux_model_precedence():
    """specific override > routing.aux_model > main model (None)."""
    cfg = LangGraphConfig()
    assert _resolve_aux_model(cfg, "") is None  # nothing set → main model
    cfg.aux_model = "protolabs/fast"
    assert _resolve_aux_model(cfg, "") == "protolabs/fast"  # falls back to aux
    assert _resolve_aux_model(cfg, "explicit") == "explicit"  # specific wins
    assert _resolve_aux_model(cfg, "  ") == "protolabs/fast"  # blank/whitespace → aux


def test_aux_model_parsed_from_routing_yaml(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"routing": {"aux_model": "protolabs/fast"}}))
    cfg = LangGraphConfig.from_yaml(p)
    assert cfg.aux_model == "protolabs/fast"


def test_empty_routing_section_does_not_crash(tmp_path):
    """`routing:` with everything commented parses to None — must not crash."""
    p = tmp_path / "c.yaml"
    p.write_text("routing:\n")  # key present, value None
    cfg = LangGraphConfig.from_yaml(p)
    assert cfg.aux_model == ""  # falls back to the default


def test_subagent_model_override_field_defaults_blank():
    from graph.subagents.config import SUBAGENT_REGISTRY

    # Every registered subagent gains the optional override, blank by default.
    assert all(getattr(sub, "model", None) == "" for sub in SUBAGENT_REGISTRY.values())
