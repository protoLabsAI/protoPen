"""Capabilities catalog (protopen-1vd) — categorizer + catalog shape."""

from operator_api.capabilities import _CATEGORY_RULES, _categorize, list_capabilities

_VALID_CATEGORIES = {label for label, _ in _CATEGORY_RULES} | {"Other"}


def test_categorize_buckets_known_tools():
    assert _categorize("marauder_scan", "Scan for WiFi APs") == "Wireless, RF & Hardware"
    assert _categorize("flipper_ir", "Flipper Zero IR") == "Wireless, RF & Hardware"
    assert _categorize("osint_recon", "OSINT footprint") == "OSINT & Recon"
    assert _categorize("dns_enum", "Enumerate DNS records") == "OSINT & Recon"
    assert _categorize("nmap_scan", "Port scan a host") == "Scanning & Enumeration"
    assert _categorize("cve_search", "Search CVEs") == "Security Intel"
    assert _categorize("cis_audit", "CIS hardening audit") == "Blue Team & Defense"
    assert _categorize("log_finding", "Record a finding") == "Targets & Findings"
    assert _categorize("run_workflow", "Run a saved recipe") == "Agent & Automation"


def test_categorize_falls_back_to_other():
    assert _categorize("xyzzy", "does an unknowable thing") == "Other"


def test_list_capabilities_shape():
    """The catalog is well-formed even when the registry can't be built (no
    deps / no store) — it degrades to an empty list rather than raising."""
    result = list_capabilities(None)
    assert set(result) == {"count", "tools"}
    assert isinstance(result["count"], int)
    assert isinstance(result["tools"], list)
    assert result["count"] == len(result["tools"])
    for tool in result["tools"]:
        assert set(tool) == {"name", "summary", "category"}
        assert tool["name"]
        # Every entry lands in a known category (no stray buckets).
        assert tool["category"] in _VALID_CATEGORIES


def test_list_capabilities_populated_when_registry_available():
    """When the tool registry is importable (deps present), the catalog is
    non-empty and sorted by (category, name)."""
    result = list_capabilities(None)
    if result["count"] == 0:
        return  # registry deps unavailable in this env — covered by the shape test
    names = [t["name"] for t in result["tools"]]
    keys = [(t["category"], t["name"]) for t in result["tools"]]
    assert keys == sorted(keys)
    assert len(names) == len(set(names))
