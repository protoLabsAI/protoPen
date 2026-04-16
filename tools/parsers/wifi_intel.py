"""Parser for wifi_intel tool output — airodump-ng survey and export actions."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from tools.parsers import PARSER_MAP

if TYPE_CHECKING:
    from knowledge.target_store import TargetStore

logger = logging.getLogger(__name__)


def parse_survey(raw: str, store: "TargetStore") -> list[dict]:
    """Parse wifi_intel survey JSON and upsert all APs into target_intel.

    The survey action returns a JSON string with an 'aps' list.  Each AP
    has: bssid, ssid, channel, rssi, encryption.
    """
    entities: list[dict] = []
    if not raw:
        return entities
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        logger.warning("wifi_intel/survey: non-JSON output, skipping parse")
        return entities

    aps = data.get("aps", [])
    for ap in aps:
        bssid = ap.get("bssid", "")
        if not bssid:
            continue
        store.upsert_wifi_network(
            bssid=bssid,
            ssid=ap.get("ssid", ""),
            channel=int(ap.get("channel", 0) or 0),
            rssi=int(ap.get("rssi", 0) or 0),
            encryption=ap.get("encryption", ""),
        )
        entities.append(
            {
                "type": "wifi_network",
                "bssid": bssid,
                "ssid": ap.get("ssid", ""),
                "channel": ap.get("channel", 0),
                "rssi": ap.get("rssi", 0),
                "encryption": ap.get("encryption", ""),
            }
        )
    return entities


def parse_export(raw: str, store: "TargetStore") -> list[dict]:
    """Stub — export output is already fully-materialized; nothing to ingest."""
    return []


PARSER_MAP[("wifi_intel", "survey")] = parse_survey
PARSER_MAP[("wifi_intel", "export")] = parse_export
