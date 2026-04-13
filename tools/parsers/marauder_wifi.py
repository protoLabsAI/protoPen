"""Parser for ESP32 Marauder scan_aps / scan_stations output."""
from tools.parsers import PARSER_MAP

def parse_aps(raw, store):
    return []

def parse_stations(raw, store):
    return []

PARSER_MAP[("marauder", "scan_aps")] = parse_aps
PARSER_MAP[("marauder", "scan_stations")] = parse_stations
