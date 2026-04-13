"""Parser for Flipper Zero nfc/rfid/subghz output."""
from tools.parsers import PARSER_MAP

def parse_nfc(raw, store):
    return []

def parse_rfid(raw, store):
    return []

def parse_subghz(raw, store):
    return []

PARSER_MAP[("flipper", "nfc_detect")] = parse_nfc
PARSER_MAP[("flipper", "rfid_read")] = parse_rfid
PARSER_MAP[("flipper", "subghz_rx")] = parse_subghz
