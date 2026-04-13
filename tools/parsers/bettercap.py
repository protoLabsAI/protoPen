"""Parser for bettercap net.show ASCII table output."""
from tools.parsers import PARSER_MAP

def parse(raw, store):
    return []

PARSER_MAP[("blackarch", "bettercap_recon")] = parse
