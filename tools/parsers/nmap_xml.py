"""Parser for nmap -oX - XML output."""
from tools.parsers import PARSER_MAP

def parse(raw, store):
    return []

PARSER_MAP[("blackarch", "nmap_scan")] = parse
PARSER_MAP[("blackarch", "nmap_vuln_scan")] = parse
