# Auto-Ingestion

protoPen automatically parses tool output and stores structured entities in the target intelligence database. This means scan results from nmap, bettercap, Marauder, and Flipper Zero are immediately queryable -- without the agent needing to manually extract and store each host, port, or network.

## How It Works

### Parser Dispatch

The parser registry (`tools/parsers/__init__.py`) maps `(tool_name, action)` tuples to parser functions:

```python
PARSER_MAP: dict[tuple[str, str], callable] = {}
```

After every tool execution, the `ingest_output()` function checks for a matching parser:

```python
def ingest_output(tool_name, action, raw, store):
    parser = PARSER_MAP.get((tool_name, action))
    if parser is None:
        return []  # no parser registered -- skip
    return parser(raw, store)
```

### Post-Hook in BlackArchTool

The `BlackArchTool.execute()` method calls `ingest_output()` as a post-hook after every action completes. For example, after an `nmap_scan`, the raw XML output is routed to the nmap parser, which extracts hosts, ports, and services into the `TargetStore`.

### EngagementManager Auto-Extract

The `EngagementManager.log_finding()` method includes a lightweight auto-extraction step. After every finding is logged, it scans the finding detail text for IP addresses and MAC addresses using regex patterns, then upserts them into the target store:

```
IP pattern:  \b(?:\d{1,3}\.){3}\d{1,3}\b
MAC pattern: \b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b
```

This ensures that even free-text findings contribute to the target intelligence picture.

## Registered Parsers

### nmap XML Parser

**File:** `tools/parsers/nmap_xml.py`

**Registered for:** `("blackarch", "nmap_scan")`, `("blackarch", "nmap_vuln_scan")`

Parses nmap's XML output format (`-oX`). Extracts:

- **Hosts**: IP, MAC, hostname, OS detection results
- **Ports**: Port number, protocol, state, service name, banner
- **Vendor**: OUI-based vendor identification from MAC addresses

Each host is upserted (merge-on-conflict) into the `hosts` table, and each port is upserted into the `ports` table linked to its host.

### bettercap Table Parser

**File:** `tools/parsers/bettercap.py`

**Registered for:** `("blackarch", "bettercap_recon")`

Parses bettercap's tabular text output (the default display format). Extracts:

- **Hosts**: IP, MAC, hostname, vendor
- **Services**: Detected network services

### Marauder WiFi Parser (stub)

**File:** `tools/parsers/marauder_wifi.py`

**Registered for:** `("marauder", "scan_aps")`, `("marauder", "scan_stations")`

Parses Marauder's serial output for WiFi scan results. Extracts:

- **WiFi networks**: BSSID, SSID, channel, RSSI, encryption
- **WiFi stations**: MAC, associated network, RSSI, probed SSIDs

### Flipper RF Parser (stub)

**File:** `tools/parsers/flipper_rf.py`

**Registered for:** `("flipper", "subghz_rx")`

Parses Flipper Zero's Sub-GHz receive output. Extracts:

- **RF signals**: Frequency, protocol, data, modulation

## Design Rationale

The parser dispatch pattern has several advantages:

1. **Separation of concerns**: Tool classes handle device communication; parsers handle data extraction
2. **Graceful degradation**: Missing or failing parsers are logged and swallowed -- they never break tool execution
3. **Extensibility**: Adding a new parser requires only writing the parse function and registering it in `PARSER_MAP`
4. **Consistency**: All sensor data flows into the same `TargetStore` tables regardless of source, enabling cross-domain correlation (e.g., "this WiFi AP is on the same host as this open SSH port")
