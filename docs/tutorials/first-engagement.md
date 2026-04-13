---
outline: deep
---

# First Engagement

This tutorial walks through a complete passive pen-testing engagement using only the Steam Deck's built-in hardware — no USB peripherals required. You will start an engagement, discover hosts on your local network, scan their services, query the target intelligence database, log a finding, and generate a report.

**Time:** ~15 minutes

**Prerequisites:**
- protoPen installed and running on the Steam Deck (see [Steam Deck Setup](./steam-deck-setup))
- Server reachable at `http://steamdeck:7870`
- The Deck connected to a network with other devices on it

::: warning Authorized networks only
Only scan networks you own or have explicit written authorization to test. Running nmap against networks you do not control is illegal in most jurisdictions.
:::

## 1. Start an engagement

An engagement is protoPen's unit of work. It defines a name, scope, and operating mode. All findings, scan data, and reports are tied to the engagement.

Start one via A2A:

```bash
curl -s http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"kind": "text", "text": "Start a new engagement called home-lab-audit with scope 192.168.1.0/24 in passive mode"}]
      }
    }
  }'
```

The agent will call the `engagement` tool with `action: start`, creating a workspace directory at `/home/deck/engagements/home-lab-audit/`.

You can also start an engagement directly through the chat UI at `http://steamdeck:7870` by typing:

```
Start a new engagement called home-lab-audit with scope 192.168.1.0/24 in passive mode
```

::: tip Engagement modes
- **passive** (default) — scanning, enumeration, traffic sniffing. No transmissions or injections.
- **active** — adds directed probing, replay attacks, service interaction.
- **redteam** — full offensive capability. Requires explicit authorization.

This tutorial uses passive mode exclusively.
:::

## 2. Run a host discovery scan

Ask the agent to find live hosts on the subnet:

```bash
curl -s http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"kind": "text", "text": "Run an nmap host discovery scan on 192.168.1.0/24"}]
      }
    }
  }'
```

The agent uses the `blackarch` tool with `action: nmap_scan` under the hood. nmap outputs XML (`-oX -`), which the auto-ingestion pipeline parses and upserts into the target intel database automatically — every discovered host and its MAC address, vendor, and hostname get stored without you needing to do anything extra.

::: tip
The nmap XML parser (`tools/parsers/nmap_xml.py`) handles the ingestion. You do not need to manually insert hosts into the target store.
:::

## 3. Scan services on interesting hosts

Once the discovery scan finishes, the agent's response will list the live hosts it found. Pick one or more interesting hosts and run a service version scan:

```bash
curl -s http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"kind": "text", "text": "Run a service version scan on 192.168.1.1 and 192.168.1.50, focusing on common ports 22,80,443,8080,8443"}]
      }
    }
  }'
```

nmap runs with `-sV` (service version detection). The results — open ports, service names, banners — are auto-ingested into the target database and linked to the host records created in step 2.

## 4. Query the target intel database

The target intelligence database tracks everything discovered across all sensors. Query it to see what the scans found:

```bash
curl -s http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"kind": "text", "text": "Query the target intel database: show all discovered hosts on 192.168.1.x and their open ports. Then show the overall stats."}]
      }
    }
  }'
```

The agent uses the `target_intel` tool with `action: query_hosts` (filtered by `ip_prefix: 192.168.1`) and `action: stats`. You will see output like:

```
Target Intelligence Stats:
  hosts: 12
  ports: 34
  wifi_networks: 0
  wifi_stations: 0
  rf_signals: 0
  ble_devices: 0
  rfid_nfc_tags: 0
  credentials: 0
  scan_sessions: 2
```

WiFi, RF, BLE, and RFID counters are zero because this engagement used only network scanning. Those populate when you attach USB peripherals (PortaPack, Flipper Zero, Marauder).

## 5. Log a finding

Findings are the deliverables of an engagement. When the agent discovers something noteworthy — an outdated service, default credentials, an unnecessary open port — it should log a finding.

Ask it directly:

```bash
curl -s http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"kind": "text", "text": "Log a finding: severity=medium, category=network, title=Unencrypted HTTP service on gateway, detail=192.168.1.1 exposes port 80 (nginx 1.18) with no TLS redirect. Admin panel accessible over plaintext HTTP."}]
      }
    }
  }'
```

The agent calls `engagement` with `action: log_finding`. Findings with severity `critical` or `high` automatically trigger a Discord alert if a webhook is configured.

::: tip
The agent also auto-extracts IP and MAC addresses from finding details and upserts them into the target store, cross-linking findings to host records.
:::

## 6. Check engagement status

See the current state of the engagement — mode, scope, finding count:

```bash
curl -s http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 6,
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"kind": "text", "text": "Show the current engagement status and list all findings"}]
      }
    }
  }'
```

The agent calls `engagement` with `action: status` and `action: list_findings`. You will see the engagement name, scope, mode, start time, and a numbered list of all logged findings with their severities.

## 7. End the engagement

When you are done, end the engagement. This saves the final `engagement.json` and `findings.json` to the workspace directory and clears the active engagement state:

```bash
curl -s http://steamdeck:7870/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 7,
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"kind": "text", "text": "Generate the engagement report, then end the engagement."}]
      }
    }
  }'
```

The agent first calls `engagement` with `action: generate_report`, which produces a Markdown report sorted by finding severity and saves it to `/home/deck/engagements/home-lab-audit/report.md`. Then it calls `action: end` to close the engagement.

The workspace directory now contains:

```
/home/deck/engagements/home-lab-audit/
├── engagement.json    # Engagement metadata (scope, mode, timestamps)
├── findings.json      # All findings as structured JSON
└── report.md          # Markdown report sorted by severity
```

## Using the chat UI instead

Every command above can be done conversationally through the Gradio UI at `http://steamdeck:7870`. The agent interprets natural language and calls the same tools. The A2A `curl` examples are shown here because they are easier to reproduce exactly and integrate into scripts or other agents.

## What you learned

- How to start and end an engagement with scope and mode constraints
- Running nmap scans through the agent, with results auto-ingested into the target intel database
- Querying the target store for discovered hosts, ports, and overall stats
- Logging structured findings with severity ratings
- Generating an engagement report

## What's next

- **Attach USB peripherals** — connect a PortaPack H4M, Flipper Zero, or WiFi Marauder to add RF, WiFi, BLE, and RFID scanning to your engagements. See the [Tools reference](/reference/tools) for the full hardware API.
- **Try active mode** — set the engagement to `active` mode to enable service probing and directed scans.
- **Integrate with other agents** — use the [A2A protocol](/guides/a2a-integration) to trigger protoPen engagements from other protoLabs agents like Ava.
