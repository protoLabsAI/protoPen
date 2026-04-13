---
outline: deep
---

# Tutorials

protoPen is an autonomous pen-testing and security research agent that runs natively on a Steam Deck. It combines BlackArch security tools (nmap, bettercap, aircrack-ng) with optional USB peripherals (PortaPack H4M, Flipper Zero, WiFi Marauder ESP32) and a LangGraph-powered AI agent that plans engagements, executes scans, auto-ingests results into a target intelligence database, and generates reports.

The server exposes a FastAPI/Gradio UI on port 7870, an A2A protocol endpoint for agent-to-agent communication, and an OpenAI-compatible chat completions API.

These tutorials walk you through going from a fresh Steam Deck to a working protoPen installation and your first completed engagement.

## Start here

### [Steam Deck Setup](./steam-deck-setup)

Go from a fresh SteamOS install to a fully working protoPen environment: SSH access, BlackArch tools, Python venv, secrets via Infisical, and a systemd service that starts protoPen on boot.

### [First Engagement](./first-engagement)

Run a passive pen-testing engagement using only the Steam Deck's built-in hardware. Start an engagement, scan the local network with nmap, query the target intel database, log findings, and generate a report.
