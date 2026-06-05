---
layout: home
hero:
  name: protoPen
  text: Autonomous Security Research & Pen-Testing Agent
  tagline: Steam Deck + RF hardware + LangGraph agent — scan, exploit, report.
  image:
    src: /pwnDeck-banner.jpg
    alt: pwnDeck — protoPen on a Steam Deck
  actions:
    - theme: brand
      text: Get Started
      link: /tutorials/
    - theme: alt
      text: Reference
      link: /reference/

features:
  - icon: 🎯
    title: Target Tracking
    details: Unified SQLite database tracks hosts, ports, WiFi networks, RF signals, BLE devices, and RFID tags across all sensors.
  - icon: 📡
    title: Hardware-in-the-Loop
    details: PortaPack H4M, Flipper Zero, WiFi Marauder, and BlackArch tools — all managed through serial bridges and risk-gated engagement modes.
  - icon: 🤖
    title: Agent-to-Agent Protocol
    details: JSON-RPC A2A endpoint lets other agents delegate recon, pentesting, and research tasks programmatically.
  - icon: 🧠
    title: Threat Intelligence
    details: CVE tracking, security feeds, Exploit-DB, GitHub security tools — with hybrid knowledge search (vector + BM25).
---

## Documentation Structure

This site follows the [Diátaxis](https://diataxis.fr) framework:

| Section | Purpose | Start here if you… |
|---------|---------|---------------------|
| [**Tutorials**](/tutorials/) | Learning-oriented walkthroughs | Are new to protoPen |
| [**How-To Guides**](/guides/) | Task-oriented procedures | Need to accomplish something specific |
| [**Reference**](/reference/) | Technical descriptions | Need exact details on an API, tool, or schema |
| [**Explanation**](/explanation/) | Understanding-oriented discussion | Want to understand how and why things work |
