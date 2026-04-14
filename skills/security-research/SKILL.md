# Security Research Skill

Run a multi-step security intelligence workflow: scan CVE feeds, check Exploit-DB, aggregate security RSS, correlate with target intel, generate threat brief.

## Deep Threat Research Workflow

When asked to research a security topic, vulnerability, or threat in depth:

1. **Check existing intel** — query `security_memory` for what's already known about the topic, target, or CVE
2. **Scan CVE feeds** — use `cve_search` to pull recent CVEs matching the target stack, product, or keyword
3. **Check Exploit-DB** — search for public exploits, PoCs, and weaponized code via `security_feeds` (source=exploit-db)
4. **Aggregate security RSS** — use `security_feeds` to scan NVD, CISA KEV, Krebs, Schneier, vendor bulletins
5. **Correlate with target intel** — cross-reference findings against `security_memory` target profiles to identify in-scope exposure
6. **Browse for context** — use `browser` to read vendor advisories, blog posts, conference talks, or PoC writeups
7. **Synthesize a threat brief** with structured output:
   - What is the threat landscape for this topic?
   - Which CVEs/exploits are actively exploited or have public PoCs?
   - What is in scope based on target intel?
   - What are the recommended mitigations?
   - What should we monitor going forward?
8. **Store findings** in `security_memory` (store_finding, store_cve, store_advisory)
9. **Rate severity** of each finding: critical / high / medium / low / info
10. **Rate exploitability** of each finding: critical / high / medium / low

## Quick Threat Scan Workflow

When asked for a quick security update on a topic:

1. Query `cve_search` for recent CVEs (last 7 days)
2. Scan `security_feeds` for trending advisories and exploits
3. Check `security_memory` for any prior tracking of the topic
4. Summarize top 5 most critical items with severity + exploitability ratings
5. Note anything relevant to currently tracked targets

## CVE Deep-Dive Workflow

When asked to analyze a specific CVE:

1. Fetch CVE details using `cve_search get` (primary), `browser` for NVD page (fallback)
2. Search Exploit-DB for related exploits and PoCs via `security_feeds`
3. Read vendor advisory via `browser` if available
4. Provide structured analysis:
   - **Vulnerability**: What the flaw is and how it works
   - **Affected Products**: Products and version ranges
   - **Attack Vector**: Network / Adjacent / Local / Physical
   - **Exploit Status**: Active exploitation / Public PoC / Theoretical / None
   - **Exploitability**: Critical / High / Medium / Low (with justification)
   - **Impact**: What an attacker achieves
   - **Target Relevance**: Which in-scope systems are affected
   - **Mitigation**: Patch, workaround, or compensating controls
5. Store the analysis in `security_memory`

## Threat Brief Generation

When generating a threat intelligence digest:

1. Search `security_memory` for recent findings, CVEs, and advisories
2. Organize by severity and exploitability
3. Write a concise threat brief with:
   - Executive summary (3-5 sentences on current threat landscape)
   - Critical/High findings (bullet points with exploitability ratings)
   - Notable CVEs and exploits (with CVE IDs and affected products)
   - Actionable recommendations (patch, mitigate, monitor)
4. Store the digest in `security_memory` (store_digest)
5. **Publish to Discord** using `discord_feed` with `action=publish`:
   - Pass `content` with the full digest text and `title` with a descriptive heading
   - Do NOT pass `channel_id` — publish uses a pre-configured webhook automatically
   - Long content is auto-chunked into multiple embeds

## Publishing to Discord

To publish any security intel to the team's Discord:

```
discord_feed action=publish title="Threat Brief — 2026-04-12" content="..."
```

**Important:** The `publish` action does NOT need a `channel_id`. It posts via a webhook automatically. Only `scan`, `history`, and `digest` actions need `channel_id`.


## Severity Rating Guide

| Rating | Criteria |
|--------|----------|
| **Critical** | Active exploitation in the wild; weaponized exploit; RCE without auth; CVSS 9.0+ |
| **High** | Public PoC available; reliable exploit path; minimal prerequisites; CVSS 7.0-8.9 |
| **Medium** | Theoretical exploit; requires specific conditions (auth, local access); CVSS 4.0-6.9 |
| **Low** | No known exploit; highly specific conditions; defense-in-depth concern; CVSS < 4.0 |
| **Info** | Environmental observation; no direct risk; useful context |

## Exploitability Rating Guide

| Rating | Criteria |
|--------|----------|
| **Critical** | Trivially exploitable; no auth required; remote; network-accessible; active campaigns observed |
| **High** | Public PoC works reliably; minimal skill required; broad attack surface |
| **Medium** | Requires specific conditions; authenticated access; local access; unusual configuration |
| **Low** | No known exploit; requires chained vulnerabilities; highly constrained environment |
