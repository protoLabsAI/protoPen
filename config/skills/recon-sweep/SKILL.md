---
name: recon-sweep
description: >-
  Use this when the user asks you to do reconnaissance on a host, network, or
  target — e.g. "recon 192.168.1.0/24", "what's running on this box", "scope out
  this target", "passive recon on example.com". A disciplined passive-first
  enumeration loop that stays within the active engagement's scope and mode.
tools: [dns_enum, subdomain_discovery, osint_recon, lan_scan, service_enum, target_intel]
---

# Recon Sweep

A passive-first reconnaissance loop. Always check the active engagement scope and
mode before touching anything — never probe a target that isn't in scope.

1. **Confirm scope.** Check the engagement: is this target in scope, and does the
   current mode permit the level of probing the user wants? If not, say so and
   stop. Passive recon is allowed at the lowest mode; active scanning is not.
2. **Passive first.** Start with zero-touch sources: `osint_recon` and
   `target_intel` for what's already known, `dns_enum` + `subdomain_discovery`
   for the DNS/attack surface. These never send packets to the target.
3. **Local network discovery.** If the target is a local range, `lan_scan` to
   enumerate live hosts and basic services (respecting mode — SNMP/ARP sweeps are
   passive-ish; an aggressive port scan is active).
4. **Service enumeration.** Once hosts are known and the mode permits, use
   `service_enum` on the in-scope hosts to identify services + versions.
5. **Correlate + record.** Tie findings back to `target_intel`; note hostnames,
   open services, versions, and anything that suggests a follow-up. Store what
   matters so later steps (and other subagents) can build on it.
6. **Summarize.** Lead with the attack surface (what's reachable + interesting),
   then the supporting detail. Flag anything out of scope you noticed but did
   NOT probe, and recommend the next phase.

Rules: passive before active, scope before everything, and never escalate the
engagement mode on your own — surface the recommendation and let the operator
decide.
