# Handoff: Personal-Target OSINT

**Date**: 2026-06-01
**Handoff Number**: 003
**Status**: Shipped to `main` and deployed to the Deck.

---

## Overview/Summary

protoPen can now profile a **person** by pivoting across public identifiers —
**username ↔ email ↔ phone** (plus an associated domain) — building on the
existing `maigret` username tool. Results persist as structured, searchable
target-store findings and can satisfy goals. The capability is **fully passive**
(nothing is sent to the target) but **engagement-gated**: collection only runs
inside an authorized, scoped engagement.

## What shipped

| PR | Content |
|---|---|
| #124 | `phoneinfoga` + `holehe` tools, the `personal_osint` playbook, and the `requires_engagement` gate flag |
| #126 | Parsers (phoneinfoga/holehe) + maigret keyed-to-person; goal verifier counts target-store findings |
| #128 | Parser guard: bail out when the email/username header isn't parsed (no anonymous `target=""` findings) |
| #130 | holehe legend-line fix (don't count `[+] Email used, [-] … [x] …` as an account) |
| #132 | `personal_osint` theHarvester uses a fast, valid keyless source set (was `all` → timeout) |
| #134 | Docs: `NUMVERIFY_API_KEY` + the OSINT binary-path vars |

## Architecture

**Tools** (`tools/`, all modeled on `maigret.py` — isolated install, env-var binary
resolution, kill-first subprocess idiom, output summarizer; all passive):
- `phoneinfoga.py` — phone → country/carrier/line type + OSINT footprint. Bin via
  `PHONEINFOGA_BIN`.
- `holehe.py` — email → which of 120+ sites have an account. Bin via `HOLEHE_BIN`.
- Registered in `lg_tools.py` (`get_pentest_tools` → `get_combined_tools`, the
  Recon group) + the `gen_tool_docs` "Reconnaissance & OSINT" category.

**Parsers** (`tools/parsers/`): turn tool output into target-store findings via
`add_findings` → the generic `findings` table (searchable in the intel surface).
Keyed to the person: `target` = number/email/username, `category` =
`osint-phone`/`osint-account`. **Parsers receive the tool's *summarized* output**
(execute() ingests the summary, not raw), so they parse the `[+]`/header lines.
Registered through imports in `parsers/__init__.py`.

**Goal bridge** (`graph/goals/verifiers.py`): `_active_findings` =
`_merge_findings(_engagement_manager())` — the engagement's logged findings PLUS
target-store findings recorded since `active_engagement.started_at` (ISO lexical
compare scopes to the current engagement, avoiding cross-engagement staleness). So
OSINT goals work, e.g. `verifier {type: findings, category: account, min: 20}`.

**Playbook** (`playbooks/library/personal_osint.yaml`): pivots from any seed
`{name, username, email, phone, domain}`; each step is `condition`-gated on its
seed so partial inputs work. Chains maigret → holehe → phoneinfoga →
theHarvester + whois.

**The `requires_engagement` gate** (`playbooks/schema.py` + `loader.py` +
`operator_api/playbooks.py::_enforce_gate`): a passive (risk-0) playbook can demand
an active engagement + in-scope target anyway, without bumping its mode. The
mechanism for "passive tools, but PII collection must be authorized."

## Install (binaries)

`start.sh` (native) + `Dockerfile` (container) install all three OSINT binaries.
**Gotchas baked in:**
- **phoneinfoga**: `go install` does NOT work for v2 (its embedded web
  `client/dist` isn't in the module). Installed as a **pinned release binary +
  sha256 verify** (`v2.11.0`, `phoneinfoga_Linux_x86_64.tar.gz`) — NOT
  `curl master/install | bash` (unpinned supply-chain risk).
- **holehe**: isolated venv (pins httpx/trio), like maigret.

## Key decisions & gotchas (read before extending)

1. **PII hygiene** — all three OSINT tools redact `argv` in logs
   (`Running %s (%d args)`, never the username/email/phone). Don't reintroduce
   `" ".join(args)` logging.
2. **holehe legend line** — holehe always prints `[+] Email used, [-] Email not
   used, [x] Rate limit`. The summarizer + parser drop lines containing `[-]`/`[x]`
   (real results have only `[+]`); the parser also requires a domain-like token.
3. **theHarvester `all` is too slow** — it queries ~40 backends and blows the
   timeout. `personal_osint` uses `crtsh,certspotter,hackertarget,rapiddns,
   duckduckgo,otx,urlscan` (all keyless, present in 4.10.1). NB: `bing` was removed
   in 4.x and errors the whole run.
4. **numverify (optional, NOT set up)** — phoneinfoga reads `NUMVERIFY_API_KEY` from
   the env (subprocess inherits the service env from Infisical). Setting it enables
   carrier + line type; without it, only `local` + `googlesearch` run. No code
   change needed — just add the key to Infisical and restart. Operator chose to
   hold off (no apilayer account yet).
5. **Tool registration** — pentest/OSINT tools live in `get_pentest_tools` /
   `get_combined_tools`, NOT the small `get_security_tools`.

## Self-test (operator, 2026-06-01)

Verified live against the operator (direct, no-persist): username `mabry1985` → 18
accounts (maigret); gmail → 7 accounts (holehe, Codepen/Replit cross-confirmed with
the username pivot); phone → US/Portland 503 line (phoneinfoga, no carrier without
numverify); work email → 0 accounts (clean); `joshmabry.dev` → `*.joshmabry.dev`
from CT logs. Both shipped bugs (holehe legend, theHarvester `all`) were caught here.

## Open / next

- **numverify key** — documented + wired; just needs a key in Infisical (deferred).
- **Deferred OSINT tools** — `h8mail` (breach/credential exposure, needs API keys),
  `GHunt` (Google account → name/photos/Maps, needs Google session cookies).
- **OSINT parser coverage** — `osint_recon`/`theharvester` output isn't parsed into
  the target store yet (only maigret/phoneinfoga/holehe are); a `theharvester`
  parser would file discovered emails/hosts as findings.
- **Stale remote branches** (closed-unmerged, preserved for a decision):
  `feat/hackrf-portapack-setup` (#32 — HackRF/PortaPack SteamOS setup docs),
  `fix/traffic-analysis-testing-findings` (#31). Delete or revive.

## Testing

```bash
python -m pytest tests/test_personal_osint.py tests/test_osint_parsers.py tests/test_maigret.py -q
```
Covers the tool summarizers, not-installed paths, kill-first timeout, the
engagement gate (blocked without an engagement, passes with one), parser
extraction/dedup/legend-drop, and the goal findings bridge. All langchain-free.

## Deploy notes

Backend + playbook YAML; the OSINT binaries are installed by `start.sh` on the Deck
(phoneinfoga v2.11.0 + holehe present). Playbook YAML changes take effect without a
restart (loaded from disk per run). Verify on the Deck:

```bash
PHONEINFOGA_BIN=$HOME/.local/bin/phoneinfoga HOLEHE_BIN=$HOME/.holehe-venv/bin/holehe \
  .venv/bin/python -c "from tools.lg_tools import get_combined_tools; \
  n=[t.name for t in get_combined_tools()]; print('phoneinfoga' in n, 'holehe' in n)"
```
