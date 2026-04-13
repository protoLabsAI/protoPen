# Report Delivery System — Design Spec

**Date:** 2026-04-13
**Status:** Approved
**Author:** proto + kj

---

## Problem

protoPen has 6 independent Discord notification paths, none with rate limiting, batching, or deduplication. During the mush.bike engagement, 9 critical/high findings each fired an individual webhook POST, plus the reporter subagent attempted additional publishes. Result: Discord spam.

## Design

### Alert Tier Model

| Severity | Delivery | When |
|----------|----------|------|
| CRITICAL | Immediate webhook | Real-time, as finding is logged |
| HIGH | Batched per phase | On engagement phase transition |
| MEDIUM | Report only | Final report delivery |
| LOW | Report only | Final report delivery |
| INFO | Report only | Final report delivery |

### 1. Immediate Critical Alerts

**File:** `tools/engagement.py` — `_send_alert()`

- Only `severity == "critical"` fires an immediate Discord webhook POST.
- **Deduplication:** 60-second cooldown window keyed by finding title. If the same title is logged within 60s, it is silently dropped (still stored in findings list, just not re-alerted).
- **Format:** Same as current (plain content with emoji + severity + title + category + detail).

### 2. Phase-Gated Batching for HIGH Findings

**File:** `tools/engagement.py` — new `_alert_queue` and `_flush_phase_alerts()`

- HIGH findings are appended to `self._alert_queue: list[dict]` instead of firing immediately.
- When the engagement transitions phases (recon → scan → exploit → report), `_flush_phase_alerts()` is called.
- `_flush_phase_alerts()` posts a single embed:
  ```
  Title: "Phase Complete: {phase_name}"
  Description: "{n} findings"
  Fields: one field per HIGH finding (title + category, truncated to 256 chars)
  Color: orange (0xf97316)
  Footer: "protoPen — {engagement_name}"
  ```
- If the queue is empty for a phase, no message is posted.
- The queue is cleared after flush.

**Phase transition detection:**
- The engagement tool tracks `self.current_phase` (string).
- A new method `transition_phase(new_phase: str)` handles: flush alerts for old phase → set new phase.
- The LangGraph orchestrator (or playbook runner) calls `transition_phase()` when moving between phases.
- If phase transitions are not explicitly called (e.g., manual/ad-hoc engagement), `_flush_phase_alerts()` is called during `generate_report()` as a catch-all to flush any remaining queued alerts.

### 3. Final Report Delivery

**File:** `tools/engagement.py` — new `_send_report_to_discord()`

When `generate_report` action is called:

1. Generate the full markdown report to disk (existing behavior, unchanged).
2. Flush any remaining phase alerts via `_flush_phase_alerts()`.
3. Post a **summary embed** to Discord:
   ```
   Title: "Pen Test Report — {engagement_name}"
   Description: "Scope: {targets}\nMode: {mode}"
   Fields:
     - Severity Breakdown: "🔴 {n} Critical · 🟠 {n} High · 🟡 {n} Medium · 🔵 {n} Low · ⚪ {n} Info"
     - Top Findings: numbered list of up to 5 critical/high findings
     - Priority Remediation: numbered list of top 3 remediation actions
   Footer: "Assessment: {date} | Overall Risk: {risk_level}"
   Color: severity-based (red if any critical, orange if high, yellow otherwise)
   ```
4. **Attach the full report** as a file upload (multipart/form-data with `file` parameter to the webhook URL).
5. Return the report string as before (existing behavior preserved).

**Webhook file upload format:**
```python
httpx.post(webhook_url, data={"payload_json": json.dumps(embed_payload)},
           files={"file": (f"{engagement_name}-report.md", report_bytes, "text/markdown")})
```

### 4. Subagent Instruction Changes

**File:** `graph/subagents/config.py`

- **`intel_reporter`** (lines 162-170): Remove all instructions to "publish to Discord" or "use discord_feed publish". Replace with: "Do NOT publish directly to Discord. The engagement tool handles all Discord delivery."
- **`reporter`** (lines 314, 371): Remove "optionally publish summary to Discord via discord_feed publish" and the 2000-char Discord guidance. Replace with: "Generate the report using the engagement tool. Discord delivery is handled automatically."

### 5. Discord Feed Guardrail

**File:** `tools/discord_feed.py` — `_publish()`

Add engagement context check at the top of `_publish()`:
```python
if not self._override_flag:
    # During engagements, publishing should go through the engagement tool
    logger.warning("discord_feed.publish called outside engagement delivery pipeline")
```
This is a **soft warning** (not a hard block) to catch accidental direct publishes during development. The tool remains usable for non-engagement contexts (research, intel digests).

### 6. Dead Code Cleanup

- **`graph/state.py`**: Remove `publish_queue` field from `ResearcherState` (line 52). It's never written to or consumed.
- **`config/engagement-config.json`**: Remove `alert_channel_id` field. It's never referenced in code.

### 7. Unchanged Paths

These paths remain as-is (they are user-triggered, not automated):

- **Discord bot** lock-emoji reaction and @mention analysis — user-initiated
- **`/intel` command** — user-initiated from chat UI
- **`discord_feed(action="share")`** — multi-instance collaboration (currently unconfigured, separate concern)

---

## File Change Summary

| File | Changes |
|------|---------|
| `tools/engagement.py` | Add `_alert_queue`, `_flush_phase_alerts()`, `transition_phase()`, `_send_report_to_discord()`. Modify `_send_alert()` for critical-only + dedup. Modify `generate_report()` to call report delivery. |
| `graph/subagents/config.py` | Remove Discord publish instructions from `intel_reporter` and `reporter`. |
| `tools/discord_feed.py` | Add soft warning in `_publish()` for engagement context. |
| `graph/state.py` | Remove `publish_queue` from `ResearcherState`. |
| `config/engagement-config.json` | Remove `alert_channel_id`. |

## Acceptance Criteria

1. During an engagement, only CRITICAL findings produce immediate Discord alerts.
2. HIGH findings are batched and delivered once per phase transition.
3. `generate_report()` posts a summary embed + attached .md file to Discord.
4. Duplicate critical findings within 60s are deduplicated (logged but not re-alerted).
5. Subagents no longer call `discord_feed(publish)` during engagements.
6. Dead code (`publish_queue`, `alert_channel_id`) is removed.
7. Existing user-triggered paths (bot reactions, /intel) are unaffected.
8. All existing tests continue to pass.
