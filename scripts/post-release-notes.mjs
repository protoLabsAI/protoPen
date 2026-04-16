#!/usr/bin/env node
/**
 * post-release-notes.mjs — Rewrite commits with Claude and post to Discord.
 *
 * Usage:
 *   node scripts/post-release-notes.mjs [--from <ref>] [--to <ref>] [--title <string>]
 *
 * Env vars:
 *   ANTHROPIC_API_KEY        — required (Claude Haiku for rewrite)
 *   DISCORD_WEBHOOK_URL      — Discord channel webhook URL
 */

import { execSync } from "node:child_process";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    from:  { type: "string" },
    to:    { type: "string", default: "HEAD" },
    title: { type: "string" },
  },
});

const to = values.to || "HEAD";

// ── Commit range ──────────────────────────────────────────────────────────────

let from = values.from;
if (!from) {
  try {
    from = execSync("git describe --tags --abbrev=0 HEAD^", { encoding: "utf8" }).trim();
    console.log(`Auto-detected range: ${from}..${to}`);
  } catch {
    from = execSync("git rev-list --max-count=30 HEAD | tail -1", { encoding: "utf8" }).trim();
    console.log("No previous tag found — using last 30 commits");
  }
}

const rawLog = execSync(
  `git log ${from}..${to} --pretty=format:"%s" --no-merges`,
  { encoding: "utf8" },
).trim();

const NOISE = /^(chore: release|Merge |promote:|docs: session handoff|Co-Authored)/i;

const commits = rawLog
  .split("\n")
  .map(l => l.trim())
  .filter(l => l.length > 0 && !NOISE.test(l));

if (commits.length === 0) {
  console.log("No notable commits in range — nothing to post.");
  process.exit(0);
}

console.log(`${commits.length} commits to summarise.`);

// ── Version / title ───────────────────────────────────────────────────────────

let version = values.title;
if (!version) {
  try {
    version = execSync("git describe --tags", { encoding: "utf8" }).trim();
  } catch {
    version = execSync("git rev-parse --short HEAD", { encoding: "utf8" }).trim();
  }
}

// ── Claude rewrite ────────────────────────────────────────────────────────────

const apiKey = process.env.ANTHROPIC_API_KEY;

let notes;
if (!apiKey) {
  console.warn("ANTHROPIC_API_KEY not set — posting raw commits without rewrite.");
  notes = commits.map(c => `• ${c}`).join("\n");
} else {
  const SYSTEM_PROMPT = `\
You are writing release notes for protoPen — an autonomous pen testing and security intelligence \
agent that runs on a Steam Deck with hardware-in-the-loop RF/WiFi/RFID peripherals and exposes \
an A2A (Agent-to-Agent) API for integration with orchestration systems.

Given raw git commit subjects, rewrite them as polished release notes.

Rules:
- Group into 2–4 themed sections relevant to: A2A / Agent Protocol, Tools & Hardware, Security Intelligence, Bug Fixes
- Each item is one sentence, present tense, outcome-focused (what it enables, not what changed)
- Skip purely internal housekeeping (fixture edits, comment typos, test data only)
- Use • for bullets. Use **Section Title** for headers. No emojis.
- Max 280 words. Plain markdown only — no code blocks, no headers with ##.`;

  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 700,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: commits.join("\n") }],
    }),
  });

  if (!resp.ok) {
    console.error(`Claude API error: ${resp.status}`, await resp.text());
    process.exit(1);
  }

  const data = await resp.json();
  notes = data.content?.[0]?.text ?? commits.map(c => `• ${c}`).join("\n");
}

if (notes.length > 3900) notes = notes.slice(0, 3897) + "…";

// ── Discord post ──────────────────────────────────────────────────────────────

const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
if (!webhookUrl) {
  console.log("DISCORD_WEBHOOK_URL not set — release notes preview:\n\n" + notes);
  process.exit(0);
}

const embed = {
  title: `protoPen ${version}`,
  description: notes,
  color: 0xdc2626,  // red — security tooling aesthetic
  timestamp: new Date().toISOString(),
  footer: { text: "protoPen" },
};

const discordResp = await fetch(webhookUrl, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ embeds: [embed] }),
});

if (!discordResp.ok) {
  console.error(`Discord post failed (${discordResp.status}): ${await discordResp.text()}`);
  process.exit(1);
}

console.log(`Posted release notes for ${version} to Discord.`);
