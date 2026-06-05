#!/usr/bin/env bash
#
# Live smoke test for a running protoPen instance.
#
# Exercises the critical paths end-to-end against a live service: the A2A 1.0
# contract (card / auth gate / version gate / cancel), a full streaming chat
# turn (tool-call DataParts + artifact), every read-only operator API endpoint,
# the web bundle, and the OpenAI-compat surface. Read-only + one benign chat
# turn — no agent launches, no playbook/workflow runs, no scheduler writes.
#
# Usage:
#   On the Deck:           ./scripts/smoke.sh
#   From a dev box (SSH):  ssh deck@steamdeck 'bash -s' < scripts/smoke.sh
#
# Config (env overrides):
#   PROTOPEN_BASE   base URL                 (default http://127.0.0.1:7870)
#   PROTOPEN_KEY    operator/API key         (default: read from the running
#                                             :7870 process env, or $PROTOPEN_API_KEY
#                                             / $RESEARCHER_API_KEY)
#
# Exit code: 0 if all checks pass, 1 otherwise.

set -u
B="${PROTOPEN_BASE:-http://127.0.0.1:7870}"

# Resolve an API key: explicit env first, then the live :7870 process environ.
KEY="${PROTOPEN_KEY:-${PROTOPEN_API_KEY:-${RESEARCHER_API_KEY:-}}}"
if [ -z "$KEY" ]; then
  PID=$(ss -ltnp 2>/dev/null | grep ":7870" | grep -oE "pid=[0-9]+" | head -1 | cut -d= -f2)
  if [ -n "${PID:-}" ] && [ -r "/proc/$PID/environ" ]; then
    KEY=$(tr "\0" "\n" < "/proc/$PID/environ" | grep -E "^(PROTOPEN_API_KEY|RESEARCHER_API_KEY)=" | head -1 | cut -d= -f2-)
  fi
fi
[ -z "$KEY" ] && echo "WARN: no API key resolved — authed checks will fail" >&2

pass=0; fail=0
ok(){ printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
no(){ printf "  \033[31mFAIL\033[0m  %s — %s\n" "$1" "$2"; fail=$((fail+1)); }

echo "== service =="
if command -v systemctl >/dev/null 2>&1; then
  [ "$(systemctl --user is-active protopen.service 2>/dev/null)" = active ] \
    && ok "protopen.service active" || no "service" "not active (or not this host)"
else
  echo "  (skip — no systemctl on this host)"
fi

echo "== A2A 1.0 contract =="
card=$(curl -s --max-time 10 "$B/.well-known/agent-card.json" -H "x-api-key: $KEY")
echo "$card" | grep -q '"protocolVersion":"1.0"' && ok "agent card is A2A 1.0" || no "agent card" "no 1.0 in card"
echo "$card" | grep -q 'tool-call-v1' && ok "card advertises tool-call-v1 ext" || no "tool-call ext" "missing"

code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X POST "$B/a2a" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"x","method":"SendMessage","params":{}}')
[ "$code" = 401 ] && ok "auth gate: 401 without key" || no "auth gate" "got $code (want 401)"

verr=$(curl -s --max-time 10 -X POST "$B/a2a" -H "Content-Type: application/json" -H "x-api-key: $KEY" \
  -d '{"jsonrpc":"2.0","id":"v","method":"SendMessage","params":{"message":{"messageId":"m","role":"ROLE_USER","parts":[{"text":"hi"}]}}}')
echo "$verr" | grep -q "VERSION_NOT_SUPPORTED" && ok "version gate: rejects missing A2A-Version" || no "version gate" "$(echo "$verr" | head -c 80)"

cerr=$(curl -s --max-time 10 -X POST "$B/a2a" -H "Content-Type: application/json" -H "A2A-Version: 1.0" -H "x-api-key: $KEY" \
  -d '{"jsonrpc":"2.0","id":"c","method":"CancelTask","params":{"id":"does-not-exist"}}')
echo "$cerr" | grep -qiE "not.?found|TaskNotFound" && ok "CancelTask recognized (TaskNotFound)" || no "CancelTask" "$(echo "$cerr" | head -c 80)"

echo "== full chat turn (SendStreamingMessage) =="
sse=$(mktemp)
curl -sN --max-time 90 -X POST "$B/a2a" \
  -H "Content-Type: application/json" -H "Accept: text/event-stream" \
  -H "A2A-Version: 1.0" -H "x-api-key: $KEY" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":\"smoke\",\"method\":\"SendStreamingMessage\",\"params\":{\"message\":{\"messageId\":\"m-$$\",\"contextId\":\"smoke-$$\",\"role\":\"ROLE_USER\",\"parts\":[{\"text\":\"List our current targets.\"}]}}}" > "$sse" 2>&1
grep -q "TASK_STATE_COMPLETED" "$sse" && ok "chat turn reaches COMPLETED" || no "chat turn" "no COMPLETED ($(wc -c <"$sse")B)"
n_tool=$(grep -oc "tool-call-v1" "$sse" 2>/dev/null || echo 0)
[ "$n_tool" -gt 0 ] && ok "tool-call DataParts streamed ($n_tool parts)" || no "tool cards" "no tool parts"
grep -q "artifactUpdate" "$sse" && ok "artifact (text answer) streamed" || no "artifact" "none"
rm -f "$sse"

echo "== operator API (read-only GETs) =="
for ep in /api/runtime/status /api/targets "/api/knowledge/search?q=ssh" "/api/intel/search?q=ssh" \
          /api/scheduler/jobs /api/playbooks /api/workflows /api/skills /api/goals \
          /api/activity /api/engagement /api/subagents /api/chat/commands; do
  c=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 -H "x-api-key: $KEY" "$B$ep")
  [ "$c" = 200 ] && ok "GET $ep" || no "GET $ep" "$c"
done

echo "== web app + OpenAI-compat =="
c=$(curl -s -o /dev/null -w "%{http_code}" "$B/app/"); [ "$c" = 200 ] && ok "/app/ serves" || no "/app/" "$c"
js=$(curl -s "$B/app/" | grep -oE "/app/assets/index-[A-Za-z0-9]+\.js" | head -1)
if [ -n "$js" ] && curl -s "$B$js" | grep -q "SendStreamingMessage"; then
  ok "deployed bundle speaks A2A 1.0"
else
  no "bundle" "no SendStreamingMessage in served JS"
fi
c=$(curl -s -o /dev/null -w "%{http_code}" -H "x-api-key: $KEY" "$B/v1/models"); [ "$c" = 200 ] && ok "GET /v1/models" || no "/v1/models" "$c"

echo
echo "==== SMOKE: $pass passed, $fail failed ===="
[ "$fail" -eq 0 ]
