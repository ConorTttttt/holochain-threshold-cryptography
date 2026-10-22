#!/usr/bin/env bash
# Phase 5C-B final READ-ONLY acceptance audit (deployment report section 4).
#
# Run from Holonix, in your own terminal, while both persistent conductors are
# live. It makes no source-chain write, issues no token or grant, and never
# prints token, capability, policy or keystore contents. `status` signs its
# read calls with Lair, so it prompts for each agent's Lair passphrase; type it
# yourself. An expired app token makes `status` fail: re-issuing a token is a
# SEPARATELY approved operation, never part of this audit.
#
# Usage: ADMIN_A=<port> ADMIN_B=<port> scripts/phase5c_b_audit.sh
# Ports change on every conductor launch; read them from the launch output.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SB="${SB:-$HOME/mpc-phase5c-sandbox}"
P="${P:-$HOME/.local/state/mpc-phase5c}"
PROV="${PROV:-$REPO/target/debug/mpc-phase5c-provision}"
AGENT_A_B64="uhCAkwfXPxtzM7lKfMBc1BS8TZkPpcBPav6RoxhpA2YfrhGjo0BQo"
AGENT_B_B64="uhCAkU0m8gBCkoSRobThBSYh47kC-DiAhCR1AJKmxUB1uf-Oi6vtb"
DNA_B64="uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu"
: "${ADMIN_A:?set ADMIN_A to node A's current admin port}"
: "${ADMIN_B:?set ADMIN_B to node B's current admin port}"

fails=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
[ -x "$PROV" ] || { echo "FAIL: build mpc-phase5c-provision first (npm run build:phase5c-provision)"; exit 1; }

echo "== Installed apps (public metadata)"
for node in A B; do
  port_var="ADMIN_$node"; agent_var="AGENT_${node}_B64"
  apps="$(hc client call --port "${!port_var}" list-apps 2>&1)" || { fail "node $node list-apps"; continue; }
  grep -q "$DNA_B64" <<<"$apps" && pass "node $node runs DNA $DNA_B64" || fail "node $node DNA differs"
  grep -q "${!agent_var}" <<<"$apps" && pass "node $node agent is ${!agent_var}" || fail "node $node agent differs"
  grep -q "mpc-phase5c" <<<"$apps" && pass "node $node has app mpc-phase5c" || fail "node $node app missing"
done

echo "== Frozen ceremony"
cmp -s "$P/a/ceremony.json" "$P/b/ceremony.json" && pass "ceremony.json identical for A and B" \
  || fail "ceremony.json differs or is missing"

echo "== Grants (redacted metadata; expect exactly one per node)"
"$PROV" list-grants --record "$P/a/ceremony.json" --admin-port "$ADMIN_A" --agent-b64 "$AGENT_A_B64" || fail "A list-grants"
"$PROV" list-grants --record "$P/b/ceremony.json" --admin-port "$ADMIN_B" --agent-b64 "$AGENT_B_B64" || fail "B list-grants"

echo "== Cross-conductor status (each node reads the shared proposal)"
"$PROV" status --app-port 8891 --origin http://localhost:8891 --app-token-file "$P/a/app-token" \
  --agent-b64 "$AGENT_A_B64" --lair-root "$SB/state/node-a/ks" --record "$P/a/ceremony.json" || fail "A status"
"$PROV" status --app-port 8892 --origin http://localhost:8892 --app-token-file "$P/b/app-token" \
  --agent-b64 "$AGENT_B_B64" --lair-root "$SB/state/node-b/ks" --record "$P/b/ceremony.json" || fail "B status"

echo "== Private-state metadata (no contents read)"
for agent in a b; do
  dir="$P/$agent"
  [ -d "$dir/node" ] && [ ! -L "$dir/node" ] && pass "$agent node dir" || fail "$agent node dir"
  pol="$dir/signer-policy.json"
  [ -f "$pol" ] && [ ! -L "$pol" ] && [ -s "$pol" ] && [ "$(stat -c '%a' "$pol")" = 600 ] \
    && pass "$agent signer-policy file metadata" || fail "$agent signer-policy file metadata"
  if [ "$(stat -c '%a' "$dir/caps")" = 700 ] \
     && [ "$(find "$dir/caps" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 1 ] \
     && [ -z "$(find "$dir/caps" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ] \
     && [ -z "$(find "$dir/caps" -mindepth 1 -maxdepth 1 -type f ! -perm 600 -print -quit)" ]; then
    pass "$agent caps metadata"
  else
    fail "$agent caps metadata"
  fi
done

echo
echo "Acceptance also needs, from the output above: both status runs match the"
echo "ceremony with both agents accepted and ready_observed=true, and each node"
echo "lists exactly one grant with the expected assignee, function and action."
echo "Policies written on 17 October predate the B2 fix and pin no spec: the"
echo "signer refuses them. Regenerate to a NEW path with write-policy before 5C-C."
[ "$fails" -eq 0 ] && echo "AUTOMATED CHECKS: PASS" || echo "AUTOMATED CHECKS: $fails FAILED"
[ "$fails" -eq 0 ]
