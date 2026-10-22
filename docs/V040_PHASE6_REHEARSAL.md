# v0.4.0 Phase 6 — three-conductor DKG rehearsal

22 October 2026 (Europe/London). A disposable rehearsal of the Phase 6
milestone, run by the coding assistant at the operator's request on the
development host. **Single-host development evidence, not a multi-machine
deployment, production custody or an independent audit.** The persistent
`~/mpc-phase5b-sandbox` and `~/mpc-phase5c-sandbox` deployments and
`~/.local/state/mpc-phase5c` were not touched.

## Result

Three independently launched Holochain 0.7.1 conductors completed one
dealerless 2-of-3 FROST Ed25519 DKG in about 40 seconds of relay time. Each
conductor had its own agent, Lair keystore, Lair-backed restricted signer,
`mpc-node` worker and `mpc-relay-service`. All three relays reported the same
transcript hash. Every Holochain call was signed by that node's own signer
through its pinned policy. No central test controller routed messages.

Each node's `journal.sqlite` then held a `completed` DKG checkpoint and
exactly one sealed share at epoch 0 (Phase 7 custody; see
`V040_PHASE7_SHARE_CUSTODY.md`). Run records live under
`~/mpc-phase6-rehearsal/run-<UTC>/` (`RESULT.json`, `logs/`).

## How to rerun

```bash
npm run build:happ
python3 -I scripts/phase6_rehearsal.py      # optional: MPC_CONDUCTOR_LOG=info
```

`scripts/phase6_rehearsal.py`:

1. Starts a local `kitsune2-bootstrap-srv`, then `hc sandbox` with three
   conductors on forced admin ports.
2. Uses a fresh `--network-seed`, so the DNA hash and DHT space are new on
   every run.
3. Performs the 5C-B provisioning sequence for three agents: app tokens, a
   2-of-3 proposal, three acceptances, reciprocal assigned grants, sealed
   offers, `mpc-node provision` and spec-pinned signer policies.
4. Starts every node's services together and waits for all three relays.

The harness:

- runs with umask 077;
- refuses any path inside the persistent sandboxes;
- generates a random throwaway Lair passphrase, stored `0600` in the run
  directory and typed through a pseudo-terminal;
- stops at the first failure.

Its one repeated write is an acceptance after the conductor reports
`DepMissingFromDht` / "could not be completed", a definitive non-commit. That
repeat happens only after `status` re-confirms the agent is still pending.

## Defects found and fixed

| Symptom on live conductors | Cause | Fix |
|---|---|---|
| First `send_protocol_message` failed: "Remote delivery not acknowledged"; recipient logged nothing | `receive_protocol_message` commits an `InboxEvent` on the recipient's chain. Concurrent deliveries from two peers raced, and strict chain-top ordering failed the loser with `HeadMoved` | The coordinator writes `InboxEvent` with `ChainTopOrdering::Relaxed`. The private entry's validation is order-independent. `get_inbox` still collapses identical duplicates and reports conflicting ones as equivocation |
| Cause invisible to the sender | The coordinator mapped every non-OK remote response to one generic string | The coordinator now names the kind: unauthorized, authentication failed, network (with Holochain's text, truncated), countersigning. It still never prints `Unauthorized` Debug output, which carries the capability secret. The text no longer tells callers to retry |
| A relay aborted with "missing, duplicate or forked DKG encryption key registrations" | A peer's key registration became visible after its attestation; the relay fetched the roster once | The relay waits while the roster is merely incomplete, consuming no randomness and publishing nothing. Duplicate, forked, foreign or malformed records still abort. Tests: `late_visible_key_registration_waits_then_completes`, `forked_key_registration_aborts` |

The coordinator changes are coordinator-only. The DNA hash is unchanged
(`uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu` for the default
seed). The 17 October artifacts are preserved, with hashes, in
`~/mpc-source-backups/deployed-5c-artifacts-2026-10-17/`.

## Consequence for the persistent 5C deployment

The live 5C cells still run the 17 October coordinator: strict inbox ordering
and the generic error. Two nodes deliver less concurrently than three, but
the same `HeadMoved` race is possible. Before 5C-C, the operator should
decide on an `update_coordinators` admin operation. That is a separately
approved step; it keeps the DNA hash and the source chains.

## What this rehearsal does not show

- **Separate machines or networks.** All conductors share one host, one Linux
  user and a local bootstrap server.
- **Failure, partition and kill behaviour during DKG.** This Phase 6 exit
  criterion is still open.
- (Signing across the same three nodes is now part of the rehearsal; see
  `V040_PHASE8_SIGNING.md`.)
- **Production custody**: same-UID keys, no anti-rollback.
- **Byzantine robustness.** The unanimous fail-closed gate lets any one member
  force an abort.
