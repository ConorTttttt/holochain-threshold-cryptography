# Sprint 1.8B recovery — INV-13 implementation-ready admission design

**Status: PROPOSED, NOT APPROVED, NOT IMPLEMENTED, NOT ACTIVATED.** Live secret-bearing Round 2 stays blocked by `ConductorBridge::require_round_two_key_approval`. This document refines `SPRINT18B_INV13_ADMISSION_DESIGN.md` (the review-only proposal at `21cd9ac4`) into a concrete specification an engineer could implement **after** decisions INV13-A…E are recorded by the operator and security reviewers. Nothing here is an approval, and no code in this sprint implements it.

Baseline inspected: `33db0497435e1713781329accece8eacde753faf` (PR #19 head).

## 1. Assessment of the existing proposal

| Area | Existing proposal (`SPRINT18B_INV13_ADMISSION_DESIGN.md`) | Assessment |
| --- | --- | --- |
| Independent authority | Leaves INV13-A open; offers signed offline roster or trusted local provisioning | Correctly refuses to infer authority. Only the **signed roster** option gives third-party-verifiable, portable evidence, so it is the recommended option here; local provisioning alone cannot be audited off-host. |
| Trust anchor | "Independently provisioned, pinned verification key" | Under-specified: it doesn't say where the anchor lives, who can write it, or how it rotates. Specified below (§3). |
| Ceremony / participant binding | Full `SessionSpec`, proposal `ActionHash`, every `(agent, x25519, registration action)` | Complete and correct. Adds the requirement that the local key equals the native secret-derived key. |
| DNA / cell / app binding | Installed app ID, `application_id`, DNA hash, role, cell | Correct. Must be checked against the **pinned** connection policy, not against conductor responses. |
| Registration provenance | DHT observation = observation, not consent | Correct, and essential. `verify_explicit_key_roster(approved, observed)` must never receive the same source for both arguments. |
| Rotation / revocation | Any rotation → new ceremony | Correct for in-ceremony keys. Issuer-key rotation/revocation is unspecified; specified in §6. |
| Restart / crash | DKG interruption terminal | Consistent with the existing journal tombstone (`sigkill_after_round_one_two_or_three_is_permanently_nonresumable`). |
| Replay / rollback | INV13-C open | Approval must be one-shot per proposal **and** recorded in the anchored journal before `part2`. See §5. |
| Forks | Late fork aborts remaining work | Correct; it needs a concrete re-observation point (§4 step 7). |
| **Verifier placement** | INV13-B open: "privileged host/bridge … with admission token to worker" | **Gap found (S18B-F01):** today the gate exists **only** in the host library. The secret-owning worker accepts `Command::BeginRoundTwo` with any complete, well-formed pin set from any holder of the node IPC key; the test harnesses `three_processes.rs`, `share_custody.rs` (`DurablePort`, `ChildPort`, `OfflineServedPort`) prove this. The design should therefore enforce approval **inside the worker**, with the host check kept as defence in depth. |

## 2. Recommended decisions (for operator/security sign-off; not decided here)

- **INV13-A (authority):** a dedicated Ed25519 *roster-approval key*, held offline by the operator. It is not a participant agent key, not a conductor/Lair key and not a CI key. Optionally use an `m`-of-`n` set of approval keys (`m ≥ 1`). The anchor is the set of approval public keys plus `m`.
- **INV13-B (placement):** primary verification in the worker (`AuthenticatedController::handle`), against an anchor file installed at `provision` time. Secondary verification in `ConductorBridge::round_two` before any IPC.
- **INV13-C (restart/rollback):** approvals are single-use per `proposal_action`; there's no expiry until a trusted time source exists; any restart is terminal (existing behaviour); consumed approval IDs are kept in the anchored journal.
- **INV13-D (schema change):** requires a wire change to `Command::BeginRoundTwo`, a new journal table and a new provisioned file. This needs explicit operator approval and a release-inventory update.
- **INV13-E:** independent FROST + Holochain review of the implementation (E8).

## 3. Trust anchor

- File: `<state_dir>/roster-approval-anchor.json`, written **only** by `mpc-node provision --approval-anchor <path>`. Mode `0400`, owned by the node user. Covered by the existing custody preflight (unsafe mode, symlink or wrong owner → refuse to serve).
- Contents: `{ "schema": 1, "threshold": m, "keys": [ { "id": <32-byte SHA-256 of pubkey>, "ed25519": <32 bytes> } … ], "revoked_approval_ids": [] }`.
- The anchor is never received over IPC, from the conductor, from the DHT, or from an SDK caller. The worker reads it once at start-up and binds its SHA-256 into the journal (`anchor_digest`), so swapping it for an existing ceremony aborts that ceremony.
- If the anchor is absent, the worker refuses `BeginRoundTwo` with the existing INV-13 message: it fails closed by default, so a deployment that never provisions an anchor behaves exactly as today.

## 4. Admission record and enforcement order

### 4.1 `Round2RosterApprovalV1` canonical preimage

Binary encoding with fixed field order. Every variable-length field is prefixed with a `u32` big-endian length. There's no JSON in the signed bytes.

```
DOMAIN  = "holochain-mpc/inv13/round2-roster-approval/v1\0"
preimage = DOMAIN
  || approval_id[32]                         (random, unique)
  || anchor_key_set_digest[32]               (SHA-256 of the anchor key set)
  || lp(installed_app_id) || lp(spec.application_id)
  || dna_hash[39] || lp(role_name) || lp(zome_name)
  || proposal_action[39]
  || spec_commitment[32]                     (commitment over the full SessionSpec,
                                              incl. protocol id/version, session_id,
                                              context_hash, threshold, max_round,
                                              sorted participants)
  || u32(n) || n × ( agent[39] || x25519[32] || registration_action[39] )   sorted by agent
signature_i = Ed25519_sign(approval_key_i, SHA-512(preimage))
```

Fixed interoperability vectors (valid, each single-field mutation, reordered roster) must be committed with the implementation.

### 4.2 Enforcement (worker = authoritative, host = defence in depth)

1. **Host** (`ConductorBridge::round_two`): verify the approval signatures against a host-side copy of the anchor. Check app/DNA/role/cell against `ConductorPin`. Then run `verify_explicit_key_roster(ceremony, binding, local, approved = approval.roster, observed = fresh get_encryption_key_bindings)`. The two sources must differ: approval from the operator, observation from the conductor.
2. **Host** sends `Command::BeginRoundTwo { pinned_keys, approval }` (wire change, INV13-D).
3. **Worker**: reject unless the anchor is loaded and its digest equals the journalled `anchor_digest`.
4. **Worker**: verify `m` distinct valid signatures from non-revoked anchor keys, and that `approval_id` isn't revoked.
5. **Worker**: verify `proposal_action`, `spec_commitment` and the participant set against its own `Binding` and `ChannelContext`. Verify `pinned_keys` is **exactly** equal to `approval.roster` (set equality, including action hashes), and that the local tuple equals `state.transport_key.public_key()`.
6. **Worker**: durably journal `round2_admission(proposal_action, approval_id, preimage_digest)` with `UNIQUE(proposal_action)`, **before** `party.part2`. A second admission for the same proposal fails closed, even with a different approval.
7. **Host** (after publishing ciphertext, before `Finalize`): re-read the key roster. Any extra, forked or rotated registration → `abort_connection()`, and no `Finalize`. Ciphertext already sent can't be unsent; the evidence is retained.

## 5. Restart, replay and rollback

- **Restart:** the existing `running` tombstone keeps any interrupted ceremony terminal. The admission record doesn't reopen it.
- **Replay:** an approval is bound to `proposal_action` and `spec_commitment`, and is consumed once per proposal in the journal. Replaying it into a different proposal fails at step 5; replaying it into the same proposal fails at step 6.
- **Rollback:** restoring an older journal is already detected by the custody anti-rollback anchor (`restored_journal_snapshot_is_refused_after_a_nonce_was_burned`, `serve_refuses_unsafe_custody…`). The admission write must go through the anchored store, and the anchor's adversarial robustness remains S1-H01 (open).
- **Time:** there's no wall-clock expiry until a trusted monotonic source is approved (INV13-C). The design relies on one-shot consumption instead.

## 6. Rotation and revocation

- **Participant key rotation within a ceremony:** forbidden. A new registration action for any member (even with the same key) → abort, then a new proposal and a new approval.
- **Approval key rotation:** re-provision the anchor file. Ceremonies already holding an `anchor_digest` keep the old digest and fail if the anchor changes mid-ceremony. That's intentional.
- **Revocation:** `revoked_approval_ids` and removal of a key from `keys` take effect at the next worker start. Revocation can't retract ciphertext already delivered.
- **Conflicting approvals:** two valid approvals for one proposal with different rosters is a hard conflict, detected by the `UNIQUE(proposal_action)` journal constraint and by step 1 if the host sees both.

## 7. Required tests before activation (all currently NOT IMPLEMENTED)

Native E3/E7: tampered signature; unknown or revoked issuer; missing anchor; anchor swapped mid-ceremony; below-threshold signatures; `approved == observed` copied from the DHT without a signature; every single-field binding mutation (app, application_id, DNA, role, zome, proposal, session, context, threshold, protocol version, participant set); shuffled roster accepted only with a valid approval; missing, duplicate, extra or forked registration; local key mismatch; second admission for the same proposal; crash after admission and before part2 → no resume; journal rollback across admission → refused.

E5/E6 (disposable conductors): an approval delivered out of band, with the full live DKG through the production `ConductorBridge`; a late fork injected after Round 2 → no `Finalize`.

Until those exist and pass, and E8 is performed, `ConductorBridge::round_two` keeps returning `INV-13: independently authorised Round-2 encryption-key roster unavailable; live delivery blocked`.
