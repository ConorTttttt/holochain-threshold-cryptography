# v0.4.0 Phase 7 — durable custody of completed FROST shares

22 October 2026 (Europe/London). Source-only, offline implementation by the
coding assistant at the operator's request. **Development-grade custody, not
production key custody and not an independent audit.** No conductor, Lair,
credential or persistent node state was accessed.

## What changed

Before Phase 7 the worker kept the completed FROST `KeyPackage` in memory only;
it was lost when the worker exited, so no signature could follow a restart.

- **Sealing.** A durable `AuthenticatedController` (`mpc-node serve`, or the
  test worker with persistence) now seals a `ShareCustody` record when a DKG
  reaches `Completed`. The record holds the binding, `KeyPackage`,
  `PublicKeyPackage` and `GroupDescriptor`. It is written with the existing
  `RuntimeStore::seal_share`:
  - XChaCha20-Poly1305 under the node's master key;
  - AAD binds proposal, epoch, owner and the group descriptor digest;
  - write-once per `(proposal, epoch, owner)`.
- **Ordering.** The seal happens BEFORE completion is journaled and BEFORE the
  `Completed` reply leaves the worker. If sealing fails, the ceremony aborts.
  A share sealed under a journal that never reached `completed` (a crash
  between the two writes) is refused by recovery, so no share is usable unless
  the node durably acknowledged completion.
- **Recovery.** `recover_completed_share(store, context, descriptor)` reopens
  the share only if ALL of these hold:
  1. the journal for this proposal, agent and session is `completed`;
  2. `descriptor` is exactly the `Completed` reply this node journaled (its
     reply digest matches);
  3. the AAD-bound ciphertext decrypts under this node's master key;
  4. the custody schema, binding, descriptor and session match;
  5. the key package identifier is this agent's FROST identifier;
  6. the public key package hash and group verifying key match the descriptor.

  Signing still requires an `ActivatedGroup` (unanimous attestations) and an
  approved `SigningIntent`, enforced by `ControlledSigner` with its durable
  nonce reservation and burn.

No zome, DNA or wire format changed. The deployed DNA hash is unaffected.

## Tests (`npm run test:share-custody`, part of `test:native`)

| Test | Shows |
|---|---|
| `sealed_shares_survive_worker_exit_and_produce_threshold_signature` | Three durable, MAC-authenticated controllers complete a 2-of-3 DKG; every worker is dropped; shares are reopened from disk; activation, intent approval and two `ControlledSigner`s produce a group signature that verifies, and a tampered message does not |
| `shares_survive_sigkill_of_separate_worker_processes` | Three real `mpc-dkg-worker` processes with persistent journals complete the DKG and are SIGKILLed; every share is recovered with the right FROST identifier |
| `recovery_refuses_wrong_descriptor_key_owner_or_second_seal` | Wrong epoch, transcript hash or group key; another member's context; wrong master key; and a second seal into the same slot are all refused |
| `aborted_ceremony_seals_nothing_recoverable` | An aborted durable DKG leaves nothing recoverable |

The network is an in-memory stand-in for authenticated zome responses, as in
`relay_simulation.rs`. Holochain transport is covered by the Sweettests.

## Limits that remain (Phase 7 is NOT complete for production)

> **Update, 26 October 2026:** `V040_PHASE7_CUSTODY_HARDENING.md` adds
> anti-rollback evidence (an authenticated custody chain plus an external
> anchor), layout and key-source checks, encrypted backup and restore, and
> retire/erase/retention. The limits below are kept as written on
> 22 October. Read them together with that document's threat table and its
> own limits. It is still not production custody.

- **Same-UID custody.** The master key file, the journal and the worker share
  one Linux user. A compromised same-UID process can read the master key and
  open the share. Dedicated OS users or a hardware-backed key are required.
- **No anti-rollback.** Restoring an older `journal.sqlite` removes nonce
  reservations and burns made after the backup. FROST nonces themselves are
  never stored, so a rollback cannot replay a nonce. It can, however, let an
  already-signed operation be signed again. Use append-only external evidence
  or a monotonic counter before valuable use.
- **No backup/restore procedure.** Losing the master key or journal loses the
  share. Threshold 2-of-3 tolerates one loss; a re-sharing protocol is not
  implemented.
- **No signing service.** Recovery and `ControlledSigner` are library APIs.
  Carrying activation attestations, approvals, commitments and shares between
  independent nodes over Holochain is Phase 8 work.
- **Lifecycle.** The share is retained until the operator deletes the journal.
  There is no expiry, revocation or epoch rotation.
