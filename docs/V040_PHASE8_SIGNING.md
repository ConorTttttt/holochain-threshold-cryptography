# v0.4.0 Phase 8 — approved 2-of-3 signing across independent nodes

22 October 2026 (Europe/London). Implemented by the coding assistant at the
operator's request, following three operator decisions:

- each node's operator approves through a CLI;
- every selected signer aggregates;
- signing uses a separate signer profile.

**Development evidence on a single host, not production key custody and not
an independent audit.** No persistent 5B/5C state was touched.

## Result

In the disposable three-conductor rehearsal (`scripts/phase6_rehearsal.py`,
2 of 2 consecutive runs), the following happened after the DKG:

1. All three operators attested the group.
2. Nodes 1 and 3 approved one signing plan.
3. Two independent `mpc-sign` services, each behind its own Lair signer in
   the signing profile, exchanged commitments and shares over Holochain.
4. Both aggregated, verified and published the same 64-byte signature
   within about 12 seconds.
5. **OpenSSL 3.5 verified it as a standard RFC 8032 Ed25519 signature**
   under the group key, and rejected it over a tampered message.

Each signer's journal records exactly one burned (`published`) nonce. The
unselected node reserved none. A second run of the same operation was refused
("deadline already registered"). The unselected member could not obtain a
signing policy.

## Protocol

No zome or DNA change: the coordinator already stores activation attestations,
signing approvals and result commitments.

1. **Activate** (`mpc-phase5c-provision activate-group`, write,
   `--confirm-activation-write`). The relay service writes
   `group-descriptor.json` into the node state when DKG completes. The
   operator attests to its digest only after `recover_share` proves this node
   durably completed exactly that descriptor. The group is active only when
   every member has attested the same descriptor.
2. **Plan** (`make-intent`, local). A public `SigningPlan` holds the
   descriptor, a random 32-byte operation id, the message and the sorted
   selected signers. The same file goes to every selected operator.
3. **Approve** (`approve-intent`, write, `--confirm-approval-write`). Allowed
   only after full activation, and only by a selected signer, once per
   operation. It publishes the `SigningIntent` digest. The automated signer
   can never approve.
4. **Sign** (`mpc-sign`, behind `mpc-lair-signer --signing-profile`).
   1. Reopen the sealed share (Phase 7).
   2. Wait for full activation and every selected approval.
   3. `ControlledSigner::prepare` registers the operation deadline and reserves
      and burns the nonce before the commitment leaves the process.
   4. Send the commitment as round 4 to every other selected signer.
   5. Each signer builds the same `SigningPackage` locally, signs once and
      sends its share as round 6.
   6. Every selected signer aggregates and verifies with
      `verify_activated_artifact`, then publishes the result commitment and
      writes `artifact.json`, `signature.bin`, `group-public-key.bin` and
      `signed-message.bin`.

   Frames carry the operation id. The inbox slot (round, sequence) is derived
   from the operation id. Senders are the conductor-authenticated provenance.

## Signing signer profile (`mpc-frost-signing-v1`)

- `SigningSignerPolicy` pins one plan, the binding and one capability for each
  other selected signer.
- It signs only:
  - `get_inbox`, `get_group_activation_attestations` and
    `get_signing_approvals`;
  - round-4/6 frames of that operation, as envelopes rebuilt from the pinned
    spec and addressed to the other selected signers;
  - `publish_result_commitment`, only for an artifact that verifies under the
    plan's group key.
- It refuses approvals, activation, key registration, provisioning and every
  other call. The DKG-time FROST policy and the probe policy are not accepted
  in this mode, and the reverse also holds.

## Tests

| Suite | Covers |
|---|---|
| `tests/signing_session.rs` (`npm run test:signing-session`, part of `test:native`), 4 tests | Two sessions over recovered shares produce one byte-identical verified signature, and a repeat is refused. There is no signature without every selected approval. An outsider cannot sign. A conflicting approval or activation fails closed. Tampered shares never aggregate |
| `signing_signer::tests` (`npm run test:signing-signer`), 2 tests | Allowed reads. Refused approval, activation and registration calls. Only this operation's frames to selected peers are signed. Forged results are refused. Wrong profile, roster or capabilities are rejected |
| Rehearsal (`npm run rehearse:three-nodes`) | Live, as above |

## Limits

- **Single host.** One Linux user, a local bootstrap server, throwaway
  passphrases typed by the harness. Separate machines and networks are not
  yet exercised.
- **Liveness.** Any failure, including an offline selected signer, aborts the
  operation. A new plan with a new operation id is required; nothing is
  retried.
- **Custody.** The share is decrypted in the `mpc-sign` process, under the same
  UID and master-key file as Phase 7. There is no anti-rollback protection.
- **Message semantics.** The plan carries arbitrary bytes. Deciding what may be
  signed (application policy, human review UI) is outside this phase.
- **Partition and kill behaviour** during signing is not yet tested beyond
  fail-closed aborts.
