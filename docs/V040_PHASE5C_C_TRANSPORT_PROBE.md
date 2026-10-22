# Phase 5C-C — isolated native encrypted transport probe

> Security review status: **NO-GO for live deployment writes.** The subsequent
> [readiness review](V040_PHASE5C_C_SECURITY_REVIEW.md) identifies inherited
> controller/signer boundary gaps. Passing offline tests are not deployment
> approval. Use the [public read-only checklist](V040_PHASE5C_C_READ_ONLY_PREFLIGHT.md)
> only under its stated scope; it has not been executed.
> **22 October 2026:** B1/B2 are remediated in source with refusal tests (see
> the review's *Remediation* section). Live writes still need the read-only
> preflight and step-specific approval.

Source-only development, 18 October 2026. No persistent conductors, native
node state, credentials or signing policies were accessed during this work.
No source-chain writes, live registrations, live sends or live DKG were run.
Offline test evidence is recorded in `V040_PHASE5C_C_OFFLINE_REPORT.md`.

## Protocol and custody boundaries

The probe uses `protocol_id: "mpc-transport-probe"`, `protocol_version: 1`,
a new proposal, a new session and exactly two participants (threshold two,
`max_round: 1`). Round one belongs to this protocol, never FROST. All core
Envelope checks remain in force. Existing coordinator/integrity source accepts
this SessionSpec without changes; no DNA, entry type or deployed artifact was
modified. FROST Binding rejects this protocol before any DKG initialization.

The CLI never instantiates `Controller`, `AuthenticatedController`, a FROST
party or RelayEngine. It only recovers an explicitly provisioned retained
X25519 identity from a separate probe node's `transport.sqlite`. It never
creates/replaces a missing key or opens `journal.sqlite`. Existing write-once
transport-key binding includes DNA, agent, proposal and session. Therefore the
old FROST proposal's retained keys/state MUST NOT be relabelled or migrated to
a probe proposal. SQLite recovery can perform housekeeping and is a local
state operation, not a read-only inspection.

The existing Lair signer defaults to its original FROST profile. Probe mode
requires BOTH `--probe-profile` and a different, strict policy schema whose
`profile` is `mpc-transport-probe-v1`. Passing either policy to the other mode
fails closed. FROST signing restrictions are unchanged. The probe profile
allows only signed reads (`get_session_status`, `get_inbox`,
`get_encryption_key_bindings`), registration of its one exact retained public
key, and its single planned encrypted send. It does not permit proposal,
acceptance, grant, revocation, arbitrary-function or DKG requests.

Authorization uses a separately provisioned probe capability. There is no
FROST credential loader/fallback. A probe credential must pin purpose,
proposal, grant action, grantor and grantee in the private probe policy.
**This label is not cryptographic proof of credential provenance:** Holochain
assigned grants authorize a function/caller, not a protocol/session. An
operator must independently verify a fresh grant and secure exchange. Do not
copy, relabel or import an existing FROST secret. The existing grant service's
four-byte session tag is not isolation; check full proposal/spec and action.
Stronger grant isolation would require a separately approved DNA design.

## Public plan and signer policy

All JSON inputs must be absolute, owned, regular single-link `0600` files,
not symlinks, and at most 64 KiB. Limits and schema failures reveal no contents.
Keep the parent directory private. Never place secrets in arguments or logs.

`ProbePlan` (`transport_probe.rs`) contains:

- `schema: 1`;
- `record`: existing CeremonyRecord encoding (`schema`, `installed_app_id`,
  `dna_hash`, `proposal_action`, full `spec`);
- exact `sender`, `recipient`, `max_plaintext` (1–128 bytes);
- `expected_payload_hash`: `commitment("mpc-transport-probe/payload/v1", bytes)`;
- `approved_keys`: exactly one `{author, action, public_key}` per member,
  sorted by author, with distinct actions and distinct nonzero keys.

The operator independently reviews and retains these public pins. `keys`
prints explicitly UNAPPROVED conductor observations. It never writes a plan
or promotes observed records into approved ones. Missing, extra, duplicate,
rotated or mismatched records are rejected, including changes to an action
with an unchanged public key. The local registration must match the key
derived from retained native secret material.

The separate probe signer JSON contains `profile`, the existing SignerBinding
as `binding`, the exact CeremonyRecord as `record`, `own_public_key`,
`send_plan` and `capability`. Initially set the last two fields to `null` for
registration/read-only mode. When enabled, `send_plan` is the independently
reviewed ProbePlan. A sender's `capability` has:

```text
purpose = mpc-transport-probe-v1
proposal = exact probe proposal action (39 raw bytes)
grant_action = independently approved new probe grant action
grantor = exact recipient agent
grantee = exact sender agent
cap_secret = privately provisioned Holochain CapSecret encoding
```

The receiver uses its own binding/key and `capability: null`. A profile with
no capability cannot send. No example secret is supplied or generated by the
CLI. Actual policies are never source-controlled. The signer pins full spec,
DNA, app, proposal, session, members, direction, key identities and bounds.
It verifies ciphertext structure/key fields; plaintext limits/digest and inner
bindings are enforced by the native endpoints, since the signer has no
X25519 decryption key. The external signer remains scoped to one proposal,
uses canonical Holochain call hashing, fresh random nonces and 30-second expiry.

## Authenticated payload and durable semantics

A SealedPacket contains a domain-tagged ProbeBody. The authenticated plaintext
includes domain, DNA, full ceremony fingerprint, commitment to the exact
approved registration evidence, complete plan digest, message ID, sender,
recipient, round one, sequence one, payload digest and payload. These values
must all equal independent expected values after decryption. The explicit
message ID commits to domain/DNA/ceremony/direction/round/sequence. Bounds are
128 plaintext bytes, the existing 3 KiB sealed cleartext bound, and 48 KiB
encoded packet. Plaintext is not printed or returned by the endpoint.

The lazy probe ledger uses the transport database, not a DKG checkpoint:

1. Sender commits one immutable `(proposal, sender)` admission, exact plan,
   message ID and ciphertext, in `BEGIN IMMEDIATE`/SQLite FULL synchronous
   storage BEFORE returning it to a signer or starting network IO.
2. Acknowledgement records the returned storage action. It proves remote
   storage response, not native decryption. Malformed/absent acknowledgements,
   timeouts and other failures produce terminal `uncertain` state.
3. Cancellation/crash can leave `pending`; it is equally terminal. No API
   permits resubmission, replacement or resetting that slot, including after
   changing the payload, plan or recipient. Registration has a separate
   fsynced exclusive attempt marker before its signed call.
4. Receiver accepts only the trusted local conductor inbox, validates the
   outer envelope, approved pins, AEAD and every inner binding, then commits
   its receipt marker transactionally. Exact duplicates return `Duplicate`
   without another application effect. Another ciphertext in the same slot
   is a conflict, even if its decrypted plaintext is equal. Invalid input is
   rejected before replay admission.

A crash after a receipt commit but before printing success yields Duplicate
on the next receive. The stored marker is the application effect: this does
not promise exactly-once delivery of console output or external side effects.
A send timeout is bounded at 30 seconds; authenticated reads use the existing
conductor client's RPC behavior. All write uncertainty is terminal. Inspect
before further action; never delete markers/DBs or regenerate a replacement
ciphertext as a retry. The low-level signer socket itself is not a durable
one-shot admission service: trusted callers must use this endpoint/CLI.

## Offline commands

```sh
cargo build --offline --locked -p holochain-mpc-dkg-worker --features lair-signer --bins
cargo test --offline --locked -p holochain-mpc-dkg-worker --features lair-signer \
  --test transport_probe --bin mpc-transport-probe
```

The integration suite uses synthetic keys/capabilities and temporary SQLite
stores. It reconstructs coordinator messages from authorized call parameters,
uses deliberately invalid mock signatures, and exercises process restarts.
It does NOT establish real Lair signing, websocket interoperability, deployed
WASM provenance, capability enforcement by a conductor, or live delivery.

## Proposed live deployment — NOT AUTHORIZED OR EXECUTED

Every live step below needs separate operator approval. Keep the existing
FROST/Phase 5C-B node directories and policies untouched. Do not start
`mpc-node serve` or `mpc-relay-service` for a probe.

1. **Approve public configuration first:** distinct probe proposal/session,
   full SessionSpec, same independently verified DNA/app, exact A/B agents,
   bounded non-sensitive payload and digest. Use the distinct `mpc-phase5c-provision propose-probe` subcommand, with
   `--threshold 2` and `--confirm-probe-proposal-write`, only after approval.
   It uses the existing proposal options (`--app-port`, `--origin`,
   `--app-token-file`, `--agent-b64`, `--lair-root`, `--installed-app-id`,
   `--dna-b64`, `--participants-file`, `--record-out`). The original `propose`
   command still creates FROST proposals and is ineligible for diagnostics.
   Read-only `status` and separately approved `accept` can then use the new
   record. No proposal command was executed during development.
2. **Approve setup writes separately:** create/accept that proposal; provision
   distinct private probe node directories pinned to it; explicitly create
   new retained transport keys there. Issue/renew app credentials only with
   credential-specific approval. Use no existing persistent node directory.
3. **Approve independent capabilities:** issue the necessary new probe grant,
   verify assigned caller/function/action and exchange its secret through an
   authenticated confidential channel. Keep grant action/purpose bindings in
   a separate private probe policy. Existing FROST credentials are ineligible.
4. Prepare registration-only probe policies, then approve starting each
   signer with `mpc-lair-signer --probe-profile --policy-file <private-file>
   --signer-socket <private-socket> --lair-root <operator-approved-root>`.
   The passphrase is entered only in the signer's terminal prompt. Signing
   uses the existing agent authority; no signing key is exported.
5. **Approve each registration:** run the probe CLI's `register-key` once per
   node, with `--record` and `--confirm-probe-registration-write`. It recovers
   the retained key, checks no own observed registration exists, commits an
   exclusive registration attempt marker, registers and verifies exact
   readback. Any uncertain result requires manual chain inspection; missing
   links/local receipts do not prove the chain write failed.
6. Collect public observations with `keys --record <record>`. Independently
   compare both agents' author/action/public-key evidence and approve the
   resulting plan. Configure sender `send_plan` + dedicated capability and
   receiver `send_plan` + null capability; approve replacing/restarting only
   the new probe signer instances. Do not modify existing FROST policies.
7. **Approve exactly one send:** `send --plan <plan> --payload-file <file>
   --confirm-probe-send`. The payload file is a private JSON byte array.
   Preserve message ID, plan digest, admission status and public receipt.
8. **Approve local receipt writes:** on B run `receive --plan <plan>
   --confirm-local-receipt-write`. PASS requires B's own pinned conductor
   inbox, recovered native key, exact sender evidence, authenticated inner
   identity and approved payload digest. Run receive again only with approval
   to confirm Duplicate. Native recovery and ledger housekeeping write locally.
9. Inspect A with `inspect --plan <plan> --confirm-local-state-access`. A
   pending/uncertain attempt remains terminal even if B proves receipt.
   Approve any new experiment under a fresh probe proposal; no automatic retry,
   grant revocation or transition to DKG is included.

Every CLI invocation also needs explicit `--node-dir`, `--app-socket` (numeric
loopback), `--origin`, `--app-token-file` and `--signer-socket`. All paths are
operator-supplied; no persistent path is embedded in the program. The signer
only serves its exact profile/proposal and never creates credentials.

## Remaining security limits

This is development custody under one OS UID. Master keys remain files on
the same machine as encrypted databases. File permissions, zeroizing buffers
and SQLite durability do not provide hardware custody, anti-rollback,
protection against a compromised same-UID process or malicious local conductor,
or independent verification of Holochain signatures. A restored old database
can erase admission/replay knowledge. Prohibit rollback operationally pending
independent storage/key-custody review. Capability labels are trusted operator
configuration, and a standalone signer can be called by another same-UID
client. SalsaBox authenticity is used together with conductor provenance; it
is not transferable proof that only one party could have made the ciphertext.
