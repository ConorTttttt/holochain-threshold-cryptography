# S1-M02 — Cross-application and exact-proposal isolation (blocking design)

**Status: BLOCKED FOR DEPLOYMENT / ARCHITECTURAL DECISION REQUIRED.**
**Date:** 2026-11-16. **Base:** Sprint 1 integrated Stage 2C branch,
`sprint1/agent6-stage2c-integration-20261116` at
`899e433d057a4d1a0533e2304a2493edb75ad82f`.
This document does **not** approve a production release, a DNA migration,
or a re-recording of existing artifacts. S1-M02 remains OPEN for the installed
coordinator and for SDK consumers of the legacy `Envelope`.

## Finding and reproduced contract gap

The v1 `SessionSpec` contains `application_id` and `context_hash`;
`Envelope` contains neither. `Envelope::validate_received` checks session
ID, protocol, roster, sender provenance, recipient, round and payload digest,
but not proposal action or application context. A message constructed from A
passes generic validation against B when the two valid specs differ only in
application ID/context but share session ID, protocol and roster. Equally, the
same spec can be published as **two different proposal actions**. The recipient
coordinator accepts a fully accepted proposal argument separately and saves
an `InboxEvent { proposal: B, envelope: A }`.

The test `legacy_v1_cross_application_acceptance_is_reproduced` documents
this current behavior. The coordinator Sweettest
`legacy_v1_coordinator_replay_is_reproduced` exercises the actual accepted
proposal path with a member-authenticated call and must be run against the
current Stage 2C DNA on **disposable** agents. These are **vulnerability
reproduction** tests, not fix assertions. They must be replaced with strict
rejection assertions once the migration is implemented.

**Threat assumptions:** Two fully accepted proposals intentionally share a
public 32-byte session ID, protocol and participant roster; an authorized
participant can deliver the wrong proposal's envelope through the recipient's
assigned capability. This does **not** require guessing a random session ID.
Authenticated Holochain caller provenance prevents unrelated outsiders from
posing as that participant. A malicious *authorized* member can always craft
a fresh B-specific message; application/proposal binding prevents replay of
the **unchanged A envelope**, not malicious re-authoring. A plain SHA-256
payload digest is neither a sender signature nor a MAC.

### Existing independent protections

The native FROST `Frame::encode/decode` checks the exact proposal action,
the signed-byte path binds proposal/operation/context, and encrypted DKG round
two uses ceremony-associated authenticated data with pinned keys. The echo /
attestation and transport checks are separate. These layers remain unchanged.
They must be retested; none of their protections can be claimed for a generic
SDK consumer or generic coordinator intake.

## Opt-in v2 *core-only* primitive in this PR

`holochain_mpc_core::{CeremonyBindingV2, BoundEnvelopeV2, BoundInboxV2}`
is **not yet wired to a coordinator extern, Holochain entry type, SDK
transport, or native FROST**. Its presence does **not** remediate delivery
through the old `receive_protocol_message` API.

* A trusted host constructs `CeremonyBindingV2` from the **actual** DNA
  identity, the **exact fully accepted** SessionProposal action and its
  `SessionSpec`. The host verifies the canonical application description
  and derives/verifies its `context_hash` (the core cannot establish this).
  Both DNA hash and ActionHash are raw 39-byte values here; a Holochain adapter
  must also verify their typed hash prefixes and chain membership. Neither
  field may come solely from the untrusted remote caller.
* The v2 domain-separated binding digest includes, with explicit lengths:
  DNA hash, proposal action, session ID, application ID, protocol ID/version,
  context hash, complete ordered participant roster, threshold and max round.
  `SessionSpec::validate` enforces sorted unique participants. This avoids
  ambiguous concatenations or shared-session context substitution.
* `BoundEnvelopeV2` is a **different** wire type with
  `wire_version = 2`, full ceremony-binding digest and an envelope digest
  covering all routing fields and payload. Validation checks the complete
  trusted binding and authenticated transport sender. The digest is
  unkeyed: if untrusted relays must preserve end-to-end origin authenticity,
  the signed/MACed bytes must separately cover the same binding and payload.
* `BoundInboxV2` binds its replay ledger to the first accepted ceremony
  and refuses cross-ceremony reuse. Like the legacy ledger, adapters must
  atomically persist inbound replay state before acknowledging/acting.
* v1 `Envelope` keeps **exactly** its previous fields, constants, digest
  label, serde representation and validation semantics. No `From<Envelope>`
  or implicit upgrade/downgrade exists. V2 rejects `wire_version=1` even
  with a forged binding field, and v1 rejects `wire_version=2`.
  Unknown fields in the new v2 types are refused by serde.

This is a **versioned candidate design**, not an approved on-chain wire
migration. SDKs must **not** claim isolation from simply depending on the
new core module while still calling v1 coordinator externs.

## Compatibility and migration decision required

| Boundary | Observed Stage 2C state | Required v2 approach |
|---|---|---|
| Transport RPC | `IncomingMessage { proposal, envelope: Envelope }`, `SendMessage`, plus `get_inbox[_slots]` return v1 | Introduce explicitly named versioned APIs (e.g. `send_protocol_message_v2`, `receive_protocol_message_v2`, `get_inbox_slots_v2`) with typed v2 input and strict refusal of v1. No negotiation or fallback. |
| Source-chain entry | Private integrity `InboxEvent { proposal, envelope: Envelope }` | Define a **distinct** v2 private entry type / storage path, with an approved append-only entry-type strategy or new-DNA migration. Do not mutate the historical v1 entry codec in place. |
| Stored v1 messages | Permanently written private author chain records, v1 codec and index | Historical v1 messages remain historical v1. No automatic reinterpretation, conversion to v2, cross-version slot merging or replay-ledger carry-over. Old sessions must terminate or explicitly complete on the old path under documented risk; new v2 sessions refuse their input. |
| Proposal/acceptance | Spec does not require session-ID uniqueness across proposals | Bind to action hash + DNA hash, not session ID alone. New proposals must be fully accepted within the **new exact** DNA; reject mismatched or partial acceptances. |
| DNA identity | Integrity-zome entry schema is part of DNA compatibility; coordinator WASM also affects bundle/code identity | Obtain operator-approved DNA update/clone strategy and app/cell migration plan, including hashes, pinned cells, grants, conductor capabilities, key registrations and historical action references. Do not change existing release hashes or conductor binaries in this PR. |
| Native FROST | Already enforces stronger frame/transport binding | Preserve existing framing and signed-byte semantics. Explicitly decide whether to add v2 generic transport around them; never silently reinterpret FROST v1 payloads or sealed data. |
| SDK | Optional read-only foundation; lacks a fully deployed v2 transport | Expose a verified, exact proposal+DNA binding token; require v2 for **new** multi-app sessions and refuse old/new mismatches. Keep legacy APIs labeled unsafe for generic cross-app isolation. |

**Decision requested from architecture/maintainers:** choose between (A) a
separate v2 DNA/cell namespace with explicit migration to fresh proposals
(**preferred for safety and rollback clarity**) or (B) an audited in-place
upgrade with a new private entry variant and documented old-cell compatibility.
Specify whether v1 intake is disabled on the new DNA, whether existing v1
sessions may complete in the old cell, how old grants are revoked/retired,
how stored v1 source-chain records are read, and how release inventories and
app bundles are attested. In both models no v1-to-v2 automatic downgrade and
no shared ambiguous envelope deserialization are permitted. Consent and a
migration rehearsal are required before claiming a completed fix.

**Rollback rule:** Reverting a new app to v1 or pointing a v2 SDK at an old
coordinator is an explicit incompatible configuration, not recovery. Do not
silently retry under `receive_protocol_message` or reuse old replay state.
Choose a fresh proposal and cell after compatibility failure.

## SDK application isolation contract (required, not yet deployed)

An SDK may claim **exact proposal isolation** only if all these hold:

1. Canonical, deterministic, versioned application intent bytes are
   independently reconstructed/verified by the app; their SHA-256 is the
   proposal `context_hash`. Encoding, field order, numeric normalization,
   locale and domain separation must be specified by the app.
2. The trusted Holochain adapter verifies the actual DNA hash and proposal
   action, the exact proposal's spec, the accepted roster and caller
   provenance. SDK consumers never take the binding from untrusted payload
   claims.
3. Every outbound and inbound message is decoded in **strict v2 mode**,
   verified against that binding, then processed under a ceremony-bound
   durable replay ledger. Reject v1 and mixed-mode messages before storage
   or effects; no fallback. Conflicting or over-quota slots remain fatal as
   required by the Sprint 1 inbox-slot security work.
4. For confidentiality, sealed packets remain encrypted and authenticated
   with context-aware AD and pinned keys. For origin authenticity beyond
   authenticated transport, the message authentication covers v2 binding,
   routing and payload; the SHA digest alone is not enough.
5. Ceremony status, FROST transcript checks, unanimous activation and signing
   authorization remain independent gates. A local completed DKG does not
   imply globally active signing authority.

Until the coordinator and native/SDK paths are migrated and tested, this
contract is a **future requirement**, not a statement about current v1.

## Tests, acceptance and evidence

Pure core regression names (opt-in v2) in `bound_v2.rs`:

- `cross_application_envelope_replay_is_rejected` — only application ID,
  only context hash, then both differ; session ID and roster are equal.
- `cross_proposal_envelope_replay_is_rejected` — only proposal action and
  only DNA hash differ; also refuses cross-bound replay-ledger reuse.
- `same_proposal_valid_envelope_still_delivers` — authenticated delivery
  succeeds once and the replay is rejected.
- `legacy_v1_cross_application_acceptance_is_reproduced` documents current
  v1 weakness; `legacy_wire_version_and_mutations_fail_closed` covers v2.
- Coordinator Sweettest `legacy_v1_coordinator_replay_is_reproduced` exercises
  current bad storage/serving of A under B, and must be **inverted** to a
  rejection test on a migrated v2 coordinator.

**Outstanding required deployment gates:** Write the three same-named
**coordinator** v2 rejection/delivery tests (including stored-read after
reload), mixed-codec/cell/grant downgrade tests, private source-chain
migration/rollback tests, and full signed/authenticated FROST regressions.
Run on a *fresh disposable* multi-conductor setup and pin the exact DNA hash.
Do not rely only on the core tests to close S1-M02.

Suggested verification commands after the build environment is available:

```sh
cargo test -p holochain-mpc-core
cargo test -p holochain-mpc-security
cargo test -p holochain-mpc-frost-ed25519 --test three_agents
npm run build:happ
cargo test -p mpc --test cross_application_isolation -- --nocapture
cargo test -p mpc --test inbox_hardening
```

**Execution evidence:** Source inspected from the exact GitHub branch. This
environment has **no rustc, cargo, Nix or conductor** and the repository Git
remote is unreachable from its local shell; no Rust/Sweettest/FROST test is
claimed as run or passing here. A new PR may trigger remote CI, but its logs
must be inspected before claiming a passing regression.

**Release disposition:** S1-M02 remains **OPEN / BLOCKING** for generalized
multi-application SDK use until an approved versioned coordinator transport
and migration proves the acceptance criterion. Independent high-severity
custody/release blockers from Sprint 1 are unaffected by this work.
