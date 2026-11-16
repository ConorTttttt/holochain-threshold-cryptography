# Sprint 1 — Stage 2C coordinator inbox integration

**Scope:** native DKG relay, signed Holochain app-client and FROST signing consumer.  
**Baseline:** `feature/v0.4.0-stage2c` (the implementation is not on `main`).  
**Review branch:** `agent2/stage2c-inbox-slot-integration-20261115`.  
**Status:** code and regression tests authored; **compilation and execution not verified** in this environment (Rust/Cargo unavailable). Treat as a draft for CI and independent security review.

## What changed

The coordinator's existing `get_inbox_slots(proposal: ActionHash) -> InboxSlots` was left unchanged. The wire representation is now understood by the native client:

```rust
struct InboxSlots {
    envelopes: Vec<Envelope>,
    conflicts: Vec<WithheldSlot>,
    over_quota: Vec<WithheldSlot>,
}
struct WithheldSlot {
    sender: Vec<u8>,
    round: u32,
    sequence: u64,
    variants: Vec<StoredVariant>,
}
struct StoredVariant {
    envelope: Envelope,
    storage_actions: Vec<ActionHash>,
}
```

The native client checks the complete response before exposing it to protocol consumers: bounded total slots and storage evidence; pinned ceremony/session, sender and recipient checks; payload commitments; one unique slot across all response categories; correct variant metadata and distinct payload variants. Bad or undecodable data is an error, not an empty inbox. The coordinator's `ActionHash` provenance is retained, not replaced by untrusted client-supplied metadata.

`MpcCall::GetInboxSlots` and `SignIntent::ReadInboxSlots` bind the exact signed function name and the pinned proposal, cell and agent. The DKG signer and separate signing signer approve `get_inbox_slots` and refuse `get_inbox`. The probe signer and legacy `GetInbox` decoder remain available for their distinct, non-DKG/non-signing diagnostic purpose, but **native DKG and signing do not call them**.

`MpcTransport::get_inbox_slots` replaces `get_inbox` in the DKG relay contract. `SigningTransport::inbox_slots` replaces the vector-returning signing method. Every active DKG poll checks conflicting and over-quota slots from other ceremony members in DKG rounds 1–3 **before** deduplicating accepted envelopes. A relevant slot immediately aborts and poisons the relay, including if its original value was accepted in a previous poll. Conflicts belonging only to signing rounds do not veto DKG.

Every signing poll checks conflict and over-quota evidence from **selected signers** for the approved operation sequence in rounds 4 and 6 before processing messages or consulting its previously-seen cache. An unrelated sender, round or operation sequence cannot veto the signing session. A previously seen ID changing its envelope also causes a direct error. Errors after `SigningSession::begin` continue through the existing durable `record_abort` path. Activation gates, explicit signing approvals, nonce reservation and result-signature validation remain unchanged.

The shared slot types depend on `holochain_zome_types`; that crate is now a non-optional direct dependency of `mpc-dkg-worker`, because the relay and signing code compile without the `conductor-client` feature.

## Compatibility and migration

**There is no automatic downgrade.** A native worker with this change requires a deployed Stage 2C coordinator exposing `get_inbox_slots` and matching native signer profiles. A missing function, unexpected reply shape, refused signed call or stale signer policy fails the operation. `SignedAppTransport` reports that `get_inbox_slots` is required and does not retry `get_inbox`. Update coordinator DNA and native client and signer policies as a coordinated deployment; do not resume or restart a partially run DKG or reuse a signing operation ID after a failed upgrade attempt.

Outgoing `send_protocol_message` and result-publication semantics are not changed. As before, ambiguous or rejected writes are **not retried automatically**: retrying may duplicate actions or reuse protocol randomness/nonce state.

## Regression evidence and verification status

The following regression tests were added or modified. They are **authored only, not yet executed** here:

| Location | Scenario | Expected assertion |
| --- | --- | --- |
| `tests/relay_simulation.rs` | Same-slot DKG variant delivered later than a previously accepted message | Relay aborts on explicit conflict evidence |
| `tests/relay_simulation.rs` | Unrelated signing-round slot is conflicting | DKG messages still processed |
| `tests/relay_simulation.rs` | DKG over-quota slot | Relay aborts and stays aborted |
| `tests/signing_session.rs` | Selected signer late commitment conflict | Operation aborts, result not published, abort journal records terminal failure |
| `tests/signing_session.rs` | Selected signing share over quota | No result published |
| `tests/signing_session.rs` | Conflict from non-selected member | Selected signers still produce identical verified result |
| `src/inbox_slots.rs` | Typed wire roundtrip, duplicate slot and empty action evidence | Correct representation accepted; ambiguous/malformed evidence rejected |
| `src/inbox_slots.rs` | Old coordinator's vector response | Cannot decode as `InboxSlots` |
| `src/signed_call_policy.rs` | Signed call binds exact API name | Old and new signed operations cannot be substituted |
| `src/lair_signer.rs`, `src/signing_signer.rs` | Signer allowlists | New read allowed, legacy read denied |
| Existing `tests/signing_session.rs` | Explicit activation/approval gates, nonce reuse, abort journal, signature verification | Must remain passing |

Run from the workspace root on a Rust environment able to build the pinned Holochain 0.7.1 stack:

```sh
cargo test -p holochain-mpc-dkg-worker --test relay_simulation
cargo test -p holochain-mpc-dkg-worker --test signing_session
cargo test -p holochain-mpc-dkg-worker --lib --features conductor-client
cargo test -p holochain-mpc-dkg-worker --lib --features lair-signer
cargo test --workspace --all-features
```

**Execution evidence:** unavailable: the task runner has no `rustc`/`cargo` installed and cannot fetch the repository directly over the container network. No tests or builds are represented here as passing. Before merging, capture command output/CI artifacts and resolve any compiler warnings or failures. Also perform a live compatibility test with an older coordinator and a Stage 2C coordinator; the current old-format unit test is not a substitute for a live conductor rejection.

## Remaining limitations and security boundaries

- Inbox snapshots are authenticated by the **trusted, pinned local conductor**. They are not an independent chain proof, and a compromised/stale local conductor may suppress evidence. A consumer cannot detect equivocation that has not yet become locally visible.
- Poll-time checking detects conflicts visible **on a later active poll**, not conflicts arriving after the relay has completed or after signing has already published its result. Finality and post-completion monitoring require a separate protocol-level design; none is claimed here.
- Slot-level quota evidence is fatal only if it belongs to slots the current DKG/signing operation could require; unrelated slots stay available. Quota exhaustion still requires an operator to start a new ceremony/operation with fresh identifiers rather than retry unsafe writes.
- This change does not modify the coordinator's storage/query behavior, remote authentication model, group activation, signing approvals or the durable nonce manager.
- Testing so far uses mocked conductor snapshots; end-to-end live websocket, DHT propagation timing, concurrent chain-head races and restart recovery require CI/integration infrastructure.

**Merge gate:** Cargo tests passing, live Stage 2C read demonstrated, old-coordinator rejection demonstrated, and Agent 1's independent security review completed.
