# Sprint 1.7 — Signing Slot Identity and Collision Characterisation

**Owner:** Agent 23. **Baseline:** 899e433d057a4d1a0533e2304a2493edb75ad82f. **Finding:** S1-L01 OPEN. **Status:** proposed deterministic fail-closed v1 policy and source regressions; NOT an implemented collision-free namespace, NOT dynamic verification.

## Exactly what the v1 source does

- crates/mpc-dkg-worker/src/signing.rs, SigningPlan::sequence (baseline lines 90–97): interpret the first eight bytes of the 32-byte operation ID as big-endian u64, then calculate (head % (u64::MAX - 1)) + 1. The comment claiming that two operations never share a slot is **false**.
- Operation A with the first eight bytes 11 22 33 44 55 66 77 88, and arbitrary nonzero last 24 bytes, and operation B with the **same first eight bytes** but byte 8 flipped, have different full operation IDs and the identical legacy sequence. In fact each fixed eight-byte head has 2^192 possible 256-bit IDs. The modulo also aliases head values 0 and (2^64 - 2), and head values 1 and (2^64 - 1). A different 64-bit hash alone cannot eliminate collisions.
- The coordinator's private InboxEvent records are scoped to a proposal ActionHash and recipient source chain. Its logical slot key is (authenticated sender, round, sequence), **not** operation ID. Sender and recipient are additionally constrained by authenticated provenance and cell ownership.
- For the same sender, recipient, round and sequence, two different FROST frames encode different payloads. If the first is already visible on the source chain, receive_protocol_message returns inbox_conflict and stores neither second variant nor a new receipt; an identical replay returns AlreadyStored. With concurrent relaxed writes, both variants can be persisted. partition_inbox then puts that slot in conflicts and withholds both; other slots remain served. This is a deterministic **availability failure**, not a choice of which operation wins.
- If only the prior frame is served, SigningSession::ingest checks the full Frame.operation_id against the current plan and errors with 'signing frame for another operation in this slot'. run_signing abort-journals errors inside its async result block. relevant_signing_slot detects selected senders' withheld rounds 4 and 6 at the colliding sequence; nonselected senders are not allowed to veto. The native frame check is **not** a coordinator namespace fix.
- Independently, approvals are indexed by the entire operation ID and the SigningIntent digest covers operation, message, roster, epoch, proposal and group activation. Every selected signer must independently approve the exact intent. AuthenticatedShareCollector requires the exact signing package and its full FROST binding; the wrapped signed bytes also contain the full operation ID. A colliding transport number alone does not grant signing approval or turn shares from operation A into a valid operation-B aggregate.
- Important caller obligation: frost::verify_artifact verifies over the operation ID **embedded in the artifact**; it does not receive an expected operation ID. Consumers MUST compare artifact.operation_id to the requested/approved plan.operation_id and check the expected group, message and roster context before accepting the result. Do not claim signature verification alone enforces an external expected operation ID.

## Chosen v1 disposition — deterministic rejection, no reinterpretation

For the existing v1 transport, an operation encountering any relevant occupied or conflicted (sender, recipient, round, sequence) slot belonging to a different full operation ID MUST abort rather than pick one. A coordinator conflict, over-quota rejection, unknown outcome, malformed frame or mismatched full operation ID MUST NOT cause automatic retries under a different sequence or reuse of the same nonce/operation ID. Return an explicit collision/availability outcome to the operator, burn already-reserved slots, and require a *fresh, independently approved operation ID* if a retry is appropriate. The new ID must be checked for prior slot occupancy before any nonce reservation where an authoritative check exists. Preflight alone is not race-free: continue validating slot evidence after every delivery.

This is the **proposed** normative disposition for v1, not a newly implemented durable collision ledger. Current source enforces core rejection in particular paths, but there is no complete atomic preflight or stable user-facing error category. The conflict may be observed only after reserving a nonce; this is safe but reduces liveness. A future version MUST use a 256-bit operation namespace or explicit collision registry if reliable long-lived signing is required. Never silently reinterpret existing InboxEvent data as v2.

## Test contract and coverage

The new agent-specific regressions live in crates/mpc-dkg-worker/tests/signing_session.rs:

- distinct_operation_ids_can_collide_on_legacy_sequence: construct two validated plans differing in byte 8, assert same sequence and different intent digest.
- colliding_operations_never_cross_authorize: full-operation-ID approvals cannot authorize the other plan; selected approvals remain unanimous.
- colliding_operations_cannot_cross_aggregate: run real native 2-of-3 signing for A with simulated authenticated transport, retain A frames, approve colliding B separately, and require both B signers to fail with the wrong-operation frame and no additional artifact. This tests native refusal, not real conductor slot behaviour.
- per_sender_quota_is_isolated and honest_sender_quota_exhaustion_is_detected: exercise the coordinator's pure partition function via the worker's test dependency, without a conductor.
- group_renewal_uses_fresh_proposal: test fresh-proposal descriptor isolation using **fabricated** new descriptor/votes, not a second real DKG.
- old_exhausted_group_is_not_silently_reactivated: deliberately **ignored and known-red** pending an actual durable expiry gate. Do NOT count it as passing.

**Evidence:** E1 source authored on agent branch. E2 compilation NOT RUN. E3 native tests NOT RUN. E4/E5/E6 NOT RUN. E7 adversarial code authored, NOT executed. E8 independent review NOT RUN. The runner has no cargo/rustc; direct git clone fails DNS. No test result is inferred from compilation-free source inspection.

Reproduction after integration, on the exact immutable merged commit with a pinned toolchain:

~~~sh
git rev-parse HEAD
cargo check --locked --workspace --all-targets
cargo test --locked -p holochain-mpc-dkg-worker --test signing_session -- --nocapture
cargo test --locked -p mpc --lib inbox_tests -- --nocapture
# The known-red expiry test needs a reviewed production gate before unignoring.
~~~

Record exact command, toolchain, exit code, full redacted log and commit. Genuine conductor collision tests must exercise receive_protocol_message, get_inbox_slots, conflict/over_quota and signed approvals at E5/E7. 
