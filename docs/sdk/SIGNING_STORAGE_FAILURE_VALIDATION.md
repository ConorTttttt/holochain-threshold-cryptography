# Sprint 1.7 — Signing Storage Failure Validation (Fable F-8 / A28)

**Owner:** Agent 20 — signing storage failure and nonce-state recovery  
**Date:** 2026-11-16 UTC  
**Disposition:** **SOURCE MITIGATION AUTHORED (E1); NOT VERIFIED FIXED**. All new Rust
tests are **NOT RUN**. No production-key, Holochain-cell or release operation was
performed. This document is not an audit or deployment approval.

## Exact source and baseline provenance

- Repository: `ConorTttttt/holochain-threshold-cryptography`.
- Requested baseline: branch `sprint1/agent6-stage2c-integration-20261116`,
  immutable SHA `899e433d057a4d1a0533e2304a2493edb75ad82f`.
- Baseline decision: **unchanged**. PR #7 remains at that SHA; the separately
  submitted Sprint 1.5 work and PR #11 independent review do not constitute a
  newer **validated, integrated** candidate. The Sprint 1.5 test report explicitly
  records an unsuccessful compile at that baseline.
- Isolated implementation branch:
  `agents/sprint17-agent20-signing-storage-f8-20261116`.
- Exact implementation commit: `579218777b4adf287617c4fd4260475557f47380`.
  Native F-8 test commits: `c753d48ace8e965b9eb4102d927f879bdfefe061`
  and `a3682a1bb5e73e8376c68f21f55e09d85661a56a`.
  Storage-boundary test commits:
  `1c514dee94bd039b1fc071b32b0cb755167a4538` and
  `6f6fb58413c4035957ab117ffdd17ebc4e25f0d7`.
  The full test source is present together at exact commit
  `6f6fb58413c4035957ab117ffdd17ebc4e25f0d7`.
- Scope of code changes: `crates/mpc-frost-ed25519/src/lib.rs`,
  `crates/mpc-frost-ed25519/tests/three_agents.rs`, and
  `crates/mpc-runtime/tests/durable.rs`. No wire schema, DNA, integrity zome,
  secret serialization or release hash changes.
- Sources examined: Fable `02_PROTOCOL_ANALYSIS.md`,
  `03_SECURITY_REVIEW.md`, `05_TESTING_AND_VERIFICATION.md`,
  `10_OPEN_QUESTIONS.md`, and `09_RESEARCH_REFERENCES.md`, all scoped to
  historical `8dec223`; current `docs/sdk/API_CONTRACT.md` and
  `docs/THREAT_MODEL.md` at `899e433d`. The separately requested
  `SPRINT15_SECURITY_REVIEW.md`, `SPRINT15_FINDINGS_REGISTER.md` and
  `SPRINT15_TEST_EVIDENCE.md` are **not present on the baseline**; they were
  inspected on PR #11's distinct commit
  `25afdd6bfc979259cec9416ae5d104780ef384f6`.
  Their separate, unmerged status is preserved.

## Current-code trace and finding

At the baseline, `ControlledSigner::prepare` verifies an existing
`ApprovedIntent`, rejects an existing `pending_approval`, calls
`RuntimeStore::reserve_nonce`, calls `Signer::commit`, serializes the public
commitment, calls `RuntimeStore::authorize_commitment`, and **only then** stores
`pending_approval` and returns the commitment.

`Signer::commit` first rejects an existing `Signer.pending`, then creates
a FROST signing nonce/commitment and stores `PendingNonce` in memory.
`authorize_commitment` changes the already-reserved SQLite row to
`published`, writes the authenticated custody event, commits, and performs
the optional external anchor reconciliation **before returning success**.
At the baseline, if authorization returns an error after `commit`,
`Signer.pending` remains `Some` but `pending_approval` is `None`.
Subsequent `prepare` calls may reserve a *new* operation and then fail
`Signer::commit` with `WrongState`. This corroborates the Fable **source trace**
for F-8/A28 on the modern source; it is **not an executed reproduction**.

The original operation's slot remains `reserved` after a rolled-back
authorization transaction, or `published` after a committed-but-unacknowledged
authorization. Neither state allows another reservation for the same
`(proposal, epoch, operation, signer)`. A released commitment was never
returned by the failed call. The bug is a liveness and wasted-reservation defect,
not evidence of observed signing nonce reuse.

### Failure boundaries before publication

| Boundary | Durable state / safety | Test or limitation |
| --- | --- | --- |
| Invalid/non-unanimously approved intent, incorrect message/profile/group, or existing pending approval | Refused before new nonce reservation | `commitment_failure_preserves_approved_intent`; normal code validation |
| `reserve_nonce`: invalid parameters, retired epoch, absent/closed deadline, SQLite begin/insert/event/commit failure | No private nonce exists yet. A failed pre-commit reservation can leave an `open` deadline; owning caller must journal terminal abort | `reserve_nonce_storage_error_is_fail_closed_after_explicit_abort`; **S15-L01 dependency** |
| `reserve_nonce`: committed row but post-commit anchor acknowledgement fails | Original row `reserved`, no FROST nonce generated and no safe same-ID retry | Source ordering; direct deterministic post-commit fault is tested below on authorization |
| `Signer::commit`: signing-message validation, unexpected pre-existing pending state, randomness/nonce generation | If a nonce was created, it must be dropped; never returned or copied into a second operation | Recovery path now drops `pending`; unexpected RNG fault not injectable with current API |
| Serialization of `SigningCommitments` | A FROST nonce may be in memory but no authorization has been recorded | Same cleanup path; serializer rejection not independently injected (known well-formed type) |
| `authorize_commitment`: invalid slot, SQLite begin/update/event/commit errors | Row remains `reserved`; commitment not returned; nonce must be dropped | `authorize_commitment_failure_does_not_publish` and six dependent security/recovery tests, via actual SQLite `BEFORE UPDATE` trigger |
| `authorize_commitment`: SQLite commit succeeds but anchor acknowledgement fails | Row is already `published`; returned error is **ambiguous**, cannot be retried, nonce must be discarded | `authorize_commitment_after_commit_before_ack_is_ambiguous_and_burned` exercises real store commit followed by forced anchor-path refusal |
| Success after authorization | Only then is `pending_approval` set and public commitments returned | Existing positive controlled signing test; new end-to-end recovery-signature test |

The fix confines all fallible operations **after successful nonce reservation**
to one error-handling boundary. On any such error, it calls
`self.underlying.pending.take()` and returns the original error without
setting `pending_approval` or releasing a commitment. Dropping
`PendingNonce` drops the zeroizing FROST `SigningNonces`. It **does not**
restore, persist, retry, or rebind the nonce. It does **not** delete the
existing SQLite slot or silently re-authorize an ambiguous write.

## Recovery policy (security requirement)

1. A failed `prepare` returns no public commitments. The caller must not
   transmit or fabricate one, use a cached result, or call `sign` for that
   operation.
2. A slot left `reserved` or `published` is permanently consumed; its
   original `(proposal, epoch, operation, signer)` must not be re-reserved or
   reset. The original signing operation is abandoned. A post-commit lost
   acknowledgement remains **uncertain**, not a successful publication claim.
3. A new operation requires a **different operation ID**, a new durable
   deadline, verified unanimous activation of the same exact group descriptor,
   and an independently approved exact intent from **every selected signer**.
   New FROST randomness is generated; no previous `PendingNonce` survives.
4. After a process restart, recover the long-term share only under existing
   authenticated custody and activation checks. A restarted signer cannot
   resurrect the original slot. Do not resume an interrupted DKG or bypass
   anti-rollback anchor reconciliation.
5. A broken/missing anchor is a **fail-closed operational condition**. The
   anchor-path replacement in the test is a disposable fault only; operators
   must never delete or rewrite real anchor evidence to hide a failure.
6. The provider does not itself own all abort-journal transitions:
   `SigningSession::begin` calls `start_deadline` and other fallible steps.
   Its errors currently propagate before `run_signing`'s later
   `record_abort` handler. **S15-L01 owns** the automatic terminal audit
   treatment of failures before reservation and around `begin`; Agent 20
   did not change that code. Until S15-L01 is addressed, failed reservation
   callers must explicitly record abort, as the storage test demonstrates.
   If the journal is unavailable, the system must not retry an uncertain write.

## Regression tests authored

Exact test-source commit:
`6f6fb58413c4035957ab117ffdd17ebc4e25f0d7`.
All entries below are **E1 authored / E3 NOT RUN / E7 NOT RUN**.
No claimed PASS or exit code exists because none of the commands executed.

| Exact test name | Intended assertion |
| --- | --- |
| `authorize_commitment_failure_does_not_publish` | Inject actual SQLite authorization failure: no returned commitment, no pending signing approval, row remains reserved |
| `storage_failure_burns_original_operation` | Drop the SQLite failure trigger; original slot still rejects re-reservation and re-prepare |
| `failed_prepare_never_reuses_nonce` | Failed nonce cannot be used for the original operation; same signer accepts a different independently approved operation only with fresh `published` slot |
| `failed_prepare_restart_is_fail_closed` | Reopen SQLite, rebuild signer from disposable long-term share; original operation fails, different approved operation can commit |
| `subsequent_new_operation_has_defined_recovery` | Same signer instance after fault completes new, independent 2-of-3 FROST signing, aggregate, and verification against activated group |
| `commitment_failure_preserves_activation_requirements` | Partial or conflicting activation votes cannot produce an activated group |
| `commitment_failure_preserves_approved_intent` | One selected signer cannot finalize approvals; changed message fails before nonce reservation; approved original message passes |
| `reserve_nonce_storage_error_is_fail_closed_after_explicit_abort` | SQLite insert failure yields no nonce slot; caller's explicit abort prevents restart (automatic `begin` accounting separately owned) |
| `authorize_commitment_after_commit_before_ack_is_ambiguous_and_burned` | Real SQLite `published` write is committed before anchor error; after restoring disposable anchor and reopening, original slot cannot be reused |
| `custody_log_failure_rolls_back_nonce_reserve_and_publication` | Inject failures of authenticated custody-log writes in both reservation and authorization transactions; neither transition partially commits |

The F-8 tests are in
`crates/mpc-frost-ed25519/tests/three_agents.rs`.
The three lower-level fault tests are in
`crates/mpc-runtime/tests/durable.rs`. Test randomness and identities are
disposable; no nonce, share, key, credential or capability value is printed.

### Exact commands and outcomes (no inferred PASS)

| Candidate SHA / command | Exit status | Relevant recorded evidence |
| --- | --- | --- |
| `6f6fb58413c4035957ab117ffdd17ebc4e25f0d7` — `cargo test --locked -p holochain-mpc-frost-ed25519 --test three_agents` | **NOT RUN** | `command -v cargo` returned exit **1**; no Rust toolchain in execution container. Covers 7 new tests plus existing native tests. |
| `6f6fb58413c4035957ab117ffdd17ebc4e25f0d7` — `cargo test --locked -p holochain-mpc-runtime --test durable` | **NOT RUN** | Same missing `cargo`. Covers 3 new SQLite/anchor tests plus existing store tests. |
| `6f6fb58413c4035957ab117ffdd17ebc4e25f0d7` — `cargo check --locked --workspace --all-targets` | **NOT RUN** | `command -v rustc` exit **1**. Separately, older baseline CI run `43835405873` failed (exit **101**) at missing `holochain_zome_types` import in `mpc-dkg-worker/inbox_slots.rs`; that earlier failure does not validate or invalidate this patch. |
| `6f6fb58413c4035957ab117ffdd17ebc4e25f0d7` — `npm run build:happ` | **NOT RUN** | No `nix` or `hc`: both `command -v` exit **1**; changes here do not alter WASM/DNA but prior build evidence cannot be promoted. |
| `6f6fb58413c4035957ab117ffdd17ebc4e25f0d7` — `npm run test:sweettest` | **NOT RUN** | No native runner or disposable conductors available. |
| `6f6fb58413c4035957ab117ffdd17ebc4e25f0d7` — `git ls-remote https://github.com/ConorTttttt/holochain-threshold-cryptography.git refs/heads/agents/sprint17-agent20-signing-storage-f8-20261116` | **128, environment failure** | `fatal: unable to access ... Could not resolve host: github.com`. GitHub App read/write connector was used instead; this was not a test run. |
| `dc11a41b0f16c6d04456175a95e749da3b377a2a` — GitHub Compare API `899e433d...dc11a41b` | **API success, not a shell exit** | Ahead 5, behind 0, changed 3 Rust files and this validation document. Source presence only, **E1**. |

**Toolchain observations:** `command -v cargo` exit 1,
`command -v rustc` exit 1, `command -v nix` exit 1,
`command -v hc` exit 1, and `command -v sqlite3` exit 1.
None of these environment checks is an executed Rust test.

### Fable E1–E8 classification

| Level | Agent 20 result |
| --- | --- |
| **E1 — source exists** | **YES** — exact GitHub code and test commits above, source comparison performed |
| **E2 — compiles** | **NOT RUN** — no Rust toolchain; baseline external CI had an unrelated compile failure |
| **E3 — native tests pass** | **NOT RUN** — do not infer from authored tests |
| **E4 — WASM and hApp build** | **NOT RUN** |
| **E5 — real Holochain conductors** | **NOT RUN** |
| **E6 — cryptography across real conductors** | **NOT RUN** |
| **E7 — adversarial/fault-injection evidence** | **NOT RUN** at execution level; 10 source regression tests authored |
| **E8 — independent review** | **NOT RUN** for Agent 20's change; the separate Sprint 1.5 review covers the earlier baseline, not this patch |

## Coordination and remaining acceptance gates

- **S15-L01 ownership:** the other owner must test and implement
  `SigningSession::begin` abort accounting, including error after
  `start_deadline`, failure before/after `reserve_nonce`, after prepare,
  and before the first outbound frame. Agent 20 did **not** modify
  `crates/mpc-dkg-worker/src/signing.rs` or claim to close S15-L01.
  The new lower-level explicit-abort test should be reused, not copied into a
  second overlapping implementation. Any common error policy should be
  reviewed together before integration.
- **Still needed:** actually execute the ten named tests on a Rust-enabled,
  clean, pinned candidate; archive commit/command/exit/result logs and a
  source review of the cleanup ordering. Specifically check `WrongState`
  recovery on the same instance, `reserved` versus `published` state
  after both injected faults, and valid new-operation threshold signature.
- The after-commit test directly exercises `RuntimeStore`. Injecting an
  anchor outage *between* `ControlledSigner::prepare`'s internal reserve and
  authorize calls without changing the public store API remains **NOT RUN**;
  code inspection shows the same post-authorization `Err` cleanup path,
  but that is not a substitute for executed combined-path evidence.
- Abnormal process snapshots and whole-disk journal+anchor rollback are
  outside this mitigation. No test in this branch establishes resistance to
  a restored **live** FROST nonce or same-UID master-key compromise.
- No changes to `main`, deployed cells, approved release hashes, secret
  logging, group/DKG activation, signing-intent wire formats or DNA identity.

**Acceptance condition:** promote from source mitigation to *verified fix*
only after E2/E3/E7 execution succeeds on an immutable combined candidate,
S15-L01's terminal accounting is reconciled, and independent review (E8)
checks storage-fault ordering and full signing approval preservation.
