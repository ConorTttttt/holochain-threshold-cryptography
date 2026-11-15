# Sprint 1 — DKG lifecycle, persistence, and crash safety (Agent 3)

**Baseline:** `feature/v0.4.0-stage2c` at `122679a7239b97584c153d7ed1feecd35b914061`.  
**Scope:** Native Rust DKG worker, journal, relay/IPC shutdown, and signing activation policy.  
**Verdict:** F1 ordinary disconnect / timeout paths addressed in code; abnormal process death remains a non-resumable `running` tombstone by design. F2 signing remains fail-closed behind unanimous activation; coordinated abandoned-share retirement remains a policy decision. **Not release cleared: tests in this change have not been executed in this environment.**

## Lifecycle and trust boundaries

These are **different conditions**, and no transition should be inferred from another:

| Condition | Meaning | Durable evidence | Does it allow signing? |
| --- | --- | --- | --- |
| DKG `running` | This participant admitted a specific proposal, agent and session before generating FROST randomness; it may have produced one or more replies. | Encrypted authenticated `dkg_checkpoints`, write-ahead revision/digest. | **No.** The old proposal may never restart. |
| Locally completed DKG | One participant finished FROST part 3 and produced a local group descriptor. Other participants might not have finished. | A `Completed` public reply and its matching digest, after share sealing. | **No.** |
| Persisted share | The participant wrote encrypted custody data write-once. The seal precedes the completion checkpoint, so a crash can leave a sealed but **unrecoverable** share under `running`. | `secrets` row, authenticated share descriptor/owner binding. Recovery additionally requires a completed checkpoint and exactly matching final reply digest. | **No.** |
| Group activated | All enrolled members independently attested the exact descriptor, DKG transcript and public key package, using authenticated Holochain response provenance. | Holochain activation attestations checked by `GroupActivation::finalize`; `ActivatedGroup` is a runtime verified capability, not deserializable from arbitrary JSON. | **Not alone.** |
| Authorised for signing | The signer has the exact activated group, a valid plan, approval from **every selected signer**, and a usable non-retired share/nonce journal. | `ApprovedIntent` and bounded, durable signing operation/nonce checks. | **Only then**, subject to application-specific approval policy. |
| DKG `aborted` | Started ceremony definitively stopped; no further replies or restart. | Permanent encrypted terminal tombstone, chained log event and revision increment. | **No.** |

A DKG checkpoint is **not** a globally agreed certificate. A completed local group is never auto-activated. Sealed ciphertext is not evidence of unanimous success.

## F1 — Root cause and change

**Verified root cause:** `AuthenticatedController::handle` durably called `dkg_abort` when a MAC-authenticated command was rejected, but `node_service::serve_connection` returned `Ok(())` on EOF and returned early on malformed/truncated framing or socket errors. These events bypassed `handle`; previously the parent service released the socket and anchored the journal without a terminal state transition. The native relay itself could also fail due to a conductor transport error, and the supervisor could return for deadline exhaustion, signal shutdown or cancellation while the worker still had a live connection. These paths could leave `running` despite an abandoned ceremony.

**Implemented:**

1. `RuntimeStore::dkg_abort_running` checks the authenticated checkpoint. It executes the existing encrypted, chained, compare-and-set `dkg_abort` transition **only** for `running`. No checkpoint means no tombstone on clean disconnect before Init; `completed` and `aborted` are never rewritten.
2. `AuthenticatedController::abort_on_disconnect` immediately invalidates the in-memory controller/secrets and requests the conditional durable abort. `node_service::serve` invokes this cleanup on **all** returns from `serve_connection`, including clean EOF, truncated framing, and ordinary I/O errors, before anchoring the journal.
3. Native `ConductorBridge::abort_connection` closes both halves of the authenticated Unix IPC socket. `LocalDkgNode::abort` is an **explicit trait obligation**, and `RelayEngine::abort` poisons the relay and closes the worker. `RelayEngine::poison` uses this same path.
4. `relay_supervisor::supervise` invokes terminal abort for every error returned by its internal polling loop, including a cancelled or timed-out `start()` whose Init may have already committed even though the relay still reports `Phase::New`. It never retries uncertain RPCs.
5. Existing write-ahead admission, encrypted records, chain log, anchor checks, immutable proposal/agent reuse rule, share sealing, and signing nonce burn rules are unchanged.

**What cannot be marked `aborted` synchronously:** SIGKILL, kernel/power failure, or process termination before the post-connection hook runs. A dead process cannot execute a durable abort. Such a journal intentionally retains `running`, **which is terminal for recovery**: `new_durable` refuses every existing checkpoint, and no FROST ephemeral secrets are serialized. Never reset or delete this marker to pretend an old ceremony can resume. A new ceremony needs a **new Holochain proposal**, new randomness, fresh authorised directory/bindings and operator coordination.

**Fail-safe ordering:** Init checkpoint before FROST randomness; each outbound reply checkpoint before IPC release; sealed share before `Completed` checkpoint; conditional abort on disconnect; anti-rollback anchor after the node connection completes. If abort persistence itself fails, the node returns an error, does not resume or send new replies, and the pre-existing `running` marker still blocks reopening. This is availability degradation, not permission to reuse secrets.

## F2 — Root cause and fail-closed policy

**Verified root cause:** FROST part 3 is local: a member can receive all valid encrypted Round-2 shares, compute its key package, seal it, and report `Completed` before a different member sees the same final messages or survives a partition. There is no safe inference from a local share to global completion. The system cannot force other members to complete merely because one member finished.

**Existing enforced path:** `recover_completed_share` validates the exact completed public-reply digest and sealed share, but does **not** grant an `ActivatedGroup`. The production `mpc-sign` flow calls `run_signing`, which first waits for `activated_group()`. `GroupActivation::finalize` requires an identical attestation from **every participant**, not just the FROST signing threshold. The group is then bound to the exact signing plan and approvals from every selected signer **before** nonce reservation or emission of signing commitments. Missing votes, conflicting descriptors or missing approvals fail closed. FROST's threshold alone does **not** replace activation.

**Sprint policy:** Keep a locally completed/persisted share **sealed but inactive** when group-wide activation has not been unanimously verified. Do not promote it automatically, do not allow signing, and do not delete or overwrite its ciphertext in response to a partial rollout or timeout. A member that never completed may retain `running` or `aborted`; its proposal is still non-resumable. The partial-completion test explicitly recovers a locally completed share and proves that a single valid activation vote cannot make it sign.

**Architecture decisions that remain open (tracked blocker for operational rollout):**

- **Retention-first:** Retain sealed, inactive shares for forensic reconciliation and operator review; impose policy-defined expiry and secure manual retirement. Best preserves evidence/custody but requires storage and incident procedures.
- **Quorum-led retirement:** Introduce authenticated, epoch-bound group cancellation with a documented quorum/unanimity threshold and a durable monotonic retirement log. Avoid coercing healthy signers into silently destroying shares, and defend against DHT equivocation and partition.
- **Unilateral local retirement:** Allow an owner to call the existing `retire_epoch`, burn outstanding nonces, then separately `erase_share` with explicit operator intent. This is local and one-way, not a proof the group never activated elsewhere.

**No automatic deletion, overwrite, reactivation, group-wide rollback, reshare, or timeout-based epoch retirement was implemented.** Group retirement policy, authenticated evidence freshness, and end-to-end conductor partition testing remain explicit blockers before valuable-key deployment.

## Regression coverage added

| Requirement | Test | Evidence/expected assertion |
| --- | --- | --- |
| Round 1 termination | `mpc-runtime/tests/dkg_journal.rs::disconnect_at_each_dkg_round_boundary_aborts_and_prevents_restart` and `mpc-dkg-worker/tests/node_service.rs::two_independent_node_processes_accept_only_their_own_authenticated_controller` | Running admission becomes aborted on normal EOF; no reentry. |
| Round 2 termination | Same journal boundary test, plus `share_custody.rs::sigkill_after_round_one_two_or_three_is_permanently_nonresumable` | Genuine real-process interruption in attestation phase retains non-resumable running marker. |
| Round 3 termination | Same tests, with `Phase::Shares` and write-ahead Round-3 metadata | No share recovery/restart after partial termination. |
| Network partition | `relay_simulation.rs::network_partition_exhausts_poll_budget_and_aborts_without_retry` | Isolated relay times out, aborts, and emits no further protocol replies. |
| Restart following abort | `dkg_journal.rs` test and `node_service.rs::truncated_ipc_frame_after_init_durably_aborts_and_denies_restart` | Encrypted terminal state survives reopening; new native process rejects reentry. |
| Partial completion without unanimous activation | `signing_session.rs::one_locally_completed_share_is_never_implicitly_activated_for_signing` | Only participant 1 finishes; others remain running; share exists but activation remains incomplete. |
| Signing non-activated group | Same `signing_session.rs` test | `run_signing` rejects before publishing commitments or a signature. |
| Process failure/durable consistency | `share_custody.rs::sigkill_after_round_one_two_or_three_is_permanently_nonresumable`, existing `dkg_restart.rs::abrupt_process_kill_leaves_encrypted_marker_and_denies_restart`, and `dkg_journal.rs` revision assertions | Genuine SIGKILL retains revision and non-restart safety; graceful disconnect increments revision and clears reply digest. |
| Completed share unaffected by cleanup | `dkg_journal.rs::completed_share_checkpoint_is_not_aborted_by_connection_shutdown` | Completed checkpoint/digest remains unchanged. |
| Pre-admission listener disconnect | `node_service.rs::disconnect_before_init_does_not_poison_an_unstarted_ceremony` | No fresh random secret or admission => no tombstone. |

**Existing relevant tests:** `mpc-dkg-worker/tests/signing_session.rs::conflicting_approval_or_activation_fails_closed` verifies bad/partial activation behaviour; `mpc-security/tests/group_activation.rs` enforces unanimity; `mpc-runtime/tests/dkg_journal.rs` covers malicious tampering, encryption and admission conflicts.

### Commands to execute in Rust-enabled CI

```sh
cargo test -p holochain-mpc-runtime --test dkg_journal
cargo test -p holochain-mpc-dkg-worker --test node_service
cargo test -p holochain-mpc-dkg-worker --test dkg_restart
cargo test -p holochain-mpc-dkg-worker --test relay_simulation
cargo test -p holochain-mpc-dkg-worker --test signing_session
cargo test -p holochain-mpc-dkg-worker --test share_custody
cargo test -p holochain-mpc-dkg-worker relay_supervisor
```

**Execution status as of 2026-11-15:** **NOT RUN**. The editing environment has no `cargo`, `rustc` or network access to the crate registry; no build, tests or live fault-injection results can be honestly claimed. Changes require compilation and execution on a Rust-enabled runner before acceptance. The regression tests are proposed test evidence, **not measured pass results**.

## Recovery and operational runbook

1. On a graceful native worker disconnect or relay timeout, expect `aborted` with a chained terminal event and a new revision. On abrupt SIGKILL expect `running`; this is **not** permission to resume.
2. Treat **every** existing checkpoint (`running`, `aborted`, `completed`) as consumed admission. Never retry ambiguous sends, re-use the proposal or replay cached FROST traffic. Do not wipe an old journal.
3. A fully completed share may be recovered only with the exact descriptor and its authenticated custody/journal match. Recovery is still insufficient to sign.
4. Verify unanimous activation evidence for the group before opening a signing session, then require all selected signing approvals and live, anchored nonce journal conditions.
5. If activation stalls, quarantine the sealed share, record the incident, and select a reviewed retention/retirement path. Do not automatically call `erase_share` or replace the participant's group epoch.
6. Run end-to-end process and conductor partition tests, verify anchor persistence across forced power-loss/snapshot rollback, review operational retirement policy, then obtain an independent security review before claiming F1/F2 release closure.

## Open blockers

- **Validation blocker:** all new and existing Rust tests must run successfully; inspect CI output before merging.
- **Power-loss limitation:** durable `aborted` cannot be guaranteed on SIGKILL or catastrophic failure; this is deliberately represented by permanently non-resumable `running`. Any requirement for a uniform terminal label requires a *separate, explicitly reviewed recovery/reconciliation transaction*, not replay.
- **F2 operational policy:** no approved group-wide cancellation / retention / epoch retirement protocol for partially activated groups. **Signing itself remains fail-closed**, but lifecycle cleanup is not solved.
- **Integration/security:** signed Holochain provenance, eventual-consistency/fork handling, and native process/port-forward/signer failures need an end-to-end conductor rehearsal. Do not assert network-level safety solely from offline stand-ins.
