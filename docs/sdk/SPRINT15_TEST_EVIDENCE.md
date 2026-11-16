# Sprint 1.5 — Evidence-Linked Security Test Assessment

**Reassessment date:** 2026-11-16 UTC  
**Verdict:** **CHANGES REQUIRED**; source tests are not automatically execution evidence.  
**Compared source:** Stage 2C `122679a7239b97584c153d7ed1feecd35b914061` to combined Sprint 1 `899e433d057a4d1a0533e2304a2493edb75ad82f`.  
**S1.5 drafts:** PR #6 (`2f3b4c3d708db6d48954d1341fdaa1ba246a9ef1`), PR #8 (`2bc9c8d09cfcbeae5fb229eceacd4b949b9ce6b0`), PR #9 (`319c04f251c013565720e1100359b2541c1c07e1`), PR #10 (`363c9f4341ffbe201fa9c3ce9b4f248cfd6071ef`), all **separate**. There is no single exact Sprint 1.5 integrated head to test.

## 1. Directly observed GitHub Actions jobs

| Run/head/job | Real step and observed result | Classification |
| --- | --- | --- |
| [43835405873](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43835405873), PR #7 combined `899e433...`; [job 133190781392](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43835405873/job/133190781392) | GitHub-hosted job started; Nix install, toolchain-report and **`cargo fetch --locked`** steps success. `cargo check` reports `error[E0433]: cannot find module or crate holochain_zome_types` at `crates/mpc-dkg-worker/src/inbox_slots.rs:5:5`; **exit 101**. Nothing after workspace check is a proven PASS. | **FAIL (compilation)** |
| [43835405873](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43835405873), [job 133190782023](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43835405873/job/133190782023) | Version pin subcheck reports PASS; approved inventory check reports `FAIL: workspace members differ`, `unexpected workspace package: holochain-dkg-sdk`, and `Cargo.lock differs from approved lockfile: added holochain-dkg-sdk 0.1.0 (workspace)`; **exit 1**. | **FAIL (approval gate by design)** |
| [43835405873](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43835405873) | Ephemeral Sweettest job skipped. Operator-gated release validation skipped. No produced artifact identity acceptance. | **NOT TESTED** |
| [43834776051](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43834776051), PR #6 head `2f3b4c...`; [job 133188575253](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43834776051/job/133188575253) | Native run independently reports same E0433 unresolved `holochain_zome_types` at `inbox_slots.rs`; static job cancelled. | **FAIL (compilation)** |
| PR #8/#9/#10 separate heads | No successfully executed Rust native/SDK/status/custody or Sweettest job for these immutable heads was inspected. | **NOT TESTED** |

**Root cause supported by exact source:** [unconditional import at `inbox_slots.rs:5`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/crates/mpc-dkg-worker/src/inbox_slots.rs#L1-L5) plus [`holochain_zome_types` declared optional and only pulled in by `conductor-client`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/crates/mpc-dkg-worker/Cargo.toml#L68-L85). A PR6 change only feature-gated an optional Lair example, not this library dependency. It is premature to fix inventory by recording it; reviewer must first check intentional manifest/lockfile contents.

## 2. Local execution limitations, independently probed

On 2026-11-16 15:35 UTC, `command -v cargo`, `rustc`, `nix`, `hc`, and `holochain` returned absent; there was no local checked-out repository. **No Rust/Holochain suite or conductor was launched in this independent review.** The GitHub-hosted steps above constitute real external execution evidence *of failures*, not passing protocol tests. GitHub source/PR inspection itself is a completed **source-level review action**, not a dynamic software test.

## 3. Regression and fault coverage mapped to concrete security claims

For each row, **AUTHORED** means the reviewed GitHub source contains the test but there is no measured successful execution on the requested combined head. A mock result cannot replace a signed conductor/fault environment.

| Gate / finding | Test source or exact planned command | Security assertion to inspect | Actual Sprint 1.5 evidence |
| --- | --- | --- | --- |
| **S1-M01** late DKG conflict | [`relay_simulation.rs:214`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/crates/mpc-dkg-worker/tests/relay_simulation.rs#L212-L232) `late_dkg_equivocation_is_detected_after_first_delivery` | Delivery A then relevant conflict B in a *later* structured snapshot must poison relay and stop sending. In live conductor, verify both distinct stored variants and associated action evidence. | **AUTHORED / NOT TESTED** |
| **S1-M01** isolated quota/conflict | [`relay_simulation.rs:234`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/crates/mpc-dkg-worker/tests/relay_simulation.rs#L232-L258) `unrelated_slot_conflict_is_isolated_but_dkg_over_quota_aborts`; [`inbox_slots.rs:113`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/crates/mpc-dkg-worker/src/inbox_slots.rs#L112-L133) old vector rejected | No unrelated signer veto; relevant withheld slot fatal; stale coordinator vector rejected, no fallback. | **AUTHORED / NOT TESTED** |
| **S1-M01** signing and nonce burn | [`signing_session.rs:315`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/crates/mpc-dkg-worker/tests/signing_session.rs#L314-L340) `selected_signer_late_equivocation_aborts_and_burns_nonce`, [`:341`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/crates/mpc-dkg-worker/tests/signing_session.rs#L340-L368) over quota | Earlier valid selected-signer slot cannot bypass conflict scan; already reserved nonce does not get reused after abort; nonselected sender has no veto. | **AUTHORED / NOT TESTED** |
| **S1-L03 / F1** clean disconnect / reply checkpoints | [`dkg_journal.rs:92`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/crates/mpc-runtime/tests/dkg_journal.rs#L91-L123) `disconnect_at_each_dkg_round_boundary_aborts_and_prevents_restart` | Encrypted Running -> Aborted CAS + higher revision; any old proposal fails on reopen; completed unaffected. | **AUTHORED / NOT TESTED** |
| **S1-L03 / F1** malformed socket | [`node_service.rs:125`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/crates/mpc-dkg-worker/tests/node_service.rs#L124-L152) `truncated_ipc_frame_after_init_durably_aborts_and_denies_restart` | Real socket EOF/truncation after Init writes terminal checkpoint, then denies restart. | **AUTHORED / NOT TESTED** |
| **S1-L03 / F1** SIGKILL/partition/deadline | [`share_custody.rs:347`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/crates/mpc-dkg-worker/tests/share_custody.rs#L345-L390) `sigkill_after_round_one_two_or_three_is_permanently_nonresumable`, [`relay_simulation.rs:300`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/crates/mpc-dkg-worker/tests/relay_simulation.rs#L299-L319) `network_partition_exhausts_poll_budget_and_aborts_without_retry` | SIGKILL leaves `running` **non-resumable**, not falsely labeled aborted. Timeout/partition closes worker and does not retry uncertain RPC. Reinspect journal and anchor after process exit. | **AUTHORED / NOT TESTED** |
| **S1-M04 / F2** partial DKG complete | [`signing_session.rs:526`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/crates/mpc-dkg-worker/tests/signing_session.rs#L525-L595) `one_locally_completed_share_is_never_implicitly_activated_for_signing` | One stored/recoverable local share + incomplete other members ⇒ no ActivatedGroup, nonce commitment or valid signature. Follow with real conductor partition and recovered journal. | **AUTHORED / NOT TESTED** |
| **S15-L01** failed Begin audit | **NEW test required**, inject errors after `start_deadline`, after `reserve_nonce`, after `authorize_commitment`, on `to_others` | Confirm no reuse and durable terminal abort (or accurately document a nonterminal audit state) across all pre-async Begin failures. | **NOT AUTHORED for this precise path / NOT TESTED** |
| **S1-M02** cross-app/proposal | PR #8 [`bound_v2.rs`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/2bc9c8d09cfcbeae5fb229eceacd4b949b9ce6b0/crates/mpc-core/src/bound_v2.rs) core: `cross_application_envelope_replay_is_rejected`, `cross_proposal_envelope_replay_is_rejected`, `same_proposal_valid_envelope_still_delivers`. Coordinator [legacy reproducer](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/2bc9c8d09cfcbeae5fb229eceacd4b949b9ce6b0/dnas/mpc/zomes/coordinator/mpc/tests/cross_application_isolation.rs). | Core v2 candidate rejects A->B; **v1 coordinator remains replay-vulnerable**; migration requires new coordinator v2 live rejection, mixed-wire and source-chain-compat tests. | **AUTHORED / NOT TESTED**, v2 not integrated; coordinator acceptance not fixed |
| **PR #10 status privilege** | [`frost_status_signer.rs` tests](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/363c9f4341ffbe201fa9c3ce9b4f248cfd6071ef/crates/mpc-dkg-worker/src/frost_status_signer.rs#L129-L220), [`native.rs` tests](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/363c9f4341ffbe201fa9c3ce9b4f248cfd6071ef/crates/holochain-dkg-sdk/src/native.rs#L119-L203), [`lib.rs` tests](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/363c9f4341ffbe201fa9c3ce9b4f248cfd6071ef/crates/holochain-dkg-sdk/src/lib.rs#L379-L429) | Status-only profile and exact proposal, app/cell/DNA/context/roster/threshold pins; deny writes and probe-profile impersonation; full-acceptance only `ReadyToStart`; no implicit activation. Need **actual** authorised signed `get_session_status` against pinned disposable conductor, wrong-intent negatives and old-coordinator refusal. | **AUTHORED / NOT TESTED**, no live signed read |
| **S1-H01** local custody | PR #9 [`custody_security_profile.rs`](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/319c04f251c013565720e1100359b2541c1c07e1/crates/mpc-runtime/tests/custody_security_profile.rs): production refusal, development backup, whole-state snapshot, multi-UID `#[ignore]` | Production must fail closed until independent witness/key. Current whole-state local rewind can reopen. Privileged UID test verifies only DAC and does not prove IPC interoperability. | **AUTHORED / NOT TESTED**; one **IGNORED**; external witness test **ABSENT** |
| **S1-M03/L01/L02** remaining lifecycle | New acceptance tests needed for quota threshold and proactive rekey, same-first-eight-byte operation IDs, concurrently rebased receipt action lookup | No quota/slot collision availability overclaim, no receipt accepted as authoritative without lookup. | **NOT TESTED / OPEN** |

### Historical-only fault and coordinator evidence (never count as a new pass)

[Phase 6 report lines 224–247](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/docs/V040_PHASE6_FAULT_TESTS.md#L224-L247) describes **F1** and **F2** on older code; [lines 293–300](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/docs/V040_PHASE6_FAULT_TESTS.md#L293-L300) claim two historical 18/18 suites and smaller separate passes. This is not executed Sprint1.5 evidence and the older test runner exit 0 could include statuses `FINDING` and `SKIP`, not just PASS. [Stage 2C hardening report lines 277–292](https://github.com/ConorTttttt/holochain-threshold-cryptography/blob/899e433d057a4d1a0533e2304a2493edb75ad82f/docs/V040_STAGE2C_COORDINATOR_HARDENING.md#L277-L292) author-reports earlier 7/7 coordinator unit, 11/11 Sweettest, 153/153 native, and **FAIL identity**. They predate the integrated SDK work and cannot validate it.

## 4. Required exact-candidate command matrix (instructions, NOT run claims)

Only after an immutable Sprint 1.5 combined branch is created, fix the manifest/import discrepancy, and run on Linux in the pinned Nix shell with `TMPDIR` short enough for Unix sockets. Record `git rev-parse HEAD`, Rust/Cargo/hc versions, each full command, exit status, counts and redacted output. Never use real credentials.

```sh
nix develop --no-write-lock-file
rustc --version; cargo --version; hc --version
cargo fetch --locked
export CARGO_NET_OFFLINE=true
mkdir -p /tmp/dkg-s15; export TMPDIR=/tmp/dkg-s15

cargo check --offline --locked --workspace --all-targets
cargo test --offline --locked -p holochain-mpc-core
cargo test --offline --locked -p holochain-mpc-runtime --test dkg_journal
cargo test --offline --locked -p holochain-mpc-dkg-worker --test node_service
cargo test --offline --locked -p holochain-mpc-dkg-worker --test dkg_restart
cargo test --offline --locked -p holochain-mpc-dkg-worker --test relay_simulation
cargo test --offline --locked -p holochain-mpc-dkg-worker --test signing_session
cargo test --offline --locked -p holochain-mpc-dkg-worker --test share_custody
cargo test --offline --locked -p holochain-dkg-sdk --all-targets
cargo test --offline --locked -p holochain-dkg-sdk --features native-holochain --all-targets
cargo test --offline --locked -p holochain-mpc-dkg-worker --features lair-signer --lib frost_status_signer::tests
cargo test --offline --locked -p holochain-mpc-runtime --test custody_security_profile
python3 -I scripts/check_holochain_versions.py
python3 -I scripts/check_release.py
npm run test:native
npm run build:happ
npm run test:sweettest
```

Add separately invoked **ephemeral** signed-conductor status run and the Phase 6 fault scenarios `dkg-kill-r1/r2/r3`, `dkg-kill-r3-partial`, `dkg-stop`, `dkg-partition`, `sign-partition` with fresh disposable shares. Execute the privileged `test_separated_uids_cannot_read_custody` only on an isolated Linux UID fixture via explicit `--ignored`, but **it cannot close S1-H01**. The run of a full rollback test must restore journal **and** software anchor, leaving a truly independent witness advanced; verify startup refuses *before* nonce emission. The independent witness/connector does not yet exist.

`python3 -I scripts/check_release.py` is an **approval-sensitive read-only check** and must remain expected-red against unapproved SDK inventory; record any FAIL, **do not call `--record-inventory`**. `npm run check:release` is a **separate operator-gated identity validation** only after fresh build and independent source/inventory review; it must not automatically record hashes. Run current Rust dependency advisories (`cargo audit` or equivalent curated auditable scan), compare exact dependency tree and lockfile, and link results to this exact SHA. No passing audit was available at review time.

## 5. Evidence rules for promotion

A fix moves to **VERIFIED FIXED** only when the merged source contains the defense, the relevant negative *and* positive tests execute successfully with archived logs and immutable head identity, and reviewer checks the semantics—not simply a test name. Specifically, **a mock successful `ReadyToStart` read is not a live authorized SDK read; a local permission test is not hardware key isolation; a core v2 unit pass is not coordinator replay rejection; an aborted relay in memory is not an anchored durable abort; a historical fault PASS is not a new branch pass.**

**Gate result:** CHANGES REQUIRED. This evidence assessment supports no production claim, no fully functioning SDK DKG/signing claim, no approval to deploy/update persistent cells and no automatic release inventory or hash change. Linked full decision: [SPRINT15_SECURITY_REVIEW.md](SPRINT15_SECURITY_REVIEW.md) and [SPRINT15_FINDINGS_REGISTER.md](SPRINT15_FINDINGS_REGISTER.md).
