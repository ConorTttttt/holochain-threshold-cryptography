# Sprint 1.8B recovery — verification, security and integration report

**Final status: BLOCKED — OPERATOR APPROVAL REQUIRED.** This is an engineering integration candidate. It is not a release, an independent audit (E8) or a production approval. No change was made to `main`, release inventories, hash manifests, deployed DNA, cells, credentials or custody.

| Item | Value |
| --- | --- |
| Baseline audited | `33db0497435e1713781329accece8eacde753faf` (PR #19 head, `sprint18b/compile-security-verification-20261116`), re-verified on 2026-11-19 |
| Continuation branch | `claude/holochain-threshold-crypto-sprint18b-gocnij` (from the 1.8B head; PR #18/#19 histories untouched) |
| Code head verified | `2eb1efc1de9224b4b33d9134548d15ff8c9d5bc4` |
| Repository state at audit | 34 branches, 19 open PRs, 0 merged, 1.8B = 69 commits ahead of `main` (all as briefed) |
| Local environment | Linux container, rustup `rustc 1.97.0 (2d8144b78 2026-07-07)` / `cargo 1.97.0`, 4 CPU. **Not** the holonix-pinned toolchain: the sandbox proxy refuses `nix develop` flake input downloads (HTTP 403). Native test binaries ran as uid 65534 because custody correctly refuses to serve as root. No IPv6, so Sweettest conductors cannot start locally. |
| Pinned-toolchain evidence | GitHub Actions `sprint18b-verify.yml`, pinned Nix, disposable conductors, exact `head_sha` |

## 1. Baseline audit: failure classification at `33db049`

CI run [43946481045](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43946481045):

| Observation | Category | Evidence | Resolution |
| --- | --- | --- | --- |
| 4 × `share_custody` failures at `share_custody.rs:465` (`nonce_is_never_reissued…`, `restored_backup…`, `restored_journal_snapshot…`, `retired_epoch…`) | **Test-harness architecture**: the tests verify signing-time custody, but their DKG *precondition* (`served_dkg`) ran through the production `ConductorBridge`, which INV-13 correctly blocks | job 133577564348 log | Split (§3.1). The custody properties are retained and pass; a new INV-13 negative test was added. |
| `three_private_node_services_frost_dkg_over_three_conductors` | **Expected security refusal**: a positive live E6 path through the production bridge | job 133577564771 log | Converted to a live INV-13 **negative**. The positive path is **BLOCKED**. |
| Every native gate after `share_custody` (round-2 uniqueness, core, security, runtime, FROST, worker, SDK, feature checks) | **Never reached** (`bash -e`) | job 133577564348 stops at first failure | Workflow now records every gate (§3.3) |
| `fable_conductor_adversarial` workflow step | **Never reached** (after the failing `test:sweettest`); the same 5 tests did run inside `test:sweettest` (`5 passed`) | job 133577564771 | Each suite is now a separate gate |
| `conductor-client` / `lair-signer` / all-features builds | **Compilation defects**, hidden at baseline by the above: E0004 in shipped `mpc-conductor-call` (non-exhaustive `MpcZomeResult::InboxSlots`), E0599 in shipped `mpc-transport-probe` (removed `get_inbox`), E0407/E0046 in the `transport_probe` test mock, E0277 in `conductor_client` unit tests | local matrix gates 14–18 at `7059faf` | Fixed in `dd7f8bc` (§3.2) |
| `cargo test -p holochain-mpc-dkg-worker` in the native job | **Harness defect**: includes conductor-requiring binaries without a hApp, and stops at the first failing binary | local gate 10 at `7059faf` (conductor_bridge aborted the run; 8 later binaries never ran) | Native job scoped with `--no-fail-fast` (`2eb1efc`) |
| `check_release.py` + 2 `test_check_release` unit tests | **Operator-approval blocker** (unapproved inventory delta) | §5 | Not changed. BLOCKED. |
| `cargo fmt --check` | **Pre-existing style**: 93 of 99 `.rs` files, no `rustfmt.toml`, never CI-gated | local gate 1 | Not reformatted (would bury the security diff). Recommend a separate formatting-only PR. |
| `sqlcipher_mlock … errno=12` log noise | **Environment** (runner `RLIMIT_MEMLOCK`) | job 133577564771 | Informational. The tests passed regardless. |

## 2. What passed at baseline, and what it actually proves

- `three_process_frost_dkg_over_three_conductors` and `dkg_live` **passed, but neither goes through `ConductorBridge::round_two`**. `three_processes.rs` sends `Command::BeginRoundTwo` directly to each worker with conductor-observed keys, and `dkg_live.rs` runs FROST inside the test process. Their PASS shows FROST protocol mechanics over real conductor transport with **test-host key pinning**. It is **not** an INV-13-admitted distributed ceremony, so the E6 production path stays unclaimed. `three_processes.rs` now carries this classification in its header.
- Inbox hardening (7) and Fable conductor adversarial (5) passed at baseline as E5/E7 coordinator evidence. They don't depend on INV-13.

## 3. Changes on the continuation branch

| Commit | Change |
| --- | --- |
| `5677171` | `share_custody.rs`: `served_dkg` uses the explicitly test-only `OfflineServedPort` (same trust as the existing `DurablePort`/`ChildPort`). New `served_bridge_refuses_round_two_without_inv13_approval`. |
| `4bbe4e4` | `conductor_bridge.rs` becomes the live INV-13 negative `three_private_node_services_stop_at_inv13_round_two_gate_over_three_conductors`. `three_processes.rs` gets its evidence classification header. |
| `26742df`, `2eb1efc` | `sprint18b-verify.yml`: every gate runs and is recorded; correct native/conductor scoping; feature-gated tests; `capability_provisioning` Sweettest; triggers on this branch. |
| `7059faf` | `SPRINT18B_INV13_IMPLEMENTATION_DESIGN.md` (proposed, not activated). |
| `dd7f8bc` | Feature-build compile fixes (§3.2). |

### 3.1 Share-custody split: why this is not a fake approval

- No library, service or gate code changed. `ConductorBridge::require_round_two_key_approval` is byte-identical to baseline.
- `OfflineServedPort` lives only in the test file. It reads the node's IPC key from the temporary directory the test itself provisioned, which is the same capability `DurablePort`/`ChildPort` already had. It produces the DKG precondition so that custody properties (nonce journal crash points, snapshot rollback, stale backup, epoch retirement/erasure) stay covered.
- The production path is now covered by a negative test that requires all of the following:
  - all three nodes reach the Round-2 boundary with a complete, consistent roster;
  - each relay stops with the exact INV-13 message and aborts;
  - zero round-3 (Round-2 ciphertext) envelopes exist;
  - 6 attestations do exist;
  - every node exits, holds no recoverable share and refuses restart.
- **Mutation probe (local, not committed):** forcing the gate to `Ok(())` makes this test fail with `Round 2 must never be entered`. The file was restored, with a verified clean diff.

### 3.2 Feature-build fixes (fail-closed)

- `mpc-conductor-call`: the `InboxSlots` result prints served/conflict/quota counts and **exits non-zero** if any withheld evidence exists, so it's never reported as PASS.
- `mpc-transport-probe receive`: reads structured slots and **refuses** if any conflicting or quota-withheld slot exists, rather than reading a downgraded list.
- Test-only fixes: the `transport_probe` mock implements `get_inbox_slots` (served envelopes only, which is genuinely all it stores), and two `conductor_client` test structs derive `Debug`.

## 4. Verification table

Allowed results: PASS / FAIL / BLOCKED / NOT RUN. "Local" means the container toolchain above, which is not pinned Nix. Counts come from `test result:` lines.

| Test | Commit SHA | Result | Evidence | Remaining issue |
| --- | --- | --- | --- | --- |
| `cargo fmt --all -- --check` | `2eb1efc` | FAIL | local; 93/99 files, pre-existing | Separate formatting PR |
| `cargo check --locked --workspace --all-targets` | `2eb1efc` | PASS | local exit 0 | — |
| worker `--all-targets` (default) | `2eb1efc` | PASS | local exit 0 | — |
| worker `--features conductor-client --all-targets` | `2eb1efc` | PASS | local exit 0 (FAIL at `7059faf`/baseline code) | — |
| worker `--features lair-signer --all-targets` (= all-features) | `2eb1efc` | PASS | local exit 0 (FAIL at `7059faf`/baseline code) | — |
| `share_custody` | `2eb1efc` | PASS | local 13/13 (incl. new INV-13 negative) | — |
| `round_two_uniqueness_tests` (lib) | `2eb1efc` | PASS | local 5/5 | — |
| `round_two_security` | `2eb1efc` | PASS | local 11/11 | Native only; not live approval |
| `holochain-mpc-core` | `2eb1efc` | PASS | local 11/11 | — |
| `holochain-mpc-security` | `2eb1efc` | PASS | local 27/27 | — |
| `holochain-mpc-runtime` (journal, durable, custody) | `2eb1efc` | PASS | local 28/28 | — |
| `holochain-mpc-frost-ed25519` (incl. share attribution) | `2eb1efc` | PASS | local 16/16; `forged_share_attribution_cross_operation_replay_and_peer_commitments_fail` passes (it FAILED on PR #14 head, run 43918839519) | E8 crypto review pending |
| worker native (lib, bins, dkg_restart, input_validation, ipc_process, node_service, relay_simulation, round_two_security, share_custody, signing_session) | `2eb1efc` | PASS | local 108 passed, 0 failed, **1 ignored** | Ignored S1-M03 expiry test is **not** a pass |
| worker `conductor-client` lib+bins | `2eb1efc` | PASS | local 55/55 | — |
| worker `lair-signer` lib+bins+`transport_probe` | `2eb1efc` | PASS | local 108/108 | Fake-signature mock; not Lair/conductor proof |
| SDK default `--all-targets` | `2eb1efc` | PASS | local 6/6 | — |
| SDK `native-holochain --all-targets` | `2eb1efc` | PASS | local 9/9 | Live authenticated status read NOT RUN |
| `holochain-mpc-vault` | `2eb1efc` | PASS | local 45/45 | — |
| coordinator `mpc --lib` | `2eb1efc` | PASS | local 7/7 | — |
| `cargo clippy --workspace --all-targets` | `2eb1efc` | PASS | local exit 0, 0 errors, 107 warnings (not `-D warnings`) | Lint debt |
| Release-tool unit tests | `2eb1efc` | FAIL | local 21/23; the 2 failures are approved-inventory comparisons | Fails only because of the BLOCKED inventory |
| `check_release.py` (read-only) | `2eb1efc` | BLOCKED | local exit 1, exactly the 5 known deltas (§5) | Operator approval |
| Lock/inventory/hash files unchanged | `2eb1efc` | PASS | `git diff --exit-code` vs baseline files | — |
| Pinned-Nix native job | `2eb1efc` | _CI_ | run 44592669204 | _to be filled from the job log_ |
| `npm run build:happ` (E4) | `2eb1efc` | _CI_ | run 44592669204 | Hashes not regenerated/approved |
| `mpc_network`, `dkg_live`, `inbox_hardening`, `fable_conductor_adversarial`, `three_processes` (E5/E7) | `2eb1efc` | _CI_ | run 44592669204 | `dkg_live`/`three_processes` ≠ INV-13 admission |
| `conductor_bridge` live INV-13 negative (E5) | `2eb1efc` | _CI_ | run 44592669204 | — |
| `capability_provisioning` Sweettest | `2eb1efc` | _CI_ | run 44592669204 | — |
| Live distributed DKG via production bridge (E6) | — | BLOCKED | INV-13 gate | INV13-A…E |
| Live authenticated SDK status read | — | NOT RUN | needs a disposable approved signer, token and SessionSpec | Operator provisioning |
| Independent FROST + Holochain review (E8) | — | NOT RUN | — | Two specialist reviewers |

## 5. Release inventory (documented, not applied)

The read-only `python3 -I scripts/check_release.py` (exit 1) reports exactly:

1. Workspace members add `crates/holochain-dkg-sdk`.
2. Unexpected workspace package `holochain-dkg-sdk`.
3. `holochain-mpc-dkg-worker`: `holochain_zome_types` changed from `{version "=0.7.1", optional}` to required `"=0.7.1"`.
4. `holochain-mpc-frost-ed25519`: new direct `frost-core = "=3.0.0"` (already transitively locked).
5. `Cargo.lock` adds `holochain-dkg-sdk 0.1.0 (workspace)`.

This sprint adds **no** new dependency or lock change: `Cargo.lock`, `release_inventory.json` and `release_hashes.json` are unchanged from `33db049`. The required update is exactly the semantic diff in `SPRINT18_RELEASE_INVENTORY_PROPOSAL.md`. It must be generated and recorded **only** by the release maintainer, with explicit authority, from the final reviewed head. `release_hashes.json` needs separate artifact-release authority.

## 6. Security report

### 6.1 Findings register

| ID | Sev | Component | Invariant | Current mitigation | Verification evidence | Remaining work | Operator approval | Disposition |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **INV-13** | HIGH | `ConductorBridge::round_two` | Round-2 keys only from an independently authorised roster | Unconditional fail-closed gate | E3: new served negative + mutation probe; E5: live negative (CI) | Implement §INV-13 design after decisions | **Yes (INV13-A…E)** | **BLOCKED LIVE** |
| **S18B-F01** (new) | HIGH (defence in depth) | worker `Command::BeginRoundTwo` | Secret-owning boundary must enforce admission | Only shipped sender is the gated bridge; IPC key is a private 0600 file | Source review; demonstrated by test hosts (`three_processes`, `DurablePort`, `ChildPort`, `OfflineServedPort`) | Worker-side approval verification + journalled one-shot admission (design §4.2) | **Yes (INV13-B/D)** | OPEN |
| **S18B-F02** (new) | MED | `mpc-conductor-call`, `mpc-transport-probe` | No silent loss of conflict/quota evidence; builds compile | Fixed `dd7f8bc`: withheld evidence → non-zero exit / refusal | E2 PASS all features; E3 55/55, 108/108 | Live run of the CLIs against a conductor | No | FIXED (E2/E3) |
| **S18B-F03** (new) | LOW (process) | `sprint18b-verify.yml` | Evidence completeness | Every gate recorded; correct scoping | Workflow diff; CI run | — | No | FIXED |
| S1-H01 | HIGH | Production custody | Key separate from journal; anti-rollback witness | Dev layout only; root refused; anchor checks | E3: custody tests 13/13 | External witness, UID separation (PR #9 not merged) | **Yes** | OPEN (prod blocker) |
| S1-M01 | MED | Relay/signing inbox | No silent loss of conflict evidence | Relay aborts before decrypt on conflict | E3: `conflicting_structured_share_slot…` in 108/108; E5 inbox_hardening (CI) | Late conflicts after completion out of scope | No | SOURCE + E3/E5 |
| S1-M02 | MED | Coordinator v1 envelopes | Cross-app isolation | None in v1; PR #8 v2 design unmerged | — | v2 binding/DNA migration | **Yes** | OPEN |
| S1-M03 | MED | Quotas / lifetime | Finite group lifetime | Lifetime quota | Ignored test documents the gap (NOT PASS) | Retirement admission gate / rekey policy | **Yes** | OPEN |
| S1-M04 | MED | Activation | Unanimous activation | `activated_group` requires all attestations | E3 signing_session | Live E6 blocked by INV-13 | No | SOURCE + E3 |
| S1-L01 | LOW | Signing slot ID | No sequence aliasing | Frame identity binds operation | PR #13 characterisation (E3) | Wire-breaking fix | **Yes** | OPEN |
| S1-L02 | LOW | Receipt identity | Receipt = stored action | — | — | Cross-check | No | OPEN |
| S1-L03 | LOW | DKG abort accounting | Durable abort, no resume | Abort on disconnect; tombstone | E3: sigkill/abort tests; new INV-13 tests assert no restart | Conductor fault run | No | SOURCE + E3 |
| S15-L01 | LOW | `SigningSession::begin` | Abort journalled after deadline | Fix `710159af` | E3 signing_session | Abort-journal storage failure | No | SOURCE + E3 |
| Fable F-8 | MED | Signer after storage fault | No nonce reuse | Pending nonce dropped on store error | E3 three_agents/signing_session; nonce crash test 6 steps | Real storage fault injection | No | SOURCE + E3 |
| Fable F-9 | MED | Duplicate Round-2 | No duplicate share acceptance | Relay rejects multiple shares/conflicts | E3 round_two_uniqueness 5/5, round_two_security 11/11 | Multi-conductor concurrency | No | SOURCE + E3 |
| FROST attribution | HIGH (investigation) | Signature aggregation | Per-signer attribution | `verify_signature_share` before aggregate | E3 FROST 16/16 | Independent crypto review | No (E8) | SOURCE + E3 |

### 6.2 Topic summary

- **INV-13:** intact and fail-closed. It's now proven load-bearing by a mutation probe and covered by native (served `mpc-node`) and live-conductor negatives. Its weakness is placement: the gate sits in the host library only (S18B-F01). The implementation-ready design moves authority verification into the worker.
- **FROST invariants:** share attribution, sealed Round-2 and transcript binding are covered at E3. No E6 or E8 evidence exists.
- **Share custody / recovery / rollback:** snapshot rollback, stale backup, retired-epoch erasure, unsafe layout and root are all refused (E3, 13/13). Production custody (S1-H01) is still open.
- **Nonce reuse:** the crash-at-every-journal-step test confirms no nonce is reissued and no operation restarts (E3).
- **Relay conflicts / inbox quotas:** conflicts and quota withholding abort before decrypt (E3). Two shipped CLIs that could have hidden this evidence are now fail-closed (S18B-F02). E5 inbox-hardening is in CI.
- **Authentication / authorisation:** IPC is HMAC-authenticated and pinned to cell/proposal/session. Signed-call policy tests pass with features. A live SDK signer was NOT RUN.
- **Adversarial conductor behaviour:** the Fable conductor adversarial suite (5) and inbox hardening (7) passed at baseline; the exact-head results come from CI.

## 7. Integration preparation

### 7.1 Topology

`main` → `feature/v0.4.0-stage2c` (PR #1–#6 base) → `sprint1/agent6-stage2c-integration-20261116` (PR #7) → `sprint18/dkg-sdk-integration-recovery-20261116` (PR #18) → `sprint18b/compile-security-verification-20261116` (PR #19, `33db049`) → **`claude/holochain-threshold-crypto-sprint18b-gocnij`** (this candidate; 6 commits, 9 files, no history rewritten).

### 7.2 Outstanding PRs (no PR was closed or merged)

| PR | Head | Relation to candidate | Recommendation |
| --- | --- | --- | --- |
| #1, #2, #3, #5 | ancestors | Already in candidate ancestry | Close after review, as represented |
| #7, #18, #19 | ancestors | Integration chain | Merge in order #7 → #18 → #19 → continuation, **only after approvals** |
| #11, #12, #16 | `25afdd6b`, `472dbd55`, `dafc21e5` | All changed files byte-identical in candidate | Superseded; safe to close after review |
| #10, #13, #14, #15, #17 | various | Imported as linear content commits; differing files are the documented Sprint 1.8 reconciliations (`three_agents.rs` concatenation, frost attribution check, relay ownership fix, `conductor_client`, `signing_session`) | Superseded; close after a reviewer confirms the reconciliation diffs |
| #4, #6 | `319679cf`, `2f3b4c3d` | CI recovery against older base; superseded by `ci.yml`/`sprint18b-verify.yml`; #4 has an un-imported `CI_RUNNER_RECOVERY.md` | Review for salvageable docs, then close as superseded |
| #8 | `2bc9c8d0` | Deliberately excluded (v2 cross-app binding; coordinator migration) | **Independently relevant; BLOCKED** on S1-M02 operator decision |
| #9 | `319c04f2` | Deliberately excluded (production custody profile) | **Independently relevant; BLOCKED** on S1-H01 operator decision |

### 7.3 Required operator decisions

1. INV13-A…E (authority, verifier placement and wire change, restart/rotation, schema permission, E8). See `SPRINT18B_INV13_IMPLEMENTATION_DESIGN.md`.
2. Release-inventory approval for the 5 deltas in §5, and separately any artifact-hash recording.
3. S1-H01 custody profile (PR #9), S1-M02 v2 binding (PR #8), S1-M03 lifetime/rekey, S1-L01 slot collision policy.
4. Provisioning of a disposable approved signer identity for the live SDK status read.
5. Whether to accept a formatting-only PR.

### 7.4 Recommended next steps

1. Record the exact-head CI results for `2eb1efc` in §4.
2. Open a draft PR from this branch to `sprint18b/compile-security-verification-20261116` (or fast-forward PR #19 with approval).
3. Obtain the INV-13 decisions, then implement the worker-side admission per the design behind a reviewed wire change, with the §7 test list.
4. Only then attempt E6, followed by E8 review and the inventory approval.

## 8. Final status

**BLOCKED — OPERATOR APPROVAL REQUIRED.** Every reproducible, safely fixable defect found is fixed and verified natively at `2eb1efc`. The four custody tests, the hidden feature-build compile failures and the gate-masking CI harness are all resolved, and INV-13 remains fail-closed and now has proven negative coverage. Completion is still blocked by decisions that aren't engineering's to make: the INV-13 independent key-roster authority (no E6 is possible without it), the release-inventory approval, and the open production-custody and cross-app findings. No E8 review has been performed.
