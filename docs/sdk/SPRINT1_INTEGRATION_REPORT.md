# Sprint 1 — Agent 6 integration and build-validation report

**Date:** 2026-11-16 UTC  
**Decision:** **CHANGES REQUIRED — DRAFT; NOT a security pass, release approval, or production deployment.**  
**Repository:** ConorTttttt/holochain-threshold-cryptography  
**Base branch:** feature/v0.4.0-stage2c  
**Verified base SHA:** 122679a7239b97584c153d7ed1feecd35b914061  
**Integration branch:** sprint1/agent6-stage2c-integration-20261116  
**Initial integrated commit:** d5da2d37dcf2fee521c43786aab36c0f24accea0  
**Integrated tree SHA:** e958aaf51c27d6a029950c1d8a1028c392174a5e  
**PR status:** draft until a Rust-enabled runner proves all required gates.

## 1. Exact provenance and scope

The initial integration commit has **six Git parents**, in this order: the exact Stage 2C baseline and the five existing PR heads. This retains each PR's original reachable commit history (no squashing, no merging into main). Changes were assembled onto a tree based strictly on Stage 2C.

| Contribution | PR | Original tip SHA | Status in integration |
| --- | --- | --- | --- |
| Rust application SDK foundation | #1 | eaf24e6af2f77036cf7a8d61f6f432898a7f0657 | Incorporated |
| Independent security review | #2 | 969ee842e8d56452c6ecaccf091424ccfa3a280c | Incorporated as finding register; not a security sign-off |
| Structured native inbox integration | #3 | eb6e33c4b1f7d3d71e0cb2d01cd33b70eff88959 | Incorporated |
| Nix/CI and development test plan | #4 | 5ab8f1947b2a40d3a5cf6fec887b9bc851c0f521 | Incorporated; provisional report replaced |
| Durable abort and partial-activation coverage | #5 | ec0176c0e4dbc19459dec3ef6516e02ba6c80198 | Incorporated |

Source inventory: 36 changed paths in the initial integrated tree, including root Cargo.toml, Cargo.lock, and the four overlap resolutions. Every other file changed by an upstream PR is taken directly from that PR head's Git blob. The Stage 2C baseline and PR head identities were checked against GitHub metadata; the integration branch was created from the exact baseline SHA.

## 2. PR #3 / PR #5 conflicts and security-sensitive resolution

The original PR patches were interpreted against the identical baseline, and the separate edit ranges were applied to the baseline files in their original order. All hunks matched their baseline context and removals; there were **zero overlapping modified base-line ranges** in the four shared files. Both authors' insertions and replacements remain present. This is a source-level merge check, **not** a compiler or protocol-correctness pass.

| Shared path | Inbox PR #3 retained | Lifecycle PR #5 retained |
| --- | --- | --- |
| crates/mpc-dkg-worker/src/lib.rs | Unix inbox_slots module export | AuthenticatedController::abort_on_disconnect: poisoned controller + durable running-to-aborted transition |
| crates/mpc-dkg-worker/src/relay.rs | get_inbox_slots transport interface; conflict and over-quota scan, including already-seen DKG slots | LocalDkgNode::abort, RelayEngine::abort and poison closure of worker IPC |
| crates/mpc-dkg-worker/tests/relay_simulation.rs | Structured snapshot fixture, late DKG equivocation and selective over-quota tests | Abort-capable mock, network partition / exhausted poll budget test |
| crates/mpc-dkg-worker/tests/signing_session.rs | Signing conflict fixtures, selected-signer late conflict and nonce-burning tests | DurablePort abort handling and completed-share-without-unanimous-activation test |

Security intent retained in the combined source:

1. In relevant DKG rounds, conflicting authenticated and over-quota inbox slots abort the relay, including conflicts that arrive after a first valid observation. Unrelated signing-slot conflicts do not veto DKG.
2. Selected-signing-sender conflicts and over-quota evidence abort signing; the signing journal remains responsible for nonce reservation, burning, and durable failure. Unselected participants do not get a veto.
3. Relay poison now invokes worker connection closure/abort. Disconnect, malformed IPC, cancellation, supervisor timeout and partition have explicit fail-closed paths. A SIGKILL leaves a running checkpoint that **must not resume**, and completed shares are not automatically erased or activated.
4. Group signing still requires unanimous activation and operator-approved signing intent; locally completed custody does not imply a globally activated group.
5. Existing signer policy keeps exact proposal/app/agent pinning, fresh nonces, operation allowlists and role separation. No legacy get_inbox downgrade or automatic ambiguous-write retry was introduced.

These are verified **source-presence and control-flow observations only**. Dynamic fault injection and security sign-off remain required.

## 3. Workspace, native dependencies, lockfile, source approval

- Added crates/holochain-dkg-sdk to root [workspace].members; left default-members and resolver unchanged.
- SDK default feature is empty. It directly depends on the local core and security crates. Optional native-holochain enables the local worker dependency with its conductor-client feature and tokio sync. The worker feature transitively enables pinned Holochain 0.7.1 native websocket/conductor API, serialized-byte support and existing signed socket client. The PR #3 worker change also makes holochain_zome_types =0.7.1 unconditional because the structured inbox type is compiled without conductor-client.
- Added the SDK package record to Cargo.lock using already locked dependency names: holochain-mpc-core, holochain-mpc-dkg-worker, holochain-mpc-security and tokio. **This is a manual lockfile reconciliation, not Cargo regeneration.** No registry versions were intentionally updated. A Rust runner must execute cargo generate-lockfile or cargo check and compare its generated lockfile, then cargo fetch --locked, cargo check --locked --workspace --all-targets and both feature builds before claiming correctness.
- scripts/release_hashes.json and scripts/release_inventory.json were **not changed**. The root workspace membership, worker manifest dependency feature and SDK manifest/source inventory have changed and therefore diverge from approved release/source identities. This must remain a deliberate operator review gate, not be silently re-recorded by the integration agent. No approved hashes or coordinator artifacts were changed.
- Native SDK live-read blocker: the existing FROST signer policy rejects GetProbeSessionStatus (a transport probe is not an approved FROST ceremony status read). A separately reviewed read-only status authorization is needed. SDK write, activation and signature APIs are explicitly unsupported; no production-ready SDK claim is made.

## 4. Evidence: commands, outcomes, exit codes and logs

**GitHub connector operations (API results, not shell exit codes):**
- Verified Stage 2C branch at 122679a7239b97584c153d7ed1feecd35b914061 and baseline Git tree 5d321ddb02946d939d13a5c7afcb1a38b5add719.
- Read each PR's complete changed-path set and per-file patch; verified all five PR tips against GitHub metadata. Read PR-head Git trees and preserved unshared source blobs exactly.
- Created branch sprint1/agent6-stage2c-integration-20261116 from the exact Stage 2C SHA: API SUCCESS.
- Reconciled four shared source files against the same baseline; all patch contexts matched; zero overlapping edit ranges: STATIC MERGE CHECK PASS.
- Created integrated Git tree e958aaf51c27d6a029950c1d8a1028c392174a5e, commit d5da2d37dcf2fee521c43786aab36c0f24accea0 with six parents, and fast-forwarded isolated integration ref: API SUCCESS.
- An API success proves object/ref creation, **not** a working Rust build.

**Local Linux x86_64 environment, 2026-11-16T08:50:04Z:**

| Exact command | Exit code | Observed output | Disposition |
| --- | ---: | --- | --- |
| command -v rustc | 1 | NOT FOUND | Rust compilation NOT RUN |
| command -v cargo | 1 | NOT FOUND | Cargo build/tests/lock regeneration NOT RUN |
| command -v rustup | 1 | NOT FOUND | Rust toolchain unavailable |
| command -v nix | 1 | NOT FOUND | Pinned Nix build NOT RUN |
| command -v hc | 1 | NOT FOUND | Holochain Sweettests NOT RUN |
| command -v python3 | 0 | /opt/pyvenv/bin/python3 | Python present |
| command -v git | 0 | /usr/bin/git | Git present |
| git ls-remote https://github.com/ConorTttttt/holochain-threshold-cryptography.git refs/heads/feature/v0.4.0-stage2c | 128 | fatal: unable to access ... Could not resolve host: github.com | Local clone NOT AVAILABLE |

PyYAML 6.0.3 is installed. **Independent Python CI-policy verification PASS (4/4; exit 0)** on a local checkout surrogate at /tmp/sprint1_ci_verify, containing exact GitHub-blob-equivalent copies of the integrated files only:
- .github/workflows/ci.yml: local git hash-object = 1cbaca6f94b9f2af0ec28f60b813a0adf33e14bf (matches GitHub blob).
- scripts/tests/test_ci_workflow.py: local git hash-object = 4c0b9806922c2a84cb6690552c3c669e9f838b5c (matches GitHub blob).
- Executed: cd /tmp/sprint1_ci_verify && python3 -m unittest discover -s scripts/tests -p test_ci_workflow.py -v
- Exit: **0**; observed 4 tests run in 0.019s, all ok, output ends with OK.
- Cases: test_all_shell_steps_have_valid_bash_syntax; test_expected_event_and_job_split; test_no_automatic_artifact_approval_or_deployment; test_sdk_absence_is_not_mislabeled_a_pass.
- The successful checks validate only the workflow Python/YAML policy and shell syntax: **not** a Rust compiler, Nix runner, GitHub Actions execution, or an integrated build.

The upstream PR #4 also reports an earlier independent author run. Its reported Actions run 43771483501 failed with no assigned runner or job steps; do not count it as Rust execution.

## 5. Required test-evidence matrix

No compiler, Nix, or Holochain runner exists locally. **NOT RUN is not PASS**, and the integrated commit has no verified successful build.

| Test group / exact command | Current status | Release condition |
| --- | --- | --- |
| python3 -m unittest discover -s scripts/tests -p test_ci_workflow.py -v | **PASS: 4/4, exit 0** | Exact source SHA verified; CI workflow policy/syntax only (local two-file fixture) |
| cargo test --locked -p holochain-dkg-sdk --all-targets | **NOT RUN** | SDK default build/tests required |
| cargo test --locked -p holochain-dkg-sdk --features native-holochain --all-targets | **NOT RUN** | Real native dependencies and read backend compile required |
| cargo check --locked --workspace --all-targets | **NOT RUN** | Combined workspace check required |
| cargo test --locked -p holochain-mpc-dkg-worker --features conductor-client --lib | **NOT RUN** | Native signed-transport checks required |
| cargo test --locked -p holochain-mpc-dkg-worker --test relay_simulation | **NOT RUN** | PR #3 late equivocation and PR #5 partition/worker abort required |
| cargo test --locked -p holochain-mpc-dkg-worker --test signing_session | **NOT RUN** | Late selected-signing conflict, nonce burn, incomplete activation required |
| cargo test --locked -p holochain-mpc-dkg-worker --test node_service | **NOT RUN** | F1 clean EOF, truncated IPC, terminal journal abort required |
| cargo test --locked -p holochain-mpc-dkg-worker --test dkg_restart | **NOT RUN** | No restart of nonterminal/aborted DKG required |
| cargo test --locked -p holochain-mpc-dkg-worker --test share_custody | **NOT RUN** | F1 SIGKILL at round boundaries, share retention policy required |
| cargo test --locked -p holochain-mpc-runtime --test dkg_journal | **NOT RUN** | F1 encrypted running-to-aborted journal transition required |
| cargo test --locked -p holochain-mpc-dkg-worker relay_supervisor | **NOT RUN** | Cancellation mid-start, timeouts and shutdown required |
| npm run test:sweettest | **NOT RUN** | Real Holochain conductor/coordinator regressions required |
| cargo test --locked -p mpc --test revoke_cap_grant -- --nocapture --test-threads=1 | **NOT RUN** | Native capability and zome permission test required |
| python3 -I scripts/check_release.py | **NOT RUN** | Operator-approved inventory gate; expected to report changed identities until approved |
| npm run check:release | **NOT RUN** | Operator-controlled final artifact approval and hash validation |

F1/F2 explicit fault scenarios to rehearse on disposable test identities: disconnect-before-Init (no false tombstone); clean EOF after Init and each round; malformed/truncated IPC; cancelled start; RPC deadline; network partition; SIGKILL at rounds 1/2/3 with persistent journal; completed-share survival; partial group activation with signature refusal; late conflicting DKG and selected-signing slots with a prior accepted variant and nonce exhaustion. No production node, real funds, approved signing share, persistent Lair state, or deployment may be used.

## 6. Open security/release blockers

1. **S1-H01 HIGH OPEN**: default share-custody key and software rollback anchor may be co-located with encrypted shares; production separation and independent witness not demonstrated. Do not release real custody.
2. **S1-M01 still needs integrated dynamic proof**: source-level inbox/late-equivocation fixes are present, but real coordinator behavior, late visibility/finality and signed read permissions have not been run end to end.
3. **S1-M02 / app-context boundary**: independently verify exact proposal/DNA/agent membership and no cross-app leakage in live multi-app conductor tests.
4. **S1-M03 and F2 policy**: decide group-wide retention/retirement for partial completion; an individual sealed share must never imply active group or signing permission.
5. **Native SDK read authorization**: separately approve a minimal read-only FROST status signer intent; never repurpose the transport-probe signer or weaken operator approval.
6. **Cargo.lock and source inventory**: manually reconciled SDK lock stanza is not regenerated/verified; approved release inventories and source/hashes intentionally remain untouched and need operator review.
7. **Rust/Holochain CI availability**: execute all matrix rows on a provisioned, pinned runner, attach exact test commands, exit statuses, timestamps, job IDs and unabridged failure logs. PR #4's prior runner-with-no-steps failure is not evidence of success.
8. **Deployment gate**: independent security sign-off, explicit production-custody assumptions, artifact/hash approvals and passing integrated Sweettests are prerequisites. No coordinator deployment or Lair modification here.

**Final verdict: CHANGES REQUIRED. Keep the integration PR draft, target Stage 2C rather than main, and do not merge or promote until all required checks are genuinely verified.**
