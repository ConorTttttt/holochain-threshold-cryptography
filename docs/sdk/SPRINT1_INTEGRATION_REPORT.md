# Sprint 1 integration report — provisional ledger

**Date:** 2026-11-15 (UTC)  
**Verdict: CHANGES REQUIRED — Blocking issues remain**  
**Status:** preliminary integration ledger, **not a completed Sprint 1
integration**, security attestation, deployment approval or release.

## Baseline and change provenance

- Repository: `ConorTttttt/holochain-threshold-cryptography`.
- Correct Sprint 1 baseline: `feature/v0.4.0-stage2c` at commit
  `122679a7239b97584c153d7ed1feecd35b914061`.
- Default `main` remains at `8dec22361b484f79c309c10f7dbbbe26e4ab47d5`
  and does **not** include the Stage 2C worker and release-tool baseline.
- Agent 5 candidate branch: `agents/sprint1-ci-sdk-testing`, forked from
  `122679a`. This is a **standalone review branch**, not an integrated merge.
- Agent 4 opened draft PR #1, `agent4/sdk-foundation-stage2c` at
  `eaf24e6af2f77036cf7a8d61f6f432898a7f0657`; it proposes a read-only
  SDK facade. It intentionally does not add workspace membership, and its own
  report says Rust tests were **NOT RUN**. The PR is **not integrated**.
- Agent 1 opened draft PR #2 at `969ee842e8d56452c6ecaccf091424ccfa3a280c`
  with `docs/sdk/SPRINT1_SECURITY_REVIEW.md`. This independent **source-only**
  review reports **CHANGES REQUIRED** (8 new findings, including a High
  custody/layout blocker). It is **not integrated** and did not run tests.
- Agent 2 opened draft PR #3 at `eb6e33c4b1f7d3d71e0cb2d01cd33b70eff88959`
  with a new native `get_inbox_slots` client/relay/signing implementation;
  its PR explicitly says Rust validation is **NOT YET VERIFIED**.
  It is **not integrated**; late-equivocation and nonce tests remain unrun.
- Agent 3 opened draft PR #5, `sprint1/agent3-dkg-lifecycle` at
  `ec0176c0e4dbc19459dec3ef6516e02ba6c80198`, proposing durable
  abort-on-disconnect and F2 non-activation regressions. Its PR reports
  **NOT RUN** for Rust tests; it is **not integrated**.
- Agent 2 and Agent 3 change four overlapping worker paths. No
  other-agent code has been integrated or tested together.

## Agent 5 delivered changes

| Path | Purpose |
| --- | --- |
| `.github/workflows/ci.yml` | PR static/native checks; push/manual ephemeral Sweettests; explicit manual release identity gate |
| `flake.nix` | Provision PyYAML with pinned Nix Python for existing release validators |
| `scripts/tests/test_ci_workflow.py` | Four offline regression tests for workflow event routing, Bash syntax, SDK NOT RUN and no automatic release approval |
| `docs/sdk/TESTING.md` | Layer-by-layer command matrix, approval rules, evidence requirements |
| `docs/sdk/DEVELOPMENT.md` | Reproducible developer entry points, SDK expectations and custody boundaries |
| `docs/sdk/SPRINT1_INTEGRATION_REPORT.md` | This honest integration ledger |

The workflow does not set or use persistent Lair credentials, deploy cells,
re-record hashes, or modify release inventories. It does not replace the
existing `scripts/check_release.py` and `scripts/release_check.py` safety checks.

## Agent integration status

| Agent | Evidence / code available | Integration result |
| --- | --- | --- |
| 1 — Independent security reviewer | Draft PR #2 reports eight independent source-level findings: 1 High, 4 Medium, 3 Low | **REVIEW RECEIVED, NOT MERGED**; CHANGES REQUIRED; dynamic tests NOT RUN |
| 2 — Coordinator/native inbox consumer | Draft PR #3 contains 13 changed worker/test/doc paths | **NOT INTEGRATED**; native test execution NOT RUN |
| 3 — DKG lifecycle and crash safety | Draft PR #5 proposes durable F1 abort and F2 partial-activation tests | **NOT INTEGRATED**; authored tests NOT RUN; F1/F2 not closed |
| 4 — Public Rust SDK | Draft PR #1 offers read-only SDK files; workspace membership omitted | **NOT INTEGRATED**; SDK tests NOT RUN; live FROST status permission blocked |
| 5 — CI / developer experience | CI config and docs proposed on Agent 5 branch | **PROPOSED, NOT CI-VALIDATED** |
| 6 — Integration coordinator | Cannot complete without 1–4 and cross-branch testing | **BLOCKED** |

## Cross-branch overlap inspection

Draft PR #3 (Agent 2) and PR #5 (Agent 3) both modify:

| Shared path | Agent 2 changes | Agent 3 changes | Integration action |
| --- | --- | --- | --- |
| `crates/mpc-dkg-worker/src/lib.rs` | New inbox-slot module export | Authenticated controller terminal abort on disconnect | Reconcile API and worker lifecycle; review errors and custody state |
| `crates/mpc-dkg-worker/src/relay.rs` | `MpcTransport::get_inbox_slots`; fail-closed DKG conflict inspection | `LocalDkgNode::abort`, relay abort/poison, transport disconnect handling | Preserve both fail-closed paths and ensure conflicting inbox cannot bypass journal abort |
| `crates/mpc-dkg-worker/tests/relay_simulation.rs` | Structured inbox fixtures and late-equivocation regressions | Relay error/timeout/partition-abort regression | Combine mock trait implementations and rerun both classes of tests |
| `crates/mpc-dkg-worker/tests/signing_session.rs` | Structured signing inbox fixtures and nonce-burning late-conflict tests | Controller disconnect mock plus incomplete-group signing test | Combine mocks, verify no nonce use after either abort path |

These file overlaps were verified from PR #3 and #5 GitHub patch hunks,
not from a local merged tree. The hunks target mostly different locations,
but compilation, trait completeness, state invariants and actual conflict-free
integration are **NOT VERIFIED**. No automatic merge was attempted.

## Verification log

GitHub repository metadata, branch list, tracked paths, manifests and
existing test/release scripts were inspected via the GitHub connection.
That is **source inspection**, not compilation or a passing test suite.
The environment used for this inspection does not provide `cargo`, `rustc`,
`nix` or `hc`, and direct Git cloning has no DNS access. An exact local copy
of the workflow was verified against the GitHub blob SHA
`1cbaca6f94b9f2af0ec28f60b813a0adf33e14bf`; the offline workflow-policy
test source was verified against blob SHA
`4c0b9806922c2a84cb6690552c3c669e9f838b5c`.

| Command or suite | Status | Explanation |
| --- | --- | --- |
| `python3 -m unittest discover -s scripts/tests -p test_ci_workflow.py -v` | **PASS** | Executed locally on blob-identical workflow and test source: 4 tests OK (YAML/event policy, no record/deploy, SDK NOT RUN, Bash syntax); not a runner test |
| `cargo check --offline --locked --workspace --all-targets` | **NOT RUN** | Rust toolchain unavailable |
| `python3 -I scripts/check_release.py` | **NOT RUN** | Full private repo not locally checked out |
| `npm run test:release-tools` | **NOT RUN** | Full private repo not locally checked out |
| `npm run test:native` | **NOT RUN** | Rust toolchain and source checkout unavailable |
| `cargo test --offline --locked -p holochain-dkg-sdk --all-targets` | **NOT RUN** | SDK crate absent |
| `npm run test:sweettest` | **NOT RUN** | Holonix / `hc` and test conductors unavailable |
| `npm run check:release` | **NOT RUN** | Fresh source build unavailable; prior Stage 2C identity failure recorded |
| `scripts/phase6_faults.py` and signing fault rehearsals | **NOT RUN** | Disposable multi-conductor harness not provisioned |
| GitHub Actions PR #4 run `43771483501` (commit `bbfe2dd`) | **FAIL** | `static` and `native` jobs failed; `integration` and `release` skipped by design. Both jobs completed in about two seconds with **zero steps** and no assigned runner name in GitHub's API. Logs could not be retrieved (404); likely a pre-execution runner/provisioning problem, **not proof any test command executed**. The precise failure cause is unknown |

The Stage 2C development report (`docs/V040_STAGE2C_COORDINATOR_HARDENING.md`)
documents historical **153/153 native** and **11/11 Sweettest** results, plus
an expected release identity failure. Those were not rerun on this Sprint 1
branch and are **not** represented above as Sprint 1 PASS results.

## Remaining security findings, compatibility and risks

- The original checkpoint describes **seven** unlabelled findings
  (1 High, 4 Medium, 2 Low); Agent 1's newly source-identified **eight**
  (1 High, 4 Medium, 3 Low) in draft PR #2 are a separate register and
  must **not** be equated to or assumed to close the original seven.
- **S1-H01 (High, open):** default development custody writes decryption
  material and software rollback anchor under the same state directory as
  sealed shares. Real custody needs separately protected key source/anchor;
  test-mode file permissions alone are insufficient.
- **S1-M01 and S1-M02 (Medium, open):** native clients miss late inbox
  conflicts; generic message envelopes lack exact app/context/proposal
  binding. These block a multi-application SDK security claim.
- **S1-M03 and S1-M04 (Medium):** permanent per-sender inbox quota imposes
  rekey/expiry requirements; locally complete DKG is not global activation.
  The independent reviewer found three additional Low issues concerning
  operation-slot prefix collisions, relaxed-order receipt identities and
  durable abort accounting.
- **F1:** DKG can exit without durable abort; PR #5 proposes abort-on-disconnect
  but no runtime or fault-injection test has executed on that code.
- **F2:** Local share completion may occur without full group activation;
  PR #5 proposes a fail-closed signing regression, but cannot turn local
  completion into unanimous activation evidence.
- Stage 2C introduces `get_inbox_slots`; native DKG/signing consumers still
  require verified conflict-metadata handling and late-equivocation policy.
- **R10-a:** relaxed chain ordering can yield a delivery receipt action hash
  that is not the final stored action. Verify the transport/consumer contract.
- Holochain protocol is scoped to the pinned 0.7.1 family; `main` is older.
  Agent 4's draft SDK is not yet in the workspace. Its proposed native
  FROST status read requires a separately reviewed signer authorisation
  path; its write/activation/signing APIs remain unsupported. API
  compatibility and cross-application replay binding remain unvalidated.
- Stage 2C changed coordinator WASM / `.dna` / `.happ`; approved hashes still
  identify Stage 2B artifacts. This **release gate remains open**.
- GitHub Actions run `43771483501` completed **FAIL** in both PR jobs;
  GitHub API shows **zero steps executed**, empty assigned runner names and
  approximately two-second lifetimes. The log endpoint returned 404.
  This suggests a pre-execution runner scheduling/provisioning problem,
  but the actual cause is not confirmed. Runner disk/RAM and Holonix
  provisioning therefore remain unvalidated. A valid YAML file and four passing local
  policy tests are not a passing GitHub workflow.

## Release control and operator action

Do **not** run `release_check.py --record` or
`check_release.py --record-inventory` to create a green check. Review all
source changes and all approved inventory differences first. Rebuild from the
verified commit, capture old and new identities, obtain explicit operator
approval, apply the approved updates and rerun checks *without* recording.
There has been **no deployment or persistent-cell upgrade** in this work.

## Remaining integration work / Sprint 2 candidates

1. Review Agents 1–4 draft PRs (#2, #3, #5 and #1), map eight newly
   identified findings to remediation owners, and do not conflate them with
   the original seven unspecified findings.
2. Reconcile four shared worker paths between Agents 2 and 3 after source
   review; compile and test the combined trait/mocks and prove conflict
   isolation, durable abort and fail-closed signing/DKG handling.
3. Close or explicitly accept F1/F2 with tested lifecycle invariants and
   disposable process-kill/restart scenarios.
4. Bring in the SDK and update the approved workspace inventory only after
   the new manifest, lockfile and binary implications are reviewed.
5. Diagnose failed PR #4 workflow run `43771483501` (jobs have zero steps,
   empty runner names and no retrievable logs), including repository Actions
   permission/billing/runner eligibility and configuration; then
   execute PR native checks, push/manual Sweettests and fault rehearsals on
   the exact integrated commit, preserving exit codes and logs.
6. Confirm rebuilt Stage 2C+ coordinator identities; obtain operator approval
   for any release-hash update and rerun the read-only release checks.
7. Repeat an independent security review of the combined changes and write
   the final report with actual commits, test evidence and release decision.

**Final verdict: CHANGES REQUIRED — Blocking issues remain.**

This verdict must not be upgraded based solely on passing unit tests or
configuration-file inspection.
