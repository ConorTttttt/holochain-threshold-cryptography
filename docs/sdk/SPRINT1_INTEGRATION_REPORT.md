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
- Other-agent commits, patches and reports: **NOT RECEIVED** at the time of
  this ledger. No other-agent code has been integrated or tested together.

## Agent 5 delivered changes

| Path | Purpose |
| --- | --- |
| `.github/workflows/ci.yml` | PR static/native checks; push/manual ephemeral Sweettests; explicit manual release identity gate |
| `flake.nix` | Provision PyYAML with pinned Nix Python for existing release validators |
| `docs/sdk/TESTING.md` | Layer-by-layer command matrix, approval rules, evidence requirements |
| `docs/sdk/DEVELOPMENT.md` | Reproducible developer entry points, SDK expectations and custody boundaries |
| `docs/sdk/SPRINT1_INTEGRATION_REPORT.md` | This honest integration ledger |

The workflow does not set or use persistent Lair credentials, deploy cells,
re-record hashes, or modify release inventories. It does not replace the
existing `scripts/check_release.py` and `scripts/release_check.py` safety checks.

## Agent integration status

| Agent | Evidence / code available | Integration result |
| --- | --- | --- |
| 1 — Independent security reviewer | No Sprint 1 review report received | **NOT RUN**; independent sign-off required |
| 2 — Coordinator/native inbox consumer | No Sprint 1 patch received | **NOT INTEGRATED**; late-equivocation rejection unverified |
| 3 — DKG lifecycle and crash safety | No Sprint 1 patch received | **NOT INTEGRATED**; F1/F2 unresolved |
| 4 — Public Rust SDK | `crates/holochain-dkg-sdk/` absent on baseline | **NOT INTEGRATED**; SDK tests NOT RUN |
| 5 — CI / developer experience | CI config and docs proposed on Agent 5 branch | **PROPOSED, NOT CI-VALIDATED** |
| 6 — Integration coordinator | Cannot complete without 1–4 and cross-branch testing | **BLOCKED** |

## Verification log

GitHub repository metadata, branch list, tracked paths, manifests and
existing test/release scripts were inspected via the GitHub connection.
That is **source inspection**, not compilation or a passing test suite.
The environment used for this inspection does not provide `cargo`, `rustc`,
`nix` or `hc`, and direct Git cloning has no DNS access.

| Command or suite | Status | Explanation |
| --- | --- | --- |
| `cargo check --offline --locked --workspace --all-targets` | **NOT RUN** | Rust toolchain unavailable |
| `python3 -I scripts/check_release.py` | **NOT RUN** | Full private repo not locally checked out |
| `npm run test:release-tools` | **NOT RUN** | Full private repo not locally checked out |
| `npm run test:native` | **NOT RUN** | Rust toolchain and source checkout unavailable |
| `cargo test --offline --locked -p holochain-dkg-sdk --all-targets` | **NOT RUN** | SDK crate absent |
| `npm run test:sweettest` | **NOT RUN** | Holonix / `hc` and test conductors unavailable |
| `npm run check:release` | **NOT RUN** | Fresh source build unavailable; prior Stage 2C identity failure recorded |
| `scripts/phase6_faults.py` and signing fault rehearsals | **NOT RUN** | Disposable multi-conductor harness not provisioned |
| GitHub Actions workflow | **NOT RUN** | Must confirm results from actual GitHub runner executions |

The Stage 2C development report (`docs/V040_STAGE2C_COORDINATOR_HARDENING.md`)
documents historical **153/153 native** and **11/11 Sweettest** results, plus
an expected release identity failure. Those were not rerun on this Sprint 1
branch and are **not** represented above as Sprint 1 PASS results.

## Remaining security findings, compatibility and risks

- Existing review baseline describes seven findings (1 High, 4 Medium, 2 Low),
  but details require an independent Agent 1 report; severity totals alone
  cannot establish remediation or exact scope.
- **F1:** DKG can exit without durable abort; old running journal may remain.
- **F2:** Local share completion may occur without full group activation.
- Stage 2C introduces `get_inbox_slots`; native DKG/signing consumers still
  require verified conflict-metadata handling and late-equivocation policy.
- **R10-a:** relaxed chain ordering can yield a delivery receipt action hash
  that is not the final stored action. Verify the transport/consumer contract.
- Holochain protocol is scoped to the pinned 0.7.1 family; `main` is older.
  The SDK crate, API compatibility and cross-application replay binding
  remain unvalidated.
- Stage 2C changed coordinator WASM / `.dna` / `.happ`; approved hashes still
  identify Stage 2B artifacts. This **release gate remains open**.
- GitHub runner disk/RAM availability and native Holonix provisioning are
  unvalidated until a full workflow run. CI configuration alone is not a
  passing reproducibility result.

## Release control and operator action

Do **not** run `release_check.py --record` or
`check_release.py --record-inventory` to create a green check. Review all
source changes and all approved inventory differences first. Rebuild from the
verified commit, capture old and new identities, obtain explicit operator
approval, apply the approved updates and rerun checks *without* recording.
There has been **no deployment or persistent-cell upgrade** in this work.

## Remaining integration work / Sprint 2 candidates

1. Collect and independently review Agents 1–4 commits and their command logs.
2. Integrate overlapping native worker changes only after security review;
   prove conflict isolation and fail-closed signing/DKG handling.
3. Close or explicitly accept F1/F2 with tested lifecycle invariants and
   disposable process-kill/restart scenarios.
4. Bring in the SDK and update the approved workspace inventory only after
   the new manifest, lockfile and binary implications are reviewed.
5. Execute PR native checks, push/manual Sweettests and fault rehearsals on
   the exact integrated commit, preserving exit codes and logs.
6. Confirm rebuilt Stage 2C+ coordinator identities; obtain operator approval
   for any release-hash update and rerun the read-only release checks.
7. Repeat an independent security review of the combined changes and write
   the final report with actual commits, test evidence and release decision.

**Final verdict: CHANGES REQUIRED — Blocking issues remain.**

This verdict must not be upgraded based solely on passing unit tests or
configuration-file inspection.
