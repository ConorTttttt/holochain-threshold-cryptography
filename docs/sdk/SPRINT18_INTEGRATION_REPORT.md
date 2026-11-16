# Sprint 1.8 — Integration recovery report

**Status: CHANGES REQUIRED. Not a release, deployment approval or independent audit.**
**Starting commit:** `899e433d057a4d1a0533e2304a2493edb75ad82f`.
**Starting branch:** `sprint1/agent6-stage2c-integration-20261116`.
**Isolation branch:** `sprint18/dkg-sdk-integration-recovery-20261116`.
**Integration checkpoint before reports:** `710159af134f4bf727ddaba3c524a036645c6953`; obtain the actual immutable report/PR head SHA from GitHub after this file is committed. Never claim this placeholder is the final release SHA.

## Baseline decision
GitHub branches, PRs #6–#17 and Actions were inspected on 2026-11-16. No **validated** successor to the starting SHA was established. On baseline, GitHub Actions 43835405873 failed with E0433 at `crates/mpc-dkg-worker/src/inbox_slots.rs`; its release-inventory job also failed. Actions 43918839519 on PR #14 reported 5/5 protocol adversarial PASS and 8/9 FROST integration PASS, with share-attribution failure. A tested PR head is not equivalent to a tested integration commit. `main` is stale and was not touched.

## Imported source and provenance
Reviewed candidate heads were incorporated as separately attributed integration commits (original PR histories remain reachable through source PRs; GitHub integration records are linear commits containing exact file content, NOT Git merge commits):

| PR | Candidate head | Integration commit | Disposition |
| --- | --- | --- | --- |
| #10 | `363c9f4341ffbe201fa9c3ce9b4f248cfd6071ef` | `1517e2724903e01b157f5d9617939ec74797c77e` | Read-only live SDK status-read candidate |
| #11 | `25afdd6bfc979259cec9416ae5d104780ef384f6` | `01e077e6bff1bd5039a009455a18bba90b521d2b` | Independent Sprint 1.5 reports, without changing findings |
| #12 | `472dbd55606f1f24abd924608c502a8df6aae49b` | `70a9ed718e1f582139ed9e8a7c7bf56c0e2f14d4` | Conductor adversarial tests, E1 initially |
| #13 | `352ac6c0648deb8d3480c63ea86edba516ddd62b` | `0b8b1be6dff73ae40521af3de40951d1a44ad8d4` | Signing-slot and quota characterisation; ignored expiry remains ignored |
| #14 | `a8e8dca0889064654190c4f866e7d54e2869c716` | `8ab212326af06b798a6e926d60623ea11364f2e7` | FROST adversarial regression, corpus and workflow |
| #15 | `2f779a937af2f756c2993b21e23781e803fceb08` | `a05baa20254d7341a91c1dcc0516e33e31441216` | Fail-closed storage-fault cleanup and SQLite regression |
| #16 | `dafc21e5ebbbd5b9ff797c3efdf7592636428463` | `5d2ad0886e76a6819332598e64f7c2c7212baa6a` | Fable reconciliation/matrices |
| #17 | `5ac2f8d3b2077c3d56fb349ae2d5546794c0ba87` | `82cb09000fbd3e7e62ecc0f8892d78daa11bc1af` | Round-2 duplicate and key-roster regressions |

PR #6's optional `phase5c_live_writes` example gate was selectively applied. PR #8's unapproved coordinator/wire migration and PR #9's non-production-approved custody profile were **not** merged. PR #7 is the starting combined baseline. The original feature stack, custody, protocol and SDK semantics were not rebuilt.

## Shared-file reconciliation and security changes
The only direct Sprint 1.7 PR #12–#17 file collision was `crates/mpc-frost-ed25519/tests/three_agents.rs` (#14 + #15). Each head's append-only addition was checked against the identical original baseline and concatenated; the upstream regression expecting forged attribution to fail was preserved. PR #13 adds tests to a different worker signing test.

At commit `f859ac6d775fe8203bc24c35e90979d687477f24`:
- Made `holochain_zome_types = "=0.7.1"` a normal wire-type dependency because default Unix inbox-slot and relay/signing consumers require it, without enabling `conductor-client` or Lair signer by default.
- Gated optional privileged `phase5c_live_writes` example on `lair-signer`.
- Added direct pinned `frost-core 3.0.0` dependency and explicit authenticated-signature-share checks in the collector **before** upstream aggregation. A mathematically valid aggregate does not prove per-sender attribution. The original adversarial test assertion remains unchanged.
- Added an explicit fail-closed live `ConductorBridge::round_two` gate until independent key-roster approval exists; conductor observations alone do not supply that approval. This intentionally prevents a live secret-bearing Round 2 and may conflict with the existing positive conductor DKG test until the operator resolves INV-13.
- Added CI default/conductor/lair build checks and SDK native checks; GitHub workflows are the only available Rust execution path in this environment.

At commit `710159af134f4bf727ddaba3c524a036645c6953`, S15-L01 is source-mitigated by journaling an abort if `SigningSession::begin` fails after a successfully registered deadline. A SQLite reopen/retry/fresh-operation regression was added.

## Dependencies / workspace / inventory
The SDK was already a workspace member in Sprint 1; PR #10 adds its optional live-read dependencies. Cargo.lock was updated for the SDK package and to list a direct use of the existing pinned `frost-core 3.0.0`. The authoritative lock graph still needs `cargo check --locked` on the exact integration SHA. The operator-approved `scripts/release_inventory.json` does not yet cover the SDK; the release inventory gate remains **BLOCKED** pending human review. `scripts/release_hashes.json`, approved WASM/DNA/hApp identities, persistent cells, `main`, and production custody were not altered.

## Changed path categories
Worker: `src/conductor_bridge.rs`, `src/relay.rs`, `src/signing.rs`, `src/frost_status_signer.rs`, `src/lib.rs`, signer/client support, worker manifest, Round-2 and signing test files. Native FROST: `src/lib.rs`, `tests/three_agents.rs`, crate manifest. Runtime tests: `crates/mpc-runtime/tests/durable.rs`. Coordinator tests: `fable_conductor_adversarial.rs`. SDK: `src/native.rs`, `examples/live_status.rs`, manifest and API contract. Security protocols: adversarial properties and fuzz corpus. Docs: `docs/sdk/SPRINT15_*`, `FABLE_*`, `SIGNING_*`, `DKG_ROUND2_*`, `SPRINT18_*`. Root: `Cargo.lock`, `.github/workflows/ci.yml`, `.github/workflows/frost-adversarial.yml`, `package.json`. Use `git diff --name-status 899e433...HEAD` for the exhaustive authoritative list.

**Integration approval is withheld until a single exact candidate passes required E2–E7 checks, key-roster policy is approved/implemented and E8 independent review is performed.**
## Sprint 1.8B continuation (2026-11-16)
PR #18's current SHA at baseline inspection was `edd7a7757d36da2faca0b566fd850429cce6e10f` (no replacement baseline). Draft [PR #19](https://github.com/ConorTttttt/holochain-threshold-cryptography/pull/19) is based on that exact head and targets the integration branch, not `main`. Its compiler and native test-fixture changes are recorded with immutable commits in `SPRINT18B_VERIFICATION_REPORT.md`. Obsolete `get_inbox` and `inbox` methods became structured slots; the test stores withheld conflict and quota evidence without discarding it. The Round-2 ownership fixture uses an owned member list, and dedicated negative tests require abort before any share decryption on a withheld slot. The original baseline's [Actions 43935051916](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43935051916) failed with E0407/E0046/E0505 (exit 101). No compilation PASS is implied by these source changes.

The dedicated exact-head verification workflow is `.github/workflows/sprint18b-verify.yml`. Consult the latest run for the final PR head, because prior in-flight runs may be cancelled by new source/docs commits. Live Round-2 remains fail-closed under INV-13; its independent authority and exact approval model are **not** resolved by `verify_explicit_key_roster`. See `SPRINT18B_INV13_ADMISSION_DESIGN.md`. Keep release inventory/operator approval and E8 review blocked, and do not merge this draft into `main`.
