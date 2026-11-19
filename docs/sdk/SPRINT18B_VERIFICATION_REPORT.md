# Sprint 1.8B — Compilation and security verification report

**Disposition at drafting: CHANGES REQUIRED.** This is an experimental SDK integration recovery candidate, not a release or independent audit. No changes to production cells, custody, approved hashes, release inventory, deployed DNA or `main` are authorised.

## Immutable provenance and access

- Source baseline: PR [#18](https://github.com/ConorTttttt/holochain-threshold-cryptography/pull/18), branch `sprint18/dkg-sdk-integration-recovery-20261116`, exact starting head `edd7a7757d36da2faca0b566fd850429cce6e10f`. Inspected on 2026-11-16; no newer head at initial inspection.
- Sprint 1.8B dedicated source branch: `sprint18b/compile-security-verification-20261116`; draft PR [#19](https://github.com/ConorTttttt/holochain-threshold-cryptography/pull/19) targets PR #18's integration branch, never `main`.
- Original CI: [Actions 43935051916](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43935051916), native job 133537498649, **FAIL exit 101** on baseline `edd7a775...`. Two obsolete test-trait methods cause E0407/E0046; an ownership test fixture causes E0505. The inventory job was cancelled and conductor/release jobs skipped; not PASS.
- Initial 1.8B source fixes: `ace41acf67c47124eea659caa3f749ffe583091a` (both structured-inbox trait methods); `a6278e321f54a6b7be64b970ada4bffb3d611452` (owned relay participant list); `d4bf787a2d0d1c62029294d7c31131e61ed0f436` (full in-memory structured inbox evidence plus negative fixture); `31756394b450fde858d78fa89f3cf88510d15edb` (relay rejects conflict/quota evidence before decrypt).
- Security design addition: `docs/sdk/SPRINT18B_INV13_ADMISSION_DESIGN.md`, created on `21cd9ac48e4c8a4f01c484864e2c1dac0fd5556f`.
- 1.8B dedicated test workflow: `.github/workflows/sprint18b-verify.yml`, added on `9ddc14fe46f8e33a123fb068e797836c4bfffb3e`; it uses pinned Nix and disposable conductors. Later source pushes cancel earlier in-progress runs by design. CI **must** be evaluated at its exact job `head_sha`, not transposed from an earlier run.

## Compilation changes and security rationale

`crates/mpc-dkg-worker/tests/share_custody.rs` now implements `MpcTransport::get_inbox_slots` and `SigningTransport::inbox_slots` using the current `InboxSlots` wire type. The fixture stores and serves `envelopes`, `conflicts` and `over_quota` together; it does not downgrade withheld evidence to an uncontested `Vec<Envelope>`. The added `transport_fixtures_preserve_conflict_and_quota_evidence` test supplies explicit two-variant conflict and single-variant quota slots to both native transport implementations. Empty collections occur only when the in-memory fixture actually has no withheld evidence.

`crates/mpc-dkg-worker/src/relay.rs` owns the three-participant fixture list before moving `Binding` into `RelayEngine` (fixes the borrow/move E0505 without cryptographic changes). The new `conflicting_structured_share_slot_aborts_before_worker_decrypt` and `quota_withheld_structured_share_slot_aborts_before_worker_decrypt` regressions require terminal abort and no attempted worker decrypt. Existing duplicate Round-2 regressions were not removed.

None of these test-fixture edits relaxes live admission, signing approval, nonce consumption, operation binding or authenticated peer checks. They are NOT verified fixes until exact-head compilation and test execution passes.

## E1–E8 evidence ledger

| Level / gate | Required execution | Status at drafting / evidence |
| --- | --- | --- |
| E1 | Current source changes and regressions present | YES, exact commits above |
| E2 default | `cargo check --locked --workspace --all-targets` | **PENDING CI**, no local Rust toolchain |
| E2 features | Worker default, `conductor-client`, `lair-signer` all targets | **PENDING CI** |
| E3 native | Core, security, runtime, FROST, worker, SDK default + `native-holochain` package suites | **PENDING CI**; no pass count inferred |
| E3/E7 regressions | `share_custody`, `round_two_uniqueness_tests`, `round_two_security`, F-8 and signing fault paths | **PENDING CI**; inherited ignored expiry is not PASS |
| E4 | `npm run build:happ`, record actual WASM/DNA/hApp identities | **PENDING CI**, do not update approved hashes |
| E5/E7 conductor | `npm run test:sweettest`, dedicated Fable adversarial tests | **PENDING CI**; blocked historical positive live DKG is not an E6 success |
| E6 distributed FROST | Actual native crypto across multiple conductors | **BLOCKED** by unapproved INV-13; not claimed |
| E5 SDK status | Authenticated `live_status` example through disposable Holochain 0.7.1 conductor and restricted signer | **NOT RUN**; needs separately provisioned test identity, app token and operator-approved SessionSpec; mocked status test is insufficient |
| E8 | Independent Holochain/FROST code review and policy approval | **NOT PERFORMED** |

Relevant 1.8B CI run for source SHA `31756394b450fde858d78fa89f3cf88510d15edb`: [Actions 43945789154](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43945789154), **in progress when report was drafted**. The eventual final PR head may be newer because this evidence/report commit changes documentation; use its exact subsequent Actions run for final verification. No claim of PASS is made here for a workflow that has not completed.

Historical evidence cannot be transferred: [43934671439](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43934671439) recorded 5/5 seeded security tests and 16/16 three-agent FROST tests at `5957fc3b835501643571453348acf4c78482fe8e`. The older Fable `8dec223...` baseline recorded 37/37 native tests only, not conductor execution.

## INV-13, storage and Holochain blockers

Existing `verify_explicit_key_roster` authenticates neither approval authority nor an out-of-band consent artifact; its exact member/key/action comparison and native-key check are necessary but insufficient. `ConductorBridge::round_two` deliberately returns `INV-13 ... live delivery blocked` before sending encrypted shares. Retain this block until the project operator authorises the authority model, exact manifest, binding, restart and rotation decisions in `SPRINT18B_INV13_ADMISSION_DESIGN.md` and a reviewed native verifier is implemented. Observed DHT registrations cannot approve themselves.

Native storage review must still verify `ControlledSigner::prepare`, `SigningSession::begin`, `RuntimeStore::reserve_nonce`, `authorize_commitment` and `record_abort` under fault injection and process restart. Never interpret a committed-but-unacknowledged write as safe to retry. Do not reuse FROST nonces, partially completed DKG secret state or an aborted operation ID.

E5 must establish actual caller provenance, assigned-capability revocation, non-member and forged-sender denial, private inbox isolation, conflict/quota semantics, concurrent delivery, plaintext Round-3 rejection and unavailable-peer failure. A fail-closed **expected** live Round-2 policy block is not a successful distributed ceremony. Real SDK status-read acceptance separately requires the read-only signer, actual Holochain AppWebsocket and pinned app/role/DNA/agent/proposal/spec; `ReadyToStart` is not activation.

## Release inventory and required decisions

Read-only inspection confirms `Cargo.toml` already lists `crates/holochain-dkg-sdk` in the workspace, `holochain-dkg-sdk 0.1.0` appears in `Cargo.lock`, and `frost-core =3.0.0` is a direct FROST provider dependency. The worker requires `holochain_zome_types =0.7.1` for default inbox types, without activating privileged features. The **approved** `scripts/release_inventory.json` omits the SDK member/package and carries older root/manifest and lock SHA-256 values; it is intentionally not rewritten. The full proposed semantic delta is in `SPRINT18_RELEASE_INVENTORY_PROPOSAL.md`. No actual inventory generator output/hash comparison has been executed locally; that gate is **BLOCKED — OPERATOR APPROVAL REQUIRED**. `scripts/release_hashes.json` is unchanged by Sprint 1.8B.

Additional open decisions: signing sequence collisions, finite group lifetime/rekey, exact cross-app v2 isolation, operator custody and anti-rollback witness, and live conductor/release policy. An ignored group-expiry test remains known-red until a separate fix and execution.

## Reviewer acceptance and next milestone

Review the exact PR #19 diff against `edd7a775...`, run complete E2/E3/E7 with captured command, toolchain, job URL, exit code and counts, and independently inspect source and error-handling semantics. Obtain E4 artifact identities and E5 conductor evidence separately from E6. Perform live read-only SDK acceptance with a disposable authorised signer. Require two specialised reviewers (FROST cryptography and Holochain/conductor identity/capabilities) and human operator signoff for INV-13 and inventory; do not self-award E8.

**Next milestone:** one exact compiled, natively tested and documented Sprint 1.8B SHA with live E5 coordinator negatives, while INV-13 remains safely blocked. Until proven, overall status remains **CHANGES REQUIRED**.

## Sprint 1.8B recovery continuation (2026-11-19)

Continuation branch `claude/holochain-threshold-crypto-sprint18b-gocnij` (from `33db049`, PR #18/#19 history untouched). Code head `2eb1efc` and code-identical `8098a20` were verified in pinned-Nix [run 44595170065](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/44595170065): native 15/15 gates PASS, conductor 9/9 gates PASS, including the live INV-13 negative over three real conductors. INV-13 remains fail-closed; E6 BLOCKED; E8 NOT RUN; release inventory BLOCKED. See `SPRINT18B_RECOVERY_REPORT.md` and `SPRINT18B_INV13_IMPLEMENTATION_DESIGN.md`.
