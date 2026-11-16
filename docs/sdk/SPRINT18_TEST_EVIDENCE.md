# Sprint 1.8 — Verification ledger (E1–E8)

**Status: CHANGES REQUIRED / EXECUTION PENDING.** This ledger deliberately distinguishes results observed on historical SHAs from the current integration source. Run each command on **one exact immutable Sprint 1.8 commit** and attach GitHub job URL, toolchain, exit status, stdout and stderr before promoting evidence.

| Level | Required proof | Current Sprint 1.8 evidence |
| --- | --- | --- |
| E1 | Source exists | YES — branch contains integrated PRs #10–#17 and targeted source mitigations; SHA controlled by GitHub |
| E2 | All supported features compile | NOT YET VERIFIED on final head; check action workflow |
| E3 | Executed native tests pass | NOT YET VERIFIED on final head; presence of test files is E1 only |
| E4 | WASM and hApp build | NOT RUN on final head |
| E5 | Disposable real conductor Sweettests run | NOT RUN on final head |
| E6 | Native FROST cryptography across real conductors | NOT RUN; deliberately blocked at Round 2 by INV-13 |
| E7 | Adversarial and SQLite fault-injection tests execute | NOT YET VERIFIED on final head |
| E8 | Independent crypto/Holochain review | NOT PERFORMED on integration head; PR #11's independent historical reassessment is not an audit of Sprint 1.8 |

## Prior exact evidence (not transferable)
- `899e433d057a4d1a0533e2304a2493edb75ad82f`: GitHub Actions [43835405873](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43835405873), job 133190781392: `cargo check --offline --locked --workspace --all-targets` **FAIL** with E0433 unresolved `holochain_zome_types`. Inventory job 133190782023: `python3 -I scripts/check_release.py` **FAIL**, SDK missing from approved inventory. Sweettests/release jobs **SKIPPED**.
- `a8e8dca0889064654190c4f866e7d54e2869c716`: Actions [43918839519](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43918839519): 5 seeded protocol tests **PASS**, 8 FROST tests **PASS**, attribution test `forged_share_attribution_cross_operation_replay_and_peer_commitments_fail` **FAIL**, making test job **FAIL**. This is PR #14's separate head, not Sprint 1.8.
- `8dec22361b484f79c309c10f7dbbbe26e4ab47d5`: historical Fable 37/37 native tests at E3 only; no live conductor proof.

## Mandatory exact-head commands
Run under pinned Nix tooling, against an immutable Git commit:
```bash
git rev-parse HEAD
rustc --version; cargo --version
cargo check --locked --workspace --all-targets
cargo check --locked -p holochain-mpc-dkg-worker
cargo check --locked -p holochain-mpc-dkg-worker --features conductor-client --all-targets
cargo check --locked -p holochain-mpc-dkg-worker --features lair-signer --all-targets
cargo test --locked -p holochain-mpc-core
cargo test --locked -p holochain-mpc-security
cargo test --locked -p holochain-mpc-runtime
cargo test --locked -p holochain-mpc-frost-ed25519
cargo test --locked -p holochain-mpc-dkg-worker
cargo test --locked -p holochain-dkg-sdk --all-targets
cargo test --locked -p holochain-dkg-sdk --features native-holochain --all-targets
cargo test --locked -p holochain-mpc-security --test adversarial_properties -- --nocapture
cargo test --locked -p holochain-mpc-frost-ed25519 --test three_agents -- --nocapture
cargo test --locked -p holochain-mpc-dkg-worker --test round_two_security -- --nocapture
cargo test --locked -p holochain-mpc-dkg-worker --test signing_session -- --nocapture
```
Native evidence alone cannot prove conductor or security policy. Build `npm run build:happ` in the pinned Nix environment, then execute `npm run test:sweettest` plus `cargo test --locked -p mpc --test fable_conductor_adversarial -- --nocapture --test-threads=1`, retained coordinator security tests, live SDK status-read fixture and real disposable-conductor negative tests. Record **NOT RUN** for any unavailable conductor test. The current fail-closed Round-2 gate intentionally blocks old positive live DKG tests until architectural approval.

## Release validation
Read-only `python3 -I scripts/check_release.py` is expected to reject the unapproved SDK inventory; do not run any record-inventory option or replace release hashes. Release gate **BLOCKED / approval required**. A failing approved-inventory check is not permission to bypass it.

## CI provenance
On source-fix checkpoint `f859ac6d775fe8203bc24c35e90979d687477f24`, actions runs 43933685885 (FROST) and 43933685971 (SDK CI) were started; at report drafting their results had not been captured. On S15-L01 checkpoint `710159af134f4bf727ddaba3c524a036645c6953`, runs 43934260071 and 43934260067 were started and results remained pending. **Do not translate a running workflow into PASS.** Update this ledger from the actual final-head job logs and exit codes.
