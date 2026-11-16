# DKG Round-2 Security Validation — Sprint 1.7 / Agent 19

**Date:** 2026-11-16 UTC
**Status:** **CHANGES REQUIRED. Regression tests authored but NOT RUN; INV-13 integration OPEN.**
**Repository:** ConorTttttt/holochain-threshold-cryptography
**Isolated branch:** `agents/sprint17-agent19-round2-security-20261116`
**Immutable base:** `899e433d057a4d1a0533e2304a2493edb75ad82f` on `sprint1/agent6-stage2c-integration-20261116`.
**New test source commits:** `fbbb3ee17a1df03c6efe9bf1c98373142cfb7d3c` (worker integration tests) and `379dc5fe0d775d733de1d7a9822213ec32c64de6` (relay tests).
**Baseline change:** NONE. No newer green, validated, combined Sprint 1.6 integration head was found; PRs #6 and #8–#11 are separate drafts and no validated successor. Never merge into main or deploy.

## Exact evidence and source separation

Read Fable `02_PROTOCOL_ANALYSIS.md`, `03_SECURITY_REVIEW.md`, `05_TESTING_AND_VERIFICATION.md`, `10_OPEN_QUESTIONS.md` and `09_RESEARCH_REFERENCES.md` (historical commit `8dec22361b484f79c309c10f7dbbbe26e4ab47d5`). At the exact combined base, inspected `docs/sdk/API_CONTRACT.md`, `docs/THREAT_MODEL.md`, `docs/sdk/SPRINT1_INTEGRATION_REPORT.md`, `crates/mpc-dkg-worker/src/lib.rs`, `relay.rs`, `conductor_bridge.rs`, `key_pinning.rs`, `transport_channel.rs`, `inbox_slots.rs` and `crates/mpc-frost-ed25519/src/lib.rs`.

The three required `docs/sdk/SPRINT15_SECURITY_REVIEW.md`, `SPRINT15_FINDINGS_REGISTER.md` and `SPRINT15_TEST_EVIDENCE.md` are **not present on the integration head**. Read them from **separate** branch `review/sprint15-independent-security-20261116`, which explicitly assessed the exact integrated SHA. Those docs are external review evidence, not integrated source.

**Do not promote historical Fable F-9/A11 ("no native duplicate-share control") to a current confirmed bug.** Current code contains the checks described below.

## Current-source trace (E1, not a verified runtime fix)

1. `Controller::handle` (`lib.rs:152-161`) poisons the instance and drops active in-memory DKG secrets on any `process` error. No further `Finalize`, `Init` or DKG activity succeeds on that controller.
2. `Controller::process(Command::Deliver)` (`lib.rs:184-228`) validates the asserted transport-authenticated sender, peer membership and sender/envelope consistency, then blocks exact (sender,round,sequence) replay. For encrypted Round 3, it opens with the pinned public sender key and obtains the FROST ID from the authenticated sender, **not** from a payload-claimed identity. It inserts into `incoming_shares` by sender ID. A second share with a different sequence produces `duplicate share`; `handle` then destroys the active state. No completed group descriptor can be obtained after this failure. The second insertion briefly replaces the first in memory before the error, but the entire active state is dropped immediately: it is not used for FROST part3.
3. `DkgRelay::poll_once` (`relay.rs:247-373`) first rejects relevant structured inbox conflicts/over-quota evidence. It tracks exact message slots in `seen` and Round-2 senders in `sharers`. Distinct-sequence duplicates are **not** exact-slot conflicts, so the separate sender uniqueness check is required. `LocalDkgNode::deliver` runs before the `sharers` insertion; the real Controller rejects the second share itself, while the relay's sender check also rejects a second packet from a permissive test node. Relay poison aborts the node.
4. `open_dkg_round_two` (`crates/mpc-frost-ed25519/src/lib.rs:226-245`) validates recipient, authenticated sender, ceremony-bound ciphertext/header and the FROST frame's proposal/session. This function is intentionally stateless: duplicate detection belongs at the native controller and relay, not in the decryption primitive.
5. `Controller::BeginRoundTwo` (`lib.rs:235-278`) requires a full distinct member key set and checks its own worker-generated key. However the worker trusts the host to have independently authenticated source-chain action/author and key approvals.
6. `key_pinning::verify_explicit_key_roster` (`key_pinning.rs:21-94`) compares exact independently approved vs observed (author, action, public key) tuples, rejects duplicates/forks/extra/rotated registrations and requires the local approved public key to be derived from the retained local secret.
7. **INV-13 actual integration GAP:** `RelayEngine::poll_once` → `LocalDkgNode::round_two` → `ConductorBridge::round_two` invokes `pins_from_conductor(records,my_key)` with **only current observed records**. It does not require the independently approved roster and does not call `verify_explicit_key_roster`. A newly observed, internally well-formed but *unapproved* member key/action could be used for Round 2 even though the independent approval verifier would reject it. The strict offline function is not an enforced production relay prerequisite. This is **OPEN at source level**, not a reproduced successful attack against a conductor.
8. **Post-completion boundary:** `RelayEngine` stops polling on `Phase::Complete`. A duplicate that becomes visible only afterwards will not be observed by that relay. If explicitly delivered to a completed Controller, the wrong-phase error would poison it, but the relay does not keep delivering. No global-finality or post-completion equivocation-detection claim is made; Holochain has no global ordering. Unanimous independently authenticated group activation remains mandatory before signing.

## New tests and cryptographic fixture

New file: `crates/mpc-dkg-worker/tests/round_two_security.rs`. The positive setup runs a **real recipient Controller** and two external real `DkgParty` instances through authenticated Round-1 envelopes, 12 digest echoes, 6 attestations, identical verified transcript hashes and genuine FROST part2 packages for that very same transcript. The attacker holds only its own disposable ephemeral X25519 key and seals the same valid recipient-specific FROST share **twice independently**, with fresh ciphertext and distinct sequences. Both ciphertexts are protocol-valid rather than malformed JSON. Recipient worker owns its own key privately.

| Test | Expected property | Run status |
| --- | --- | --- |
| `valid_unique_round_two_packages_complete_native_dkg` | Positive real-FROST part3 succeeds with exactly one authenticated B and C share | NOT RUN |
| `duplicate_round_two_different_sequence_aborts` | Seq 1 then seq 2: first decrypts; second reaches duplicate-share check; no restart | NOT RUN |
| `duplicate_round_two_reverse_order_aborts` | Seq 2 then seq 1 has same terminal result | NOT RUN |
| `duplicate_round_two_across_deliveries_aborts` | Separate Controller deliveries; **not** claimed to be actual inbox polls | NOT RUN |
| `round_two_wrong_sender_rejected` | Valid sealed B package rejected when claimed authenticated caller is C | NOT RUN |
| `round_two_wrong_recipient_rejected` | Genuine encrypted B→C packet cannot be delivered to A | NOT RUN |
| `round_two_cross_proposal_rejected` | Valid ciphertext from same-session, other-proposal ceremony rejected | NOT RUN |
| `round_two_duplicate_cannot_activate_group` | With valid B and C shares available but before Finalize, malicious second B packet poisons Controller; no Completed descriptor | NOT RUN |
| `forked_encryption_key_registration_rejected` | Extra or duplicate registration fails independent exact approval check | NOT RUN |
| `unapproved_key_rotation_rejected` | Rotated action/key, or new action reusing old key, is not approved | NOT RUN |
| `local_approved_registration_must_match_secret` | Approved local key must equal native secret-derived public key | NOT RUN |

Three additional unit tests in `crates/mpc-dkg-worker/src/relay.rs` (`round_two_uniqueness_tests`) use a **real FROST part2** share from an independently unanimous three-party in-memory transcript, sealed twice with different sequences. The test peer decrypts both authenticated packets and *deliberately does not enforce uniqueness* so the relay's independent `sharers` guard is what must reject the second. The relay is directly placed in `Shares`: a targeted unit test, not evidence of a fully initialized conductor or relay network.

| Test | Expected property | Run status |
| --- | --- | --- |
| `duplicate_round_two_in_one_poll_aborts` | Two decryptable B packets with different sequences in one inbox snapshot; terminal abort | NOT RUN |
| `duplicate_round_two_across_polls_aborts` | B's second different-sequence package appears in next cumulative poll; terminal abort | NOT RUN |
| `duplicate_round_two_reverse_order_across_polls_aborts` | Reverse ordering across polls; same terminal abort | NOT RUN |

## Exact command / commit / exit / log ledger

The following tests were **NOT EXECUTED**. No command exit code or passing output exists. New tests first exist at commits `fbbb3ee17a1df03c6efe9bf1c98373142cfb7d3c` and `379dc5fe0d775d733de1d7a9822213ec32c64de6`; report-only changes leave them unchanged. Run these on an immutable green integration commit and archive outputs:

| Command | Disposition | Evidence |
| --- | --- | --- |
| `cargo test --locked -p holochain-mpc-dkg-worker --test round_two_security -- --nocapture` | NOT RUN; no exit status | Rust/Cargo unavailable |
| `cargo test --locked -p holochain-mpc-dkg-worker --lib round_two_uniqueness_tests -- --nocapture` | NOT RUN; no exit status | Rust/Cargo unavailable |
| `cargo test --locked -p holochain-mpc-dkg-worker --test relay_simulation -- --nocapture` | NOT RUN; no exit status | Required existing regression suite not rerun |
| `cargo test --locked -p holochain-mpc-dkg-worker --all-targets` | NOT RUN; no exit status | Integrated build is not green |
| `cargo check --locked --workspace --all-targets` | NOT RUN on this new test head; no exit status | Prior exact integrated base failed in CI |
| `npm run build:happ` | NOT RUN; no exit status | WASM/Holochain tooling unavailable |
| `npm run test:sweettest` | NOT RUN; no exit status | No conductor execution |

**Observed CI on the original exact integrated base**, not new test execution: GitHub Actions run **43835405873** (head `899e433d057a4d1a0533e2304a2493edb75ad82f`), native job **133190781392**, workspace cargo check **exit 101** at 2026-11-16 09:35:23 UTC. Log contains `error[E0433]: cannot find module or crate holochain_zome_types` at `crates/mpc-dkg-worker/src/inbox_slots.rs:5:5`; worker manifest marked that dependency optional while import was unconditional. Thus **no integrated Rust green gate**. Inventory job **133190782023** exited **1**, refusing the unapproved SDK package/Cargo.lock inventory difference. Sweettest and release jobs were skipped. Do not rewrite approved release hashes to suppress a correct failure.

**Local environment, 2026-11-16 UTC:** `cargo --version` and `rustc --version` produced `command not found` (shell exit 127). `command -v nix`, `command -v hc` and `command -v rustfmt` found no executables (exit 1). `curl -I -L --max-time 8 https://github.com` could not resolve github.com (curl exit 6). GitHub connector source reads and isolated-branch writes succeeded; GitHub API success is not a compiler, test, or conductor result.

## Fable E1–E8 status

| Level | Status | Claim |
| --- | --- | --- |
| E1 source exists | **YES** | Current guards, new test module and relay unit tests present at the recorded commits |
| E2 compiles | **NOT VERIFIED / NOT RUN for this branch** | Earlier combined base has an observed CI compile FAIL 101 |
| E3 executed native test | **NOT RUN** | No new cryptographic regression has executed |
| E4 WASM and hApp | **NOT RUN** | No artifact build |
| E5 real conductors | **NOT RUN** | No Sweettest |
| E6 native crypto across conductors | **NOT RUN** | No distributed FROST |
| E7 adversarial evidence | **AUTHORED ONLY; NOT EXECUTED** | No executed adversarial or fault-injection evidence |
| E8 independent review | **NOT ATTESTED** | Source assessment is not a third-party audit/sign-off |

## Disposition and blocking decisions

- **Fable A11/F-9 / INV-12:** **SOURCE MITIGATION ONLY, NOT VERIFIED FIXED.** Native controller and relay have per-sender uniqueness checks even across distinct sequences. Exact-sequence slot deduplication is not confused with per-sender uniqueness. Do not reinstate the obsolete historical "no control" statement as a current finding; execute the added real-package tests before closing the issue.
- **INV-13:** **OPEN.** Independent explicit approval exists as a helper but is **not required by the live Round-2 path**. Require a separately obtained, durable, authenticated operator-approved (author, action, public key) roster for this exact DNA/cell/agent/proposal/session. At the start of Round 2, compare it to all conductor-observed registrations and the actual worker-generated local key, fail closed on absence, fork, extra/rotated records or mismatch. Merely copying `get_encryption_keys` into an `approved` vector is NOT an approval. Coordinate with DKG lifecycle/relay owner to choose the host configuration/admission boundary; no speculative IPC or DNA migration here.
- **Late arrival after local Complete:** **OPEN architectural observation boundary**. Local completion is not global activation; no post-completion observation/finality guarantee is currently justified. A separate reviewed readiness/monitoring decision is required before claiming later duplication can never coexist with activation.
- **No implementation change:** A11's original duplicate-share weakness already has source guards; a new crypto or controller rewrite would be unnecessary without an executed reproducer. INV-13 needs a real independent-approval authority and owner-reviewed integration contract; do not invent this from untrusted observations.

**Revalidation gate:** After a green immutable integrated build, run the commands above with actual toolchain/commit/exit/log evidence, then run disposable-conductor E5/E6/E7 negatives for sender, recipient, cross-proposal, duplicate/forked/rotated and unapproved registrations, plus incomplete malicious exchange with no unanimous activation. Obtain an independent E8 review before asserting verified fixes or promoting any release.
