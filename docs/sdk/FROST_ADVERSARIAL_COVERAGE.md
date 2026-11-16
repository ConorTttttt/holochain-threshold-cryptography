# FROST Adversarial Coverage — Sprint 1.7 / Agent 22

**Status:** Test sources authored; execution must be judged from the exact-head CI result. This document alone is **not** evidence that tests pass.

**Starting integration baseline:** `899e433d057a4d1a0533e2304a2493edb75ad82f` (`sprint1/agent6-stage2c-integration-20261116`).

**Working branch:** `agents/sprint17-agent22-frost-adversarial-20261116`; isolated from `main` and all deployed Holochain cells. No new validated integrated Sprint 1.6 head was established before branching. The separate PR #6/#8/#9/#10 draft heads are not the integrated baseline (see `SPRINT15_SECURITY_REVIEW.md` on `review/sprint15-independent-security-20261116` at `25afdd6bfc979259cec9416ae5d104780ef384f6`).

**Historical reference:** Fable `02_PROTOCOL_ANALYSIS.md`, `03_SECURITY_REVIEW.md`, `05_TESTING_AND_VERIFICATION.md`, `10_OPEN_QUESTIONS.md`, and `09_RESEARCH_REFERENCES.md` were written against `8dec223`. They are a regression checklist, *not* a description of the current integrated code.

## Safety scope

Only tests, non-mandatory fuzz tooling, corpus and documentation are added. No FROST primitive is reimplemented; no modification to protocol logic, wire formats, integrity schemas, DNA identities, production secrets, release hashes, deployment configurations, persistent Lair credentials or existing cells. All identities in these tests are synthetic, all signing messages are nonvaluable fixtures.

### Current enforcement vs new coverage

| Historical scenario / required property | Current enforcement inspected at baseline | New regression / verdict condition | Evidence boundary |
| --- | --- | --- | --- |
| A6/A7: malicious Round-1 origin equivocates to two honest recipients | `EchoBroadcast::receive_envelope`, `record_digest`, `receive_announcement`, unanimous `finalize` | `bounded_three_party_round_one_agreement_and_equivocation`: 64 seeded cases, full Announce/EchoDigest/Attest transport envelopes. Honest baseline yields identical full packages; equivocation cannot mint either honest token | E1 until executed; native E3/E7 on passing CI, **not** E5 |
| A8: contradictory authenticated attestation | `EchoBroadcast::receive` records unique sender hashes or aborts | `conflicting_attestations_from_one_authenticated_origin_abort`: send contradictory round-2 envelopes under same authenticated member | E1 pending run |
| A12: duplicate vs conflicting announcement | Identical direct Announce idempotent; mismatch aborts. Coordinator slot policy is a separate layer | `duplicate_announcements_are_idempotent_but_conflicts_fail_closed`: duplicate same slot accepted once; conflicting authenticated payload in same slot makes gate terminal | E1 pending run |
| INV-1: forged transport identity | `Envelope::validate_received` checks proven sender; `Binding::id_of` maps authenticated roster identity | `forged_provenance_and_cross_proposal_attestation_are_rejected`, `frame_rejects_proposal_session_and_transport_mismatch_after_rehashing`; misattributed valid signature share fails full aggregation | Native synthetic provenance only; conductor provenance **NOT RUN** |
| A13/A14/A15: proposal/session/operation replay | `Frame::decode` checks proposal, session-vs-signing type, round and authenticated sender; aggregate binds message+operation | Rehash tampered frame to bypass mere envelope checksum; `forged_share_attribution_cross_operation_replay_and_peer_commitments_fail` asserts different-operation aggregation fails | **Important:** `Frame::decode` does not receive an *expected signing operation ID*. A dispatcher must still compare `decoded.operation_id` with its current operation. No generic frame-dispatch proof is claimed |
| A5: share attributed to a wrong signer; invalid shares | `AuthenticatedShareCollector::ingest` derives ID solely from authenticated sender, validates roster/package digest; FROST verifies shares at aggregate | Deliver genuine shares under swapped authenticated identities; reject out-of-roster and unknown callers; no artifact returned | Share checking is deferred to aggregate, not done inside `ingest` |
| A23: tampered peer signing commitment | FROST binding factors cover complete signing commitment set and message | Change a peer's commitment after genuine shares were made; aggregation fails; unchanged package yields valid artifact | No guarantee of liveness against an active malicious signer |
| A9: tampered Round-2 peer share | `DkgParty::part3_with_evidence` calls FROST share verification after verifying exact gate | Replace C-labelled private share with B's authentic share; cannot produce a DKG public proposal/activation | Test stops before activation because no key is produced |
| A18/A19: malformed JSON, deep nesting, corrupted binary, oversized envelopes | `Envelope::validate_against` caps payload; decoder parses JSON; `NativeChannelKey::open` checks authenticated ciphertext/header | 4 fixed seeds × 128 cases each in both provider and security suites, bounded lengths (up to 2,048 byte provider and 1,024 byte security), `catch_unwind` denies panics; optional `cargo-fuzz` harness up to core `MAX_PAYLOAD_BYTES` | No heap profiling, allocation upper-bound proof or DoS benchmark; E7 only after execution |
| INV-11: public outputs must not contain secret shares/nonces | `SignedArtifact` contains proposal, session, operation, public key, signature only | Strict JSON public-field allowlist on a real valid signature artifact. No secret logged by these tests | **Limited assertion**: does not audit all public DHT types or heap memory |

Existing positive DKG, approval and nonce durability tests are retained unchanged. Tests must not bypass unanimous transcript gate or activation. The two-party `threshold` concerns signing only; DKG still requires all three.

### Explicitly outstanding / architectural decisions

1. **Duplicate sealed Round-2 packages (Fable A11/INV-12):** `open_dkg_round_two` is a stateless parser and does not itself enforce one package per sender/recipient/ceremony. `ChannelReplay` exists, but deterministic replay admission belongs to the controlling transport and transactional store. This suite does not claim that the duplicate-Round-2 lifecycle is fixed; a controller-level rejection test remains required.
2. **Per-operation frame demultiplexing:** `Frame::decode` will successfully parse a genuine signature-share frame for operation A while handling operation B unless a separate operation equality test is made. This test explicitly checks the mismatch and verifies aggregation rejects the replay; it does not certify all consumers.
3. **Real sender authentication:** `authenticated_sender` is supplied by synthetic tests. Holochain `call_info()?.provenance`, capability checks and conductor spoofing require E5/E6 tests.
4. **Resource-exhaustion exposure:** the core payload cap is 64 KiB. JSON expands byte arrays and deserializes within this outer limit; the sealed inner payload cap is 3 KiB and checks are after authenticated decryption. A member can still flood a recipient's bounded lifetime inbox (historically 16,384 events/proposal; Sprint 1.5 found a 2,048 sender lifetime quota with 3 members), with full-chain scanning/availability effects. No allocation profiling, hostile conductor benchmark or throughput guarantee in this change.
5. **Public secret confidentiality:** the `SignedArtifact` allowlist verifies output shape only. A full audit of coordinator writes, debugging, IPC and all failure logs remains separate.
6. **Finiteness:** 64 deterministic ceremony cases and 512 decoder cases per test suite do not establish a mathematical security proof. Fresh FROST DKG keys still come from `OsRng`; only attacker-controlled payload sequences are deterministic. Never save private key packages as fuzz fixtures.

### Reproducible seeds and corpus

Both seeded suites use xorshift64* with multiplier `0x2545f4914f6cdd1d` and explicit initial seeds:

```text
0x0000000000000001
0x3141592653589793
0x9e3779b97f4a7c15
0xfffffffffffffffe
```

Cases are indexed `0..16` for three-party broadcasts and `0..128` for each decoder suite. On assertion failures, `seed=0x...` and `case=...` appear in the assertion output. Hand-authored payload seeds are under `fuzz/corpus/frame_envelopes/`; the standalone fuzz crate is outside the root workspace. Do **not** add the fuzz crate to the ordinary CI matrix.

## Exact validation commands and evidence accounting

Execution must record `git rev-parse HEAD`, `rustc --version`, `cargo --version`, command exit status, test counts and redacted log excerpt. The optional Rust fuzz harness is **not** an ordinary acceptance requirement.

```sh
git rev-parse HEAD
cargo test --offline --locked -p holochain-mpc-security --test adversarial_properties -- --nocapture
cargo test --offline --locked -p holochain-mpc-frost-ed25519 --test three_agents -- --nocapture
cargo test --offline --locked -p holochain-mpc-frost-ed25519 --lib

# Opt-in only; requires cargo-fuzz and a separate dependency fetch.
cd fuzz
cargo +nightly fuzz run frame_envelopes -- -max_len=65536 -runs=10000
```

A branch-scoped GitHub Actions workflow `.github/workflows/frost-adversarial.yml` runs the native commands in pinned Nix, after `cargo fetch --locked`, and reports the exact commit. **Never assign a PASS solely from these test definitions.** The root workspace's previously documented `holochain_zome_types` optional-import failure on the original integrated head is not fixed here because it is owned by the integration/CI recovery task.

| Fable level | Scope in this work | Initial status, until the exact-head run reports results |
| --- | --- | --- |
| E1 | Test, corpus, workflow and documentation sources present | PRESENT on isolated branch |
| E2 | Targeted test compilation | NOT RUN / awaiting exact-head native CI |
| E3 | Real FROST native tests | NOT RUN / awaiting exact-head native CI |
| E4 | WASM/hApp packaging | NOT RUN — outside this test-only change |
| E5 | Real Holochain conductors | NOT RUN — requires disposable conductor environment |
| E6 | Native cryptography across conductors | NOT RUN |
| E7 | Adversarial injection executing successfully | NOT RUN / awaiting exact-head native CI |
| E8 | Independent reviewer | NOT RUN |

For any failed command, preserve failure output and leave the test red. An unrelated compilation blocker is **not** proof of a negative case, and a passing E3 test cannot substitute for E5/E6. No production custody, release or mathematical proof is implied.
