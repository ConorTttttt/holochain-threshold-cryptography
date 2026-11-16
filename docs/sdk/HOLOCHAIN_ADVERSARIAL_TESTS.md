# Sprint 1.7 / Agent 21 — Holochain conductor adversarial tests

**Status (2026-11-16 UTC): E1 SOURCE / EXECUTION NOT RUN. NOT a verified security fix or conductor acceptance.**
All fixtures use throwaway Sweettest app installations and nonvaluable messages.
No deployed Holochain cell, persistent Lair identity, integrity schema, wire
version, DNA release identity or approved hash was modified.

## 1. Exact baseline and source reconciliation

- Requested starting ref: `sprint1/agent6-stage2c-integration-20261116`.
- **Immutable baseline kept:** `899e433d057a4d1a0533e2304a2493edb75ad82f`.
  GitHub's branch listing showed this exact head when inspected.
- An alternative *newer validated Sprint 1.6 integration candidate* was
  **not identified**. PR #6 at `2f3b4c3d708db6d48954d1341fdaa1ba246a9ef1`
  is a separate CI-repair draft, not a validated combined integration.
  PR #8/#9/#10 likewise remain separate candidates. No source baseline was
  silently changed.
- Isolated test branch: `sprint17/agent21-holochain-adversarial-20261116`.
  Test source commit: `e71e050069239bbee6f3447fcf02de459537b9e9`
  (the previous source commit is `e69e70cc91af713656827454ed3ca5e4c547aa20`).
  These hashes identify **source changes**, not passing test executions.
- Five Fable sources read: `02_PROTOCOL_ANALYSIS.md`,
  `03_SECURITY_REVIEW.md`, `05_TESTING_AND_VERIFICATION.md`,
  `10_OPEN_QUESTIONS.md`, `09_RESEARCH_REFERENCES.md`.
  Their implementation observations apply to **historical** `8dec223`
  only. The specified `docs/sdk/API_CONTRACT.md` and `docs/THREAT_MODEL.md`
  exist at the combined baseline.
- `docs/sdk/SPRINT15_SECURITY_REVIEW.md`,
  `docs/sdk/SPRINT15_FINDINGS_REGISTER.md` and
  `docs/sdk/SPRINT15_TEST_EVIDENCE.md` are **absent from baseline**
  `899e433d...`; they were read at **separate independent review commit**
  `25afdd6bfc979259cec9416ae5d104780ef384f6`.
  This does **not** incorporate that review branch into the implementation.
  It records actual Sprint 1 CI failures and explicitly denies verification
  or deployment approval.

## 2. Present coordinator contract inspected at the baseline

`dnas/mpc/zomes/coordinator/mpc/src/lib.rs`:

- `receive_protocol_message` takes `call_info()?.provenance` and requires
  `Envelope.sender` to equal the authenticated caller. It validates recipient,
  session and payload commitment before writing a **private** `InboxEvent`.
  `send_protocol_message` constructs the envelope using the **local** agent
  and uses a real `call_remote`; it cannot be used to issue arbitrary
  forged sender envelopes.
- `prepare_inbox_grant` installs a function-scoped **Assigned** grant for
  exactly the other listed participants. `revoke_inbox_grant` exists. The
  integrity zome now explicitly allows an original grant author's
  `CapGrant` deletion through both `OpRecord::DeleteEntry` and
  `FlatOp::Delete`; other app-entry and link deletes remain rejected.
  Fable's historical F-7 revocation prediction is therefore **not** a
  current source-level finding; its real-conductor behaviour still requires
  execution.
- Inbox events use `ChainTopOrdering::Relaxed`. A read-before-write check
  rejects already visible conflicting slots, but two racing writes may
  **both commit**. This is not a test failure by itself. The authoritative
  read contract is
  `get_inbox_slots -> InboxSlots { envelopes, conflicts, over_quota }`.
  All conflicting variants, including their storage action hashes, are
  withheld from normal consumption. Other senders' unconflicted slots stay
  visible. The legacy `get_inbox` returns just the served envelopes.
- Read-time quota is isolated by authenticated sender. At 3 participants
  it is `4096 / (3 - 1) = 2048` stored records **per sender, recipient and
  proposal**, not a sliding window. Overshoot caused by concurrent commits
  is reported as `over_quota` rather than served. Quota exhaustion remains
  an architectural liveness limit, **not** an unbounded group guarantee.
- For `protocol_id = "frost-ed25519"`, v1, round 3, a payload must deserialize
  as structurally valid `SealedPacket` on **both** send and receive paths.
  That WASM check is structural, not a proof of MAC authenticity or FROST
  share correctness. Decryption remains a native responsibility.
- Acceptance is locally observed by DHT queries: every listed participant
  must have accepted before delivering. Missing gossip is not global finality.
  A remote failure with an unknown outcome must **not** trigger a silent
  retry; a relaxed-ordering `storage_action` receipt is not independently
  authoritative without a source-chain lookup.

The integrity zome's private `InboxEvent` validation does not authenticate
its contents against a compromised local coordinator. Its security claim
depends on an honest local conductor and coordinator as part of the trusted
computing base; the test below does not change that assumption.

## 3. Existing Sweettest inventory — do not duplicate

Source read at `899e433d...`:

| Existing file | Existing cases and evidence target |
| --- | --- |
| `tests/mpc_network.rs` | Three real conductors, consent, assigned-grant remote send, dedup, opaque out-of-order delivery, member-private inbox read. No FROST round-3 negative. |
| `tests/inbox_hardening.rs` | `membership_and_context_binding_survive_hardening` already tests nonmember with a leaked secret, forged claimed sender, wrong recipient, malformed fields and proposal binding **using `call_from_fallible` on one conductor**. |
| `tests/inbox_hardening.rs` | `r11_conflicting_pair_leaves_unrelated_slots_readable` races one authenticated sender, requires both committed variants, verifies both `storage_actions`, preserves Carol's unrelated messages; `r11_one_sender_cannot_exhaust_another_senders_allocation` and `r11_concurrent_deliveries_cannot_overrun_the_served_quota` assert per-sender quotas and `over_quota`. |
| `tests/inbox_hardening.rs` | `r10_network_fan_in_is_stored` runs concurrent distinct-sender `call_remote` calls across three conductors; `send_protocol_message_keeps_the_remote_failure_kind` checks wrong capability and conflicting remote delivery. |
| `tests/revoke_cap_grant.rs` | `grantor_can_revoke_own_assigned_inbox_grant`: creates then deletes a grant under conductors, **does not** try another remote delivery after deletion. |
| Native worker tests | `relay_simulation.rs` and `signing_session.rs` contain conflict-aware polling examples; those are not E5 or E6 merely because the files exist. |

Earlier Stage 2C documents report test passes; there is **no independent
executed pass on this Sprint 1 integrated head**. Specifically Sprint 1.5
review reports GitHub Actions run `43835405873`: native `cargo check`
**FAIL exit 101** on `E0433` unresolved `holochain_zome_types` in
`crates/mpc-dkg-worker/src/inbox_slots.rs:5`; approved inventory check
**FAIL exit 1** (unapproved SDK package/lockfile). These are historical
external execution failures **on the exact baseline**, not failures newly
reproduced by Agent 21 and not permission to alter release inventories.

## 4. Added Sweettests

New file:
`dnas/mpc/zomes/coordinator/mpc/tests/fable_conductor_adversarial.rs`,
initially authored on `e69e70cc91af713656827454ed3ca5e4c547aa20`,
refined on `e71e050069239bbee6f3447fcf02de459537b9e9`.

| Test | Fixture | Assertion / limit |
| --- | --- | --- |
| `revoked_grant_cannot_deliver` | **Four distinct disposable conductors**, members A/B/C, nonmember D | A→B remote succeeds under Bob's Assigned grant; Bob revokes; A→B with old secret refuses; no second inbox record; freshly granted secret works. Does not claim in-flight writes retroactively fail. |
| `unaccepted_peer_blocks_delivery_until_convergence` | Four distinct conductors | Only A/B accepted: no A→B delivery; after C accepts and `await_consistency`, remote delivery succeeds. This is **deterministic missing acceptance**, not a randomized convergence race. |
| `private_inbox_isolation_preserved` | Four distinct conductors | Nonmember D with leaked grant is stopped by sender's local membership preflight; valid A→B `call_remote` stores one event on B; C's local slots are empty; D's local inbox read refuses. The D path here does **not** prove the *remote* recipient grant check. |
| `local_injection_rejected` | One disposable conductor, three separate cells | Bob's local `receive_protocol_message` call claims Alice as sender; authentic local provenance must reject it and leave no inbox entry. |
| `frost_round3_requires_sealed_packet` | Four distinct conductors for send-side negative; separate one-conductor `call_from_fallible` receiver fixture | Plaintext round-3 payload refused on real sender and directly at Bob's recipient extern with valid Assigned grant and Alice provenance; nothing stored. Does not prove native AEAD decryption. |

The nonce ledger, activation unanimity, signer-approval rules, protocol wire
format and `InboxEvent` integrity schema are untouched.

### Coverage mapping to requested scenario names

| Requested case | Coverage and remaining gap |
| --- | --- |
| `nonmember_cannot_deliver` | Existing `membership_and_context_binding_survive_hardening` exercises Bob's assigned grant check (single conductor); new fourth-conductor local preflight refuses leaked secret. **Cross-conductor forced remote nonmember call still missing** because the ordinary sender extern blocks it before `call_remote`. |
| `forged_envelope_sender_rejected` | Existing `membership_and_context_binding_survive_hardening` uses a member's authenticated test provenance but claims another sender. A test-only sender zome or external real network call bypassing the sending preflight is needed to test **forged wire traffic across conductors**. |
| `local_injection_rejected` | New test. |
| `revoke_inbox_grant_roundtrip` and `revoked_grant_cannot_deliver` | Existing grant-delete test + new post-revocation real remote test. |
| `frost_round3_requires_sealed_packet` | New send-side and recipient-side negative. |
| `concurrent_deliveries_preserve_unrelated_slots` | Existing network fan-in and race tests; no duplicate. |
| `late_conflicting_slot_is_reported` | Existing `r11_conflicting_pair_leaves_unrelated_slots_readable` asserts two variants and unaffected peers. A **deterministic read-after-first-variant, then late second commit** is not in the new suite; native active-poll tests are a separate layer, and conflict visibility after a completed operation is not guaranteed. |
| `quota_exhaustion_is_sender_isolated` | Existing flood and concurrent overshoot tests. |
| `private_inbox_isolation_preserved` | New four-conductor test and existing three-conductor private read. |
| Offline peer and visibility-race behaviour | **NOT RUN / incomplete**: no shutdown/partition fault harness or forced gossip delay. Failure must be treated as fail-closed; unknown delivery outcome is never automatically retried. |

### Suite wiring

At commit `545b4ebed7f8cfd613fe787109df4102c8fbe4ef`,
`package.json` was updated so the normal `npm run test:sweettest`
suite also invokes this test file, and an opt-in
`npm run test:fable-conductors` script builds the disposable hApp and runs
only Agent 21 cases. **Neither script was executed here.** Existing
tests were not skipped, weakened or replaced.

## 5. Evidence by Fable E1–E8

| Level | Agent 21 status | Explanation |
| --- | --- | --- |
| E1 source exists | **YES** | New Sweettest file at exact GitHub commit `e71e050069239bbee6f3447fcf02de459537b9e9`; existing coordinator, integrity and tests inspected at `899e433d...`. |
| E2 compiles | **NOT RUN** | No local Cargo/Rust compiler, no local clone. Existing integrated baseline has independently reported compile failure. |
| E3 executed native test passes | **NOT RUN** | No new native test executed by Agent 21. Existing author-reported results are not fresh evidence. |
| E4 WASM + hApp build | **NOT RUN** | `hc`, `cargo`, `nix` absent; approved release hashes left unchanged. |
| E5 real-conductor execution | **NOT RUN** | Source fixtures do not establish tested conductor authentication or revocation. |
| E6 native crypto across conductors | **NOT RUN / OUT OF AGENT 21 SCOPE** | This fixture tests the coordinator envelope path, not an end-to-end native FROST ceremony. |
| E7 adversarial/fault injection | **AUTHORED, NOT RUN** | No executable negative result or captured conductor log on this new commit. |
| E8 independent review | **NOT RUN for this change** | The distinct Sprint 1.5 source review cannot serve as review of the new Agent 21 test commit. |

### Attempted local environment probes (not security tests)

Executed on 2026-11-16 against the Agent 21 workspace, **not** a cloned
GitHub commit. The full local transcript was also exported as
`agent21_environment.log`; no private values are printed.

| Exact command | Exit | Relevant output |
| --- | --- | --- |
| `command -v rustc` | 1 | no path |
| `command -v cargo` | 1 | no path |
| `command -v nix` | 1 | no path |
| `command -v hc` | 1 | no path |
| `command -v holochain` | 1 | no path |
| `command -v node` | 0 | Node binary exists; **not** a Rust/Holochain runner |
| `command -v npm` | 0 | npm exists; **not** a WASM/hApp build |
| `command -v git` | 0 | /usr/bin/git |
| `timeout 10 git ls-remote https://github.com/ConorTttttt/holochain-threshold-cryptography.git refs/heads/sprint1/agent6-stage2c-integration-20261116` | 128 | `Could not resolve host: github.com`; GitHub repository contents were inspected through the linked repository connection instead. |

**No `cargo test`, `npm run build:happ`, `npm run test:sweettest` or
`hc` command was executed here. Their exit statuses are NOT AVAILABLE,
not zero. No test execution logs were generated.**

## 6. Exact execution plan for a fresh pinned disposable runner — NOT RUN

Check out **this branch at an exact immutable commit**, record it with
`git rev-parse HEAD`, and use the repository's locked Holonix 0.7.1 toolchain.
Use a short temporary directory for Unix sockets, fresh Sweettest identities,
and no external production app or Lair state. Before running, fix the
integrated-workspace `holochain_zome_types` dependency gate in the owning
task; do not bypass it via `--exclude` or altered approval hashes.

```sh
git rev-parse HEAD
rustc --version; cargo --version; hc --version
mkdir -p /tmp/dkg-agent21
export TMPDIR=/tmp/dkg-agent21
cargo check --locked --workspace --all-targets
npm run build:happ
cargo test --locked -p mpc --test mpc_network -- --nocapture --test-threads=1
cargo test --locked -p mpc --test inbox_hardening -- --nocapture --test-threads=1
cargo test --locked -p mpc --test revoke_cap_grant -- --nocapture --test-threads=1
cargo test --locked -p mpc --test fable_conductor_adversarial -- --nocapture --test-threads=1
```

Run the commands sequentially, archiving for **each**: immutable commit,
complete command, exit status, `rustc`/`cargo`/`hc` versions, test name
and relevant redacted output. Treat every `FAIL`, panic, no-run, hang or
missing Holochain dependency as failure/not-run evidence, never a pass.
Do not print debug-form `ZomeCallResponse::Unauthorized`, grant secrets,
nonce bytes, encrypted payloads, IPC frames or private DKG material.

After a green integrated build, remaining required deeper coverage is:
an isolated test-only remote caller that can send forged envelopes and a
fourth nonmember over the **network** while using authentic Holochain
provenance; deterministic late-conflict injection with a pre-conflict
snapshot; offline conductor, pending acceptance gossip, and revocation/write
race witnesses. Any dedicated test-only DNA must be separately packaged and
must not replace the approved production DNA.

## 7. Decision / acceptance status

**CHANGES REQUIRED — E5/E7 acceptance NOT MET.** The new source is a
reproducible fixture proposal, not evidence that authenticated provenance,
revocation, private reads, quota or conflict handling passed on real
conductors at this commit. Do not merge it into `main`, alter deployed
cells, approve release identities, or promote production readiness without
a green exact-head build and independent executed negative evidence.
