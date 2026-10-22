# v0.4.0 security review — Phase 7 custody, Phase 8 signing, Gate 0 and Phase 6 changes

22 October 2026 (Europe/London). Performed by the coding assistant at the
operator's request, following the operator-supplied "Crypto Holochain Security
Reviewer" instructions, with `docs/security-profile.yaml` as the project
profile. **This is a code review, not an independent audit, formal
verification or certification.**

## Verdict

**Verdict:** CHANGES_REQUIRED, then remediated in the working tree (see
[Remediation](#remediation)). After remediation: PASS_WITH_CAVEATS, with R6
open.
**Mode:** DEEP. The scope touches signature generation, key custody, signing
authorization and Holochain validation.
**Scope:** branch `feature/v0.4.0-phase5c-live-writes`.
- Base: `HEAD 544270f` (v0.3.8).
- Reviewed tree: `refs/checkpoints/phase8-20261022` (`0af1d2d`). Nothing is
  committed on the branch.
- Examined in full: `crates/mpc-dkg-worker/src/{signing, signing_signer,
  sign_main, lair_signer, lair_signer_main, signed_relay, signed_call_policy,
  socket_signer (request path), node_service, relay (inbox and roster),
  phase5c_provision_main (Phase 8 commands)}.rs`, the custody code in
  `crates/mpc-dkg-worker/src/lib.rs`, `crates/mpc-frost-ed25519/src/lib.rs`,
  `crates/mpc-security/src/{activation, sealed}.rs`,
  `crates/mpc-runtime/src/lib.rs`, the integrity zome, and the coordinator
  functions for inbox, delivery, results, activations and approvals.
- Examined for secret handling only: `scripts/phase5c_b_audit.sh` and
  `scripts/phase6_rehearsal.py`.
- Not re-reviewed: the 5C-C code covered by
  `V040_PHASE5C_C_SECURITY_REVIEW.md` (capability exchange, transport probe).
**Findings:** P0: 0 / P1: 1 / P2: 0 / P3: 5
**Bottom line:** the cryptographic core holds up: single-use nonces, roster
binding, verified aggregation and activation gating. However, the approval
step let every operator approve a message they never saw, which defeats the
threshold-approval guarantee. Do not merge without R1.

## Findings

**[P1] R1 — `approve-intent` approves message bytes the operator never sees or checks**
- **Location:** `crates/mpc-dkg-worker/src/phase5c_provision_main.rs:604-647`
  (`make_intent`, `approve_intent`); display at `:619` and `:639-640`.
- **Confidence:** HIGH
- **Violated property:** "An operation needs independent human/application
  authorization before signing", and `Signer::sign`'s contract that the
  signer is shown "the *exact* human-readable intent"
  (`mpc-frost-ed25519/src/lib.rs:470-471`).
- **Evidence:** `approve_intent` loads the plan file and prints only
  `operation_id`, `message_bytes=<len>` and the signers. It then publishes
  the digest of whatever message the file carries. `make_intent` labels a
  domain-separated `commitment(...)` as `message_sha256_commitment`, which
  `sha256sum` cannot reproduce. The plan is public JSON whose message is an
  unreadable array of numbers.
- **Trigger or attack path:** the plan author is one operator, and the
  distribution channel is unspecified. A malicious author, or anyone who
  alters the plan in transit, substitutes the message. Every selected
  operator then approves through the tool without any means to notice.
- **Impact:** the group signs an attacker-chosen message, with every
  required approval present.
- **Fix:** `approve-intent` requires `--message-file`, the operator's own,
  independently obtained copy. Approval is refused unless the plan's message
  matches it byte for byte, and the check runs before Lair is unlocked. The
  review prints the plain SHA-256, an escaped preview (no terminal control
  bytes) and the group key. `make-intent` prints the same review.
- **Regression test:** `tests/signing_session.rs::approval_review_binds_the_operators_own_message`.
  The rehearsal's `approve-tampered-*` step must also be refused.

**[P3] R3 — Any non-selected member can veto a signing operation**
- **Location:** `crates/mpc-dkg-worker/src/signing.rs:204-207`
- **Confidence:** HIGH
- **Violated property:** only the selected signers take part in an operation;
  members outside the roster carry no authority.
- **Evidence:** `ingest` returned `Err` for any round-4/6 frame in the
  operation's slot from a sender outside `plan.selected`, and `run_signing`
  aborts on that error.
- **Trigger or attack path:** a non-selected member learns the public plan
  and already holds a delivery grant from 5C-B. It sends one envelope with
  the operation's sequence to a selected signer.
- **Impact:** the operation aborts and the nonce slots burn. A member that
  was deliberately left out can block every operation it learns about.
- **Fix:** ignore such frames, which is safe: only roster commitments
  ever enter the package.
- **Regression test:** `non_selected_member_frames_are_ignored`.

**[P3] R6 — One conflicting delivery pair blocks a node's inbox for the whole proposal (open)**
- **Location:** `dnas/mpc/zomes/coordinator/mpc/src/lib.rs:225` (relaxed
  ordering) together with `:279-291` (`get_inbox` fails the whole call on
  equivocation).
- **Confidence:** MEDIUM. The race is real, but there is no live
  demonstration.
- **Violated property:** availability of operations that do not involve the
  misbehaving member.
- **Evidence:** the Phase 6 fix changed `InboxEvent` creation to
  `ChainTopOrdering::Relaxed`. Two concurrent deliveries with the same
  (sender, round, sequence) and different payloads can now both commit;
  strict ordering made the second fail with `HeadMoved`. From then on,
  `get_inbox` returns "Equivocation" for the proposal on that node.
- **Trigger or attack path:** a malicious member with a delivery grant sends
  a conflicting pair concurrently, retrying until the race wins.
- **Impact:** the victim node can no longer read its inbox for this group,
  so it can never sign for the group again. Before this change the same
  outcome was available only through the 16,384-message capacity limit, which
  costs far more. The project does not claim robustness against malicious
  members, which is why this is P3.
- **Fix (not applied; needs a design decision):**
  1. Have `get_inbox` return conflicting envelopes rather than fail the call,
     so that only the consumer of that slot aborts. The DKG relay already
     aborts on conflicts in a poll; `run_signing` would need the same check.
  2. Add a per-sender share of `MAX_MESSAGES_PER_SESSION`, so that one member
     cannot exhaust another member's capacity.
  Both are coordinator-only changes, and both fall under the pending
  `update_coordinators` decision for the 5C cells.
- **Regression test:** a Sweettest that delivers a concurrent conflicting
  pair, then checks that `get_inbox` still serves other senders' slots.

**[P3] R2 — The DKG-time signer also signs signing-round frames**
- **Location:** `crates/mpc-dkg-worker/src/lair_signer.rs:151-158` (`env.round>6`)
- **Confidence:** HIGH
- **Violated property:** profile separation and least privilege. Rounds 4–6
  must be signed only against an operator-approved plan.
- **Evidence:** the DKG profile accepted any round from 1 to 6. The DKG uses
  only rounds 1–3 (`relay.rs` and the controller).
- **Trigger or attack path:** a buggy or confused relay, or any client on the
  signer socket, asks the DKG-profile signer to send round-4/6 frames
  attributed to this agent, with no plan check. Same-UID compromise is
  already out of scope, so this is hardening.
- **Impact:** frames injected as this agent make honest peers abort. No
  forgery follows, because the share is never touched.
- **Fix:** the DKG profile refuses rounds above 3.
- **Regression test:** `lair_signer::tests::dkg_profile_refuses_signing_rounds`.

**[P3] R4 — A failed signing run left its operation `open` in the journal**
- **Location:** `crates/mpc-dkg-worker/src/signing.rs:317-335`
- **Confidence:** HIGH
- **Violated property:** the durable state matches what happened ("record
  exact state before remediation").
- **Evidence:** errors after `SigningSession::begin` returned without
  `record_abort`. The lifecycle row stayed `open` and the nonce row stayed
  `published` until a later `ensure_live` expired them.
- **Trigger or attack path:** any failure after the commitment is published,
  such as a peer that never answers or a transport error.
- **Impact:** an operator or audit reading the journal cannot tell a dead
  operation from an in-flight one. Safety is unaffected: the deadline row and
  the lost in-memory nonce already block re-entry.
- **Fix:** journal the abort, which also burns the nonce slot, on every
  failure after `begin`.
- **Regression test:** `failed_run_journals_the_abort`.

**[P3] R5 — Plans that validate could not be loaded by any reader**
- **Location:**
  - `crates/mpc-dkg-worker/src/signing.rs:28,69` (16 KiB message limit);
  - `phase5c_provision_main.rs:57` (64 KiB `MAX_FILE`) and `:616,670`
    (pretty-printed JSON);
  - `probe_signer.rs:272` (64 KiB limit).
- **Confidence:** HIGH (measured)
- **Violated property:** the validation limits are consistent with every
  reader.
- **Evidence:** pretty-printed JSON spends up to about 9 bytes per message
  byte. With 3 parties, a worst-case plan passed 64 KiB at about 6.4 KB of
  message. Even compact JSON exceeds 64 KiB at 16 KiB.
- **Trigger or attack path:** an operator signs a message larger than about
  6 KB.
- **Impact:** `make-intent` writes a plan that `approve-intent`,
  `write-signing-policy` and `mpc-sign` all refuse. The failure is closed, but
  late and confusing.
- **Fix:**
  - the message limit is 8 KiB;
  - `validate` bounds the compact encoding at 48 KiB;
  - plans and signing policies are written as compact JSON;
  - `write-signing-policy` refuses output above 64 KiB.
- **Regression test:** `plans_that_validate_fit_every_reader`.

## Unresolved security questions

- **What may be signed.** Message semantics and application policy, such as
  a review UI and allow-lists, remain outside Phase 8. R1 makes approval bind
  to the operator's bytes; it does not decide whether those bytes are safe.
- **Availability against malicious members** (R6, plus inbox capacity). The
  project needs a stated target before R6's design choice can be made.
- **Custody.** The share, the master key and every service share one UID and
  disk, with no anti-rollback. Restoring an old journal re-enables the
  one-shot checks for an old operation id. Nonces are never stored, so a
  nonce cannot repeat, but the operation could be signed again. Resolving
  this needs per-role OS users or an HSM, and a monotonic counter.
- **Trusted time.** Deadlines use the system clock. Clock rollback cannot
  reuse a nonce, because nonce slots are insert-once, but it can extend a
  deadline.

## Verification

- **Inputs:** the operator's review instructions and the security-profile
  template; repository docs (`SECURITY.md`, `V040_PHASE5C_C_SECURITY_REVIEW.md`,
  `V040_PHASE6/7/8_*.md`); `Cargo.toml` pins (frost-ed25519 =3.0.0,
  crypto_box =0.9.1, Holochain 0.7.1).
- **Commands run after the fixes (development host, rustc 1.99):** see
  [Remediation](#remediation).
- **Not available or not done:**
  - no PR diff (the reviewed scope is the uncommitted working tree against
    `544270f`);
  - no fuzzing or side-channel analysis;
  - no multi-machine run;
  - no live persistent 5B/5C deployment was touched.

## Final assessment

R1 had to be fixed before merging, and it is now fixed and tested, together
with R2–R5. R6 stays open pending a decision on the availability target. The
material remaining assurance gaps are an independent audit, multi-machine and
fault testing, and production custody. A PASS here is not cryptographic
certification.

## Remediation

Applied in the working tree on 22 October, after the review findings were
written up. No zome or DNA change was made: the hApp, the DNA hash and the
coordinator are unchanged.

| ID | Status | Change |
|---|---|---|
| R1 | Fixed | `signing::approval_review` and `message_sha256`. `approve-intent` requires `--message-file` and checks it before Lair is unlocked. Both `approve-intent` and `make-intent` print the plain SHA-256, an escaped preview and the group key |
| R2 | Fixed | `lair_signer.rs`: the DKG profile refuses rounds above 3 |
| R3 | Fixed | `SigningSession::ingest` ignores frames from senders outside the roster |
| R4 | Fixed | `run_signing` calls `record_abort` (lifecycle `aborted`, nonce slots `burned`) on any failure after `begin` |
| R5 | Fixed | The message limit is 8 KiB and the compact plan limit 48 KiB. Plans and policies are written as compact JSON. `write-signing-policy` refuses output above 64 KiB |
| R6 | **Open** | Needs a decision on the availability target and the coordinator design (see R6). It goes with the pending `update_coordinators` decision |

**Evidence (development host, rustc 1.99):**

- **Pre-fix proof.** The new regression tests were run against the reviewed
  tree (`phase8-20261022`, exported to a scratch directory).
  - `plans_that_validate_fit_every_reader`, `failed_run_journals_the_abort`,
    `non_selected_member_frames_are_ignored` and
    `dkg_profile_refuses_signing_rounds` **failed**.
  - The 4 original signing tests passed.
  - R1's test cannot compile against that tree, because the check did not
    exist; the rehearsal step below demonstrates it live.
- **Post-fix suites:**
  - `npm run test:native`: 18 groups, 115 passed, 0 failed (previously 111).
  - `signing_session` 8/8.
  - `cargo test -p holochain-mpc-dkg-worker --features lair-signer --lib`:
    56/56.
  - `--bin mpc-phase5c-provision`: 6/6.
  - `npm run test:transport-probe`: 1/1 and 21/21.
  - Sweettests `mpc_network`, `dkg_live`, `revoke_cap_grant`,
    `three_processes`, `conductor_bridge` and `capability_provisioning`: each
    1/1.
  - `check_release.py`, `check:holochain-versions` and `check:wasm-imports`:
    PASS.
- **Disposable rehearsal** (`scripts/phase6_rehearsal.py`, run
  `run-20261022T130823Z`):
  - A 2-of-3 DKG completed, and both selected operators approved.
  - Each operator's `approve-intent` on a plan with an altered message was
    refused before Lair unlocked ("the plan's message differs from your
    --message-file").
  - The printed `message_sha256` equals `sha256sum` of the operator's file.
  - Nodes 1 and 3 signed, and OpenSSL verifies the signature and rejects a
    tampered message.
  - A repeat run and the unselected member were refused.
- The persistent 5B/5C deployments and `~/.local/state/mpc-phase5c` were not
  touched.

**Operator impact:**

- `approve-intent` now needs `--message-file`.
- Plan files written before this change still load if they fit the new
  limits; any message above 8 KiB must be split or shortened.
- DKG-profile signer policies are unchanged on disk; only their allowed
  rounds narrowed.
