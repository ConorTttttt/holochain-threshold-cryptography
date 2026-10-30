# v0.4.0 threat model — Holochain MPC Core

27 October 2026 (Europe/London). Written by the coding assistant at the
operator's request from the existing repository documents and the 22 October
security review; no new code behaviour is claimed. **Development evidence, not
production custody, not an independent audit.** The project is not production
ready: do not use real keys, funds or identities.

Sources: `ARCHITECTURE.md`, `SECURITY.md`, `SECURITY_PROTOCOL.md`,
`V040_SECURITY_REVIEW_2026-10-22.md`, `security-profile.yaml`,
`V040_PHASE7_SHARE_CUSTODY.md`, `V040_PHASE8_SIGNING.md`,
`V040_PHASE5C_B_PERSISTENT_DEPLOYMENT_REPORT.md`, and the code paths named in
each row. Where a row rests only on a document, it says "per" that document.

## Risk IDs

`R1`–`R11` and `L1`–`L4` are the IDs in the engineering handover's risk table.
They are **not** the same as the `R1`–`R6` finding numbers inside
`V040_SECURITY_REVIEW_2026-10-22.md`; this document writes those as `REV-1`
to `REV-6`.

| ID | Short name | Status in handover (27 Oct) |
|---|---|---|
| R1 | Grants are function-scoped, not session-scoped | Open, documented |
| R2 | Uncertain writes; no retry | Open, process rule |
| R3 | Development-grade custody; no anti-rollback | Open |
| R4 | Deployment evidence gap on the persistent 5C cells (5C-B audit output, installed-WASM provenance, real Lair/WebSocket interop) | Open, operator-only |
| R5 | Probe capability checks labels, not grant provenance | Open |
| R6 | Uncommitted working tree | Open, operator |
| R7 | App interfaces use `allowed_origins: "*"` and `installed_app_id: null` | Open on persistent conductors; tooling and a disposable-conductor check exist (`V040_RELEASE_HARDENING.md`) |
| R8 | *No row exists in the handover table* | Unassigned |
| R9 | Supply chain: dependency advisories, toolchain provenance | Open (reduced 22 Oct) |
| R10 | Persistent 5C cells run the 17 October coordinator | Open, operator decision |
| R11 | A malicious member can block a node's inbox (= `REV-6`) | Open, design decision |
| L1 | Unanimous echo is not reliable broadcast; any member can abort | Limitation |
| L2 | SDK pinned to 0.7.1; rebuilt integrity WASM changes the DNA hash | Limitation |
| L3 | Registration has no overall CLI deadline | Limitation |
| L4 | FHS, ZKP, offline payments are research ideas, not features | Limitation |

## 1. Assets

| # | Asset | Where it lives | Harm if lost or altered | IDs |
|---|---|---|---|---|
| A1 | FROST key share (`KeyPackage`) of each member | In memory in the worker; sealed in the node's `RuntimeStore` journal (XChaCha20-Poly1305, write-once per proposal, epoch and owner) | A share holder below the threshold learns nothing alone; `t` shares forge group signatures | R3, L1 |
| A2 | Node master key (`storage.key`, 0600) and journal | Same disk and UID as the worker, signers and `mpc-sign` | Opens A1; a restored old journal re-enables one-shot checks | R3 |
| A3 | Group verifying key and `GroupDescriptor` | Public (DHT attestations, `group-descriptor.json`) | Wrong key pinned means signatures verify against the wrong group | R1, L2 |
| A4 | Agent signing keys | Lair keystore 0.7.1, passphrase typed by the operator | Lair access lets an attacker sign zome calls as the agent | R3, R4 |
| A5 | Signing nonces | Never persisted; slots reserved and burned in SQLite before a commitment leaves the process | Nonce reuse reveals the share | R3 |
| A6 | Signing intent: the message an operator approves | Public `SigningPlan`; operator's own `--message-file` | The group signs a message nobody meant to approve | REV-1 (fixed) |
| A7 | Private inbox (`InboxEvent`) and capability secrets | Recipient's source chain; `CapGrant` secrets exchanged as sealed offers | Delivery as another member; sealed Round-2 packets exposed to a local attacker | R1, R5 |
| A8 | Availability of a node's inbox and of operations | Coordinator `get_inbox`, 16,384-message cap | A node can no longer sign for a group | R11, L1 |
| A9 | Build artifacts: zome WASM, `.dna`, `.happ`, DNA hash | `target/`, `dnas/mpc/workdir`, `workdir` | Wrong code or wrong network in a deployed cell | R4, R9, L2 |
| A10 | Persistent 5C deployment state | `~/mpc-phase5c-sandbox` and `~/.local/state/mpc-phase5c` (operator-only) | Integrity of the running cells and grants | R4, R10 |
| A11 | Native binaries and their dependency set | `cargo` workspace, `Cargo.lock` | A vulnerable or substituted dependency executes with the share | R9 |

## 2. Trust boundaries

| # | Boundary | What crosses | Authentication | Evidence | IDs |
|---|---|---|---|---|---|
| TB1 | Other members ↔ my coordinator (Holochain remote call) | `IncomingMessage` | Conductor-provided `call_info()?.provenance`; assigned capability secret per peer | `authenticate_incoming` in the coordinator; `SECURITY.md` | R1, R5, R11 |
| TB2 | Coordinator ↔ DHT | Public entries and links | Author-signed actions; integrity validation of membership, immutability, link relationships | `security-profile.yaml` (`required_validation_invariants`) | L2 |
| TB3 | Relay or bridge ↔ conductor app interface | Signed zome calls, reads | App authentication token; origin; loopback bind check; pinned app, role, agent and DNA | `connection_policy.rs`, `conductor_client.rs`, `V040_APP_WEBSOCKET_PREFLIGHT.md` | R7 |
| TB4 | Relay or bridge ↔ signer (Unix socket) | Admission requests, signed call params | Directory 0700 and socket 0600 owned by the operator's UID, plus a same-UID peer check (`SO_PEERCRED`); signer policy pins profile, roster, rounds and bytes | `socket_signer.rs`, `lair_signer.rs`, `signed_call_policy.rs` | R3 |
| TB5 | Signer ↔ Lair | Zome-call signing | Operator-typed passphrase; external Lair process | `V040_LAIR_SIGNER_PHASE5A.md` | R3, R4 |
| TB6 | Host ↔ worker (`mpc-node`, `mpc-dkg-worker` IPC) | `AuthFrame<Command>` and replies | HMAC-SHA256 per direction, ceremony context, strict sequence, 512 KiB line cap | `ipc.rs`, `node_service.rs` | R3 |
| TB7 | Operator ↔ operator (plan files, capability offers) | `SigningPlan` JSON, sealed offers | Out of band. Approval binds the operator's own copy of the message byte for byte | `signing.rs::approval_review` | REV-1 |
| TB8 | Worker ↔ disk (journal, share custody) | Sealed records | Master key (same UID); file-mode checks | `V040_PHASE7_SHARE_CUSTODY.md` | R3 |
| TB9 | Build host ↔ deployed cell | WASM, `.dna`, `.happ` | Byte comparison and DNA hash only; no signed provenance | `scripts/release_check.py`, `V040_RELEASE_HARDENING.md` | R4, R9, L2 |
| TB10 | Operator ↔ persistent conductors | `update_coordinators`, token issue, grants | Operator-only; step-specific approval | Handover safety rules | R4, R10 |

## 3. Actors

| Actor | Capability assumed | Not assumed | IDs |
|---|---|---|---|
| Network observer or relay | Delay, drop, duplicate, reorder messages | Breaking X25519/XSalsa20 or HMAC | L1 |
| Malicious member (up to t−1) | Holds a delivery grant; publishes DHT entries that pass validation; may abort any ceremony; may send conflicting deliveries | Reading other members' private chains | L1, R1, R11 |
| Non-selected member | Knows public plans; holds a delivery grant | Authority over an operation outside its roster | REV-3 (fixed) |
| Malicious plan author or channel | Substitutes the message in a plan file | Access to an operator's `--message-file` | REV-1 (fixed) |
| Local same-UID process | Reads master key, journal, Lair socket | Defended against: **no** | R3 |
| Compromised conductor | Reads private entries and grant secrets | Defended against: **no** (trusted component) | R3, R7 |
| Dependency or toolchain supplier | Ships a malicious or vulnerable crate or compiler | Defended against beyond lockfile pins and audit: **no** | R9 |
| Browser page or local program reaching an app WebSocket | Opens a connection to a loopback app port | Holding a valid authentication token | R7 |
| Operator | Trusted for approvals, passphrases, persistent steps | Perfect procedure | R2, R4, R10 |

## 4. Attacks, controls and residual risk

Residual risk is stated as the project documents it. "Open" means no code or
procedure in the repository closes it.

| # | Attack | Controls implemented | Tests or evidence | Residual risk | IDs |
|---|---|---|---|---|---|
| T1 | Forge the sender of an inbox delivery | Sender is `call_info()?.provenance`, never the payload field; `Envelope::validate_received` | `forged_caller_rejected` (`mpc-core`) | A member holding a grant can still deliver as itself | R1 |
| T2 | Reuse a capability grant in a second session with the same members | Grant tag carries 4 session bytes; zome checks proposal, membership and consent; tool binds the ceremony | Documented behaviour; no isolation test | **Open.** Real isolation needs a DNA design | R1, L2 |
| T3 | Equivocate in DKG round 1 or attestation | Authenticated echo, unanimous digest attestation, `VerifiedTranscript` gate before `part2`; relay aborts on conflicts in a poll | `security_protocol.rs` (equivocation, conflicting attestations) | Safe but any member can force an abort | L1 |
| T4 | Withhold messages or go offline to stall a ceremony | Fail closed; deadlines; no resume of a DKG | Rehearsal abort paths | **By design:** liveness is not provided | L1 |
| T5 | Read or alter a DKG round-2 share in transit | X25519+XSalsa20Poly1305 `SealedPacket`; header (sender, recipient, round, sequence) and ceremony fingerprint inside the ciphertext, checked after decryption; recipient keys pinned to author-signed registrations | `security_protocol.rs` (tampering, context swapping, wrong pinned key) | A key registration does not prove possession of the private key. A compromised conductor reads private chain entries | R3, R5 |
| T6 | Put a plaintext round-3 share into the inbox | `require_sealed_dkg` (coordinator) and `SealedPacket::structurally_valid`; relay and signed-call policy refuse unsealed round 3 | Coordinator and `signed_call_policy` tests | Structure only; authenticity is checked by the native receiver | R5 |
| T7 | Deliver a conflicting pair for one (sender, round, sequence) to make `get_inbox` fail | `get_inbox` reports equivocation instead of choosing | Behaviour documented in `ARCHITECTURE.md` | **Open.** With relaxed ordering both writes can commit; the victim cannot read that proposal's inbox. Fix is a coordinator change bundled with `update_coordinators` | R11, R10 |
| T8 | Exhaust the 16,384-message inbox of another member | Per-session cap | — | **Open.** No per-sender share | R11 |
| T9 | Substitute the message in a signing plan | `approve-intent` requires the operator's `--message-file`, compares byte for byte before Lair unlocks, prints SHA-256 and an escaped preview; the plain `message_sha256` matches `sha256sum` | `approval_review_binds_the_operators_own_message`; rehearsal `approve-tampered-*` refused | Whether the bytes are safe to sign is outside the system | REV-1, R3 |
| T10 | A non-selected member vetoes an operation | `SigningSession::ingest` ignores frames from outside the roster | `non_selected_member_frames_are_ignored` | None documented | REV-3 |
| T11 | Use the DKG-profile signer for signing rounds, or the reverse | DKG profile refuses rounds above 3; signing profile signs only one plan's rounds 4 and 6; probe profile only probes | `dkg_profile_refuses_signing_rounds`, `lair_signer` tests | Same-UID compromise defeats profile separation | REV-2, R3 |
| T12 | Reuse a nonce or sign one operation twice | Nonce slot reserved and burned in SQLite before the commitment leaves; nonces never persisted; `start_deadline` insert-once per operation; any failure journals an abort | `failed_run_journals_the_abort`; rehearsal repeat run refused | Restoring an old journal can let an operation be signed again | REV-4, R3 |
| T13 | Roll back the journal or disk | None | — | **Open.** Needs a monotonic counter or append-only external evidence | R3 |
| T14 | Read the share or master key as another process of the same user | File mode 0600 and directory checks; share sealed under the master key | `recovery_refuses_wrong_descriptor_key_owner_or_second_seal` | **Open.** Master key, journal and services share one UID and disk. No HSM or keyring | R3 |
| T15 | Retry an uncertain write and fork state | Journal forbids restarting aborted proposals; uncertain or invalid acknowledgement never retries | `uncertain_or_invalid_ack_never_retries_even_after_reopen` | `prepare_inbox_grant` is not idempotent and the coordinator's error text suggests retrying | R2, L3 |
| T16 | Concurrent deliveries fail on a stale coordinator | The repository coordinator uses relaxed ordering for `InboxEvent` | Phase 6 rehearsal | The persistent 5C cells still run the 17 October coordinator | R10 |
| T17 | A web page or local program connects to an app interface, or uses an interface bound to another app | Client requires loopback, an authentication token file (0600, no links), and verifies app id, role, agent and DNA | `connection_policy::tests`, `conductor_client` tests; `mpc-phase5b-bootstrap check-app-interfaces` and `attach-app-interface` (unit tests, plus one live run on a disposable conductor: a bound interface refused foreign origins) | Interfaces made by `hc sandbox` or `add-app-ws` default to `*` and no app binding, and the persistent 5C conductors still have them. Token binding to another app was not tested live | R7 |
| T18 | Vulnerable or substituted dependency or compiler | Exact version pins for Holochain and the crypto crates; `Cargo.lock`; `check:holochain-versions`; `check:wasm-imports`; `cargo audit` | `V040_RELEASE_HARDENING.md` (27 Oct `cargo audit`: all 10 advisories test-only or build-only in this repository, one unplaced) | `lru` (unsound warning) ships in the `lair-signer` binaries; the same `quinn-proto` line probably ships in the live conductor; toolchain unpinned, no signed build provenance | R9, L2 |
| T19 | An integrity change silently changes the network | Integrity zome and DNA properties frozen; release check compares the integrity WASM and DNA hash | `scripts/release_check.py` `identity` step against `scripts/release_hashes.json` (passes; a tampered hash fails) | A rebuilt integrity WASM is a new DNA by design | L2 |
| T20 | Install a forged capability offer | Offers are sealed and ceremony-bound; policy pins the FROST ceremony and spec | `review_b2_frost_signer_refuses_misbound_probe_ceremony` | The probe capability checks syntax and labels, not grant issuance or secret provenance | R5 |
| T21 | Move the system clock to extend a deadline | Nonce slots are insert-once, so rollback cannot reuse a nonce | Documented in the 22 October review | Deadlines extend; time is untrusted | R3 |
| T22 | Malformed or oversized input to a parser | Bounds, version fields and `deny_unknown_fields` on IPC, signer, signing and custody types | Existing refusal tests plus `wire_validation.rs` and `input_validation.rs` (11 tests, see `V040_RELEASE_HARDENING.md`) | Several wire types ignore unknown fields (gaps G1 to G3); the relay's inbox limit (4,096) is below the coordinator's cap (16,384); the signed-call policy admits sends up to 128 KiB against a 64 KiB envelope limit | R3, R11 |
| T23 | Treat unverified artifacts as the deployed build | Byte-identity check of the rebuilt WASM, `.dna` and `.happ` against recorded hashes | `scripts/release_check.py` (passes on the development host) | The recorded hashes were not compared with the installed 5C cells; the 5C-B audit has no output | R4 |
| T24 | Merge or lose unreviewed work | Checkpoint refs; `git` rules in the handover | Handover | Working tree is uncommitted | R6 |
| T25 | Claim research ideas as shipped features | Wording rule: FHS, ZKP and offline payments stay out of FROST claims | This document | None | L4 |

## 5. Residual risk register by ID

| ID | Open item | Needed to close |
|---|---|---|
| R1 | Grants not session-scoped | DNA design (a new network) |
| R2 | Operator discipline around uncertain writes | Idempotent grant preparation (coordinator change) and corrected error text |
| R3 | Same-UID custody, no anti-rollback, untrusted time | Per-role OS users or an HSM, a monotonic counter, tested backup and restore |
| R4 | No 5C-B audit output; installed-WASM provenance and Lair/WebSocket interop unproven on the persistent cells (disposable-rehearsal evidence exists) | Operator relaunch, read-only audit, comparison with `release_check.py` hashes |
| R5 | Probe capability not tied to a freshly verified grant | Independent verification of a fresh assigned grant and the sealed-offer import |
| R6 | Uncommitted tree | Operator review and checkpoint |
| R7 | Wildcard origin and unbound interfaces on conductors set up outside the repository | Operator runs `check-app-interfaces`, then `attach-app-interface` for each app and repoints the tools. No automated test of a refused origin exists; the live check was a one-off script |
| R8 | Not in the handover table | Handover owner to assign or retire the ID |
| R9 | Advisories in the Holochain crate tree (test-only or build-only here); `lru` unsound warning ships; toolchain unpinned and not attested | Upstream Holochain/Lair release; a pinned toolchain file; signed or attested builds |
| R10 | Persistent cells on the old coordinator | Approved `update_coordinators` |
| R11 | Inbox blocking by a malicious member | Availability target, then a coordinator change |
| L1 | Unanimous abort model | Stated in every claim; reliable broadcast is not planned |
| L2 | Integrity frozen at SDK 0.7.1 | Explicit SDK change with separate tests and a fresh DNA |
| L3 | No overall registration deadline | Kill a stalled call; the attempt marker stays terminal |
| L4 | Research ideas | Out of scope for FROST claims |

## 6. Not assessed

- No side-channel analysis, fuzzing, formal verification or independent audit.
- No separate-machine, partition or kill testing in the repository at this
  date.
- Message semantics and signing policy (what may be signed) are outside the
  system.
- The vault application and UI work packages are outside this document.
- Third-party code (Holochain, Lair, `frost-ed25519`, `crypto_box`, `rusqlite`)
  is trusted as shipped; only its versions are pinned and audited for
  advisories.
