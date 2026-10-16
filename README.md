
## v0.3.5 — Process-isolated DKG (experimental)

`npm run test:dkg-process` launches three separate native `mpc-dkg-worker` child processes,
one per Holochain conductor. Each retains its own FROST secret/key and exchanges
public DKG envelopes and encrypted Round-2 ciphertext via its conductor.
This uses a **test-only unauthenticated stdio parent/child IPC**; there is no
restart recovery or OS-keystore binding. See `docs/V035_PROCESS_ISOLATED_DKG.md`.

# Holochain MPC Core — v0.3.4 live-DKG integration test (experimental source)

An **application-independent Holochain 0.7 coordination primitive** with a
native FROST Ed25519 cryptographic provider, v0.3.1 security
protocol crate, and v0.3.2 native transactional runtime. Native key generation, echo-broadcast, recipient-specific
X25519+XSalsa20Poly1305 encryption, and threshold signing remain separated
from the DHT and from any payment/identity application logic.

**Status:** v0.3.3 native suites (26 tests) and three-conductor coordination Sweettest (1 test) passed in the user's Holonix environment. The **new v0.3.4 live-DKG test has NOT been compiled or executed here**. Neither version is audited or ready for production keys, assets or identity data.

## What is new in v0.3.4

- `dnas/mpc/zomes/coordinator/mpc/tests/dkg_live.rs` adds a **separate** Sweettest using three running Holochain conductors and real agent identity/proposal action hashes. All DKG announce, compact echo, transcript-attest and encrypted Round-2 payloads traverse `send_protocol_message` → private recipient `get_inbox`, rather than in-memory cross-party delivery.
- Native FROST controllers independently calculate their own verified echo gates and Round-2 shares, then complete DKG and compare public key packages. Public group activation attestations are published and authenticated by Holochain action authors. A native signature smoke test verifies 2-of-3 key usability; **signing messages themselves are not transported via Holochain** in this milestone.
- No DNA schema/wire format changes. Existing 0.3.3 session files are preserved; the 0.3.4 source package increases version metadata and native integration coverage only.
- The test harness provisions capability secrets directly and retains ephemeral X25519 and FROST secrets within one Rust test process. This is **not** an independently deployable secure sidecar, durable event journal, restart-safe DKG process, portable cryptographic receipt, or Byzantine reliable broadcast.
- Run `npm run test:dkg-live` inside Holonix from the repository root. `npm run test:sweettest` now runs both the old coordination test and the new DKG test sequentially. See [docs/V034_LIVE_DKG_INTEGRATION.md](docs/V034_LIVE_DKG_INTEGRATION.md).

## What's new in the v0.3.3 DKG research upgrade

- **Compact ceremony-bound echoes:** peers repeat a domain-separated 32-byte hash of each original Round-1 package rather than retransmitting large packages to every recipient. Missing or conflicting packages/echoes still prevent progress; this reduces bytes but does **not** reduce the number of messages or guarantee Byzantine liveness.
- **Wire-v2 replay protection:** broadcast RPC payloads include the exact proposal ActionHash and ceremony fingerprint. Older unbound broadcast messages are rejected at the adapter boundary.
- **Explicit security model:** the only currently supported guarantee is `UnanimousAbort`; a request for asynchronous Byzantine reliable broadcast fails closed.
- **No forged checkpoint import:** `EchoBroadcast` can no longer be directly deserialized as trusted state. Recovery requires a verifier-gated `replay_authenticated_events` reconstruction from authenticated durable events (durable signed-receipt provisioning and real controller wiring still pending).
- **Locally derived DKG finalisation:** `DkgParty::part3_with_evidence()` generates the `DkgPublicProposal` from a verified FROST public package and the same echo gate; feed its group descriptor to unanimous group activation. The older `part3` is retained for source compatibility.
- **New adversarial tests** and a traffic estimator, plus a reduced 8 KiB JSON Round-1 package limit to respect envelope bounds.

**Important:** `BoundBroadcastV2` changes the private security protocol wire format. Do not mix old and new controllers within one ceremony. Native/FROST/WASM tests have not been executed here. No application-specific DKG fallback or automatic group activation is introduced.

Full threat model, academic references and test plan: [docs/V033_DKG_RESEARCH_UPGRADE.md](docs/V033_DKG_RESEARCH_UPGRADE.md).

## What changed in v0.3.2

- `crates/mpc-runtime`: native-only SQLite transactional message ledger, replay/conflict refusal,
  non-reusable durable signing nonce reservations, persist-before-publish commitment burns,
  durable abort/deadline policy and XChaCha20Poly1305 encrypted write-once group-share storage.
  Master keys are externally injected; OS/Lair key provisioning and anti-rollback are **not implemented**.
- `mpc-security::activation`: unanimous group public-key-package finalisation,
  opaque `ActivatedGroup` token, canonical signing intent with an exact signer roster,
  all-selected-signers approval token, plus a locally pinned key-rotation chain.
- `mpc-frost-ed25519::ControlledSigner`: checks group activation + FROST public key,
  intent approval, SQLite-backed nonce reservation, exact signing roster and deadlines.
  `AuthenticatedShareCollector` attributes incoming shares to authenticated caller identities.
- New Holochain append-only `EncryptionKeyEpoch`, `GroupActivationAttestation`,
  `SigningApprovalAttestation` public entries and discoverable links. These are author-
  signed **declarations** and do not independently verify the cryptographic ceremony.
- New native crash/restart, replay, key-storage, approval/rotation and controlled FROST
  tests; extended three-conductor Sweettest public-record test source.

**Release gate:** This is a *source milestone*, not a verified functioning three-
conductor FROST runtime. In particular, the native runtime still needs its
conductor adapter, secure master-key provisioning, portable signed evidence,
key-rollback protection and real crash/fault-injection tests. No Cargo/hc
compilation or tests were available to run in this authoring environment.

Detailed design: [docs/V032_SECURITY_DESIGN.md](docs/V032_SECURITY_DESIGN.md).

## What changed in v0.3.1

- `crates/mpc-security`: reusable unanimous authenticated **announce → echo →
  transcript attest** state machine. Any mismatched package or attestation
  aborts, and missing peers prevent Round 2. It is fail-closed, not a general
  asynchronous Byzantine consensus algorithm.
- `VerifiedTranscript` is constructible only by the completed state machine.
  FROST `DkgParty::part2` now **requires this gate**, and verifies the actual
  canonical serialized FROST Round-1 packages against its authenticated bytes.
  Its old caller-supplied digest-map parameter has been removed.
- Native `SalsaBox` recipient-specific ciphertext packets, with sender and
  recipient identities, exact proposal, session, round and sequence inside the
  authenticated encrypted plaintext. Existing envelopes continue carrying
  only the sealed ciphertext in FROST DKG round 3 (the provider's `DkgRound2`).
- Holochain coordinator rejects plaintext containers for FROST's private DKG
  round; this is structural checking, NOT proof that a packet decrypts.
- Immutable, author-signed public encryption-key registrations and optional
  public transcript checkpoints, with discovery links. Consumers **must pin**
  the intended registry action/key to the expected member; `latest` is unsafe.
- Additional native tests for equivocation, withholding, bogus attestations,
  context/tampering, replay, encrypted actual FROST DKG shares and valid 2-of-3
  signing. Holochain Sweettest source checks new registry records.
- FROST randomness uses `rand 0.8` / `rand_core 0.6`-compatible `OsRng`, as required by `frost-ed25519 3.0.0`.

## Repository

```text
crates/mpc-core/                       SessionSpec, Envelope, SealedPacket (wire only)
crates/mpc-security/                   Echo state machine + activation/approval + crypto_box
crates/mpc-runtime/                    Native persistent journal, nonce burn, sealed share store
crates/mpc-frost-ed25519/              Native FROST DKG + signing provider
adapters/holochain-0.7/                Authenticated caller-provenance adapter
dnas/mpc/zomes/integrity/mpc_integrity/ DHT schema and deterministic validation
dnas/mpc/zomes/coordinator/mpc/        Capabilities, inbox and public registration
workdir/happ.yaml                     Packaged hApp manifest
docs/SECURITY_PROTOCOL.md              Protocol integration, remaining gaps
```

## Building and testing

```bash
nix develop
cargo test -p holochain-mpc-security --test security_protocol
cargo test -p holochain-mpc-security --test group_activation
cargo test -p holochain-mpc-runtime --test durable
cargo test -p holochain-mpc-frost-ed25519 --test three_agents
npm run test:native
npm run build:happ
npm run test:sweettest
```

`npm run build:happ` explicitly builds **only** `mpc_integrity` and `mpc` as
WASM. The native cryptographic and security crates must NOT be linked into
WASM. `cargo test` runs them on a native host.

## Integration flow

1. All listed agents accept the exact proposal, pin participant identities,
   and provision remote-call capabilities over an authenticated channel.
2. Each agent securely generates an independent X25519 keypair and publishes
   its *public* key through `register_encryption_key`. Peers pin the author and
   exact ActionHash of each accepted registration.
3. Create `EchoBroadcast` for the exact proposal and authenticated local agent (v0.3.3 controllers use versioned `BoundBroadcastV2` RPC payloads);
   generate FROST Round-1 packages locally; send announcements over remote RPC.
4. Each receiving peer echoes a ceremony-bound SHA-256 digest of the exact observed package; every participant still receives the original public package.
   Inconsistent broadcasts cause abort. Once all echoes are complete, every
   peer creates and exchanges an `Attest` message of the identical transcript.
5. `finalize()` yields `VerifiedTranscript` only when all participants have
   attested to the same transcript. Pass it into `DkgParty::part2`.
6. Encrypt *each* outgoing FROST private Round-2 share for its recipient using
   `seal_dkg_round_two`, send via `send_protocol_message`, and decrypt only in
   the intended native receiver with `open_dkg_round_two`.
7. Finish DKG via `part3_with_evidence`, attest to the derived full public-key package, activate the group, persist secret shares only in a secure key store, approve signing
   intent, then run threshold signing with independent output verification.

Public DHT transcript checkpoints are audit artifacts, **not network-wide
finality, consensus, or trusted certificates.** Detailed API guidance and
security limitations: [docs/SECURITY_PROTOCOL.md](docs/SECURITY_PROTOCOL.md).

## Outstanding production blockers

Compilation and runtime tests have not been executed here. Production still
needs hardware/OS-backed master key provisioning, rollback-resistant durable state,
portable signed provenance, actual three-conductor/native controller integration,
real crash/partition and Byzantine tests, key possession challenges, external
security review and trusted application-level approval UX.
FROST provides threshold signatures, **not arbitrary MPC computation**, and
none of these facilities solve double spending or offline settlement.
