# v0.3.3 — Research-informed DKG assurance and echo-traffic reduction

Status: **experimental source only**. Rust compilation, Holochain 0.7 conductor integration, adversarial security validation and audit remain outstanding. This design does not implement consensus or Byzantine reliable broadcast.

## Scope and source grounding

- Zcash Foundation FROST [DKG tutorial](https://frost.zfnd.org/tutorial/dkg.html): use a **consistent** authenticated broadcast for *each* participant's Round-1 public package, and an authenticated confidential peer channel for Round-2 shares. A plain fan-out is insufficient.
- Bracha (1987), *Asynchronous Byzantine Agreement Protocols*, [Information and Computation](https://doi.org/10.1016/0890-5401(87)90054-X): distinguish fail-closed consistent dissemination from full Byzantine reliable broadcast/agreement and its resilience assumptions. This release offers **no** f-resilient asynchronous termination guarantee.
- Gennaro, Jarecki, Krawczyk and Rabin (1999), *Secure Distributed Key Generation for Discrete-Log Based Cryptosystems*, [EUROCRYPT](https://doi.org/10.1007/3-540-48910-X_21): public-key validity and distributed contribution verification are DKG security properties. Do not substitute a hash exchange for the FROST DKG package checks.
- Komlo and Goldberg, *FROST: Flexible Round-Optimized Schnorr Threshold Signatures*, SAC 2020, [proceedings](https://doi.org/10.1007/978-3-030-81652-0_2): threshold signatures and preprocessing are separate from key-generation communication guarantees.

## Implemented changes

1. **Compact echo:** `BroadcastMessage::EchoDigest` carries a 32-byte SHA-256 commitment to `(ceremony fingerprint, origin ID, exact Round-1 package bytes)`. `Announce` still sends the original package so the recipient can run FROST's own checks; this is NOT a hash-only key-generation protocol. `Echo` with full package is retained as legacy input but never emitted by the new implementation.
2. **Out-of-order protection:** a digest arriving before the direct package is tentatively stored. The direct package and every echo must agree; conflicts abort. `echoes_complete()` revalidates all hashes. No transcript is released without every member's authenticated attestation.
3. **Strict ceremony binding:** a `BoundBroadcastV2` wrapper contains the exact proposal ActionHash and full ceremony hash, *inside* the Holochain envelope payload. `receive_envelope` rejects legacy unbound payloads and cross-proposal replays, even if session ID and all other `SessionSpec` fields are identical. **Wire-breaking change** relative to older broadcast envelopes; all participants need the upgraded security adapter.
4. **Explicit guarantee profiles:** `BroadcastGuarantee::UnanimousAbort` is the only supported policy. `AsynchronousByzantineReliable` fails at construction, not silently downgrading the caller's security requirement. Unanimous means any withheld contribution prevents completion; timeouts/partitions must fail closed.
5. **Safer recovery boundary:** `EchoBroadcast` is no longer deserializable as an authoritative proof object. A native controller must durably record *authenticated* inbound messages, local announces and attestations, and replay these through state-machine methods. Message authenticity must be independently revalidated when reading a journal or retained as tamper-evident signed receipts. `replay_authenticated_events` now provides a verifier-gated state-machine replayer, but the **durable signed-receipt adapter and process-restart orchestration are not implemented**.
6. **FROST DKG completion evidence:** `DkgParty::part3_with_evidence` requires the same `VerifiedTranscript` used to unlock Round 2 and returns a non-deserializable, privately constructed typed `DkgPublicProposal` derived from the local verified `PublicKeyPackage`. It binds proposal action, session, Round-1 transcript, **full PublicKeyPackage hash** (including verifying shares), and group verifying key. `DkgPublicProposal::group_descriptor()` constructs the proposed `GroupDescriptor` for the already-existing unanimous `GroupActivation` flow. The older `part3` remains available for compatibility, but controllers should use `part3_with_evidence`.
7. **Payload cap:** `MAX_ANNOUNCEMENT` is reduced from 32 KiB to 8 KiB because the current JSON `Vec<u8>` representation expands byte arrays and the core envelope is capped at 64 KiB. This is a deliberate compatibility limit, not a FROST intrinsic limit; change it only after measuring a binary wire codec.

## Complexity and security boundaries

For `n` agents and `m`-byte round-1 packages, the current per-origin echo/fanout pattern produces `n(n−1)²` directed echo deliveries. Full-package echo payload is `n(n−1)²m` bytes; digest echo payload is `n(n−1)² × 32` bytes, *excluding framing/headers*. Example, n=3, m=4096: 12 deliveries, 49,152 raw echo payload bytes reduced to 384. Real FROST Round-1 packages are typically much smaller, so actual savings will vary. The number of messages is **unchanged** and still scales cubically. The DKG announcement phase still sends public packages to each peer.

- **No portable signatures in native echo tokens.** `VerifiedTranscript`, `DkgPublicProposal`, `ActivatedGroup` are **local assertions** from authenticated processing, not network-portable cryptographic certificates. A Holochain RPC caller must be authenticated against the pinned membership. DHT entries alone do not establish consensus.
- **No general f-resilience:** a malicious or unavailable participant can stall or abort a ceremony; do not equate `threshold=2` with a 2-of-3 DKG availability guarantee or Byzantine agreement.
- **No automatic secure restart:** replay only **verified** immutable events, never arbitrary serialized structs; use v0.3.2's transactional journaling as a starting point but add a signed provenance bridge and local durable stage transitions before live controller deployment.
- **No key-share repair, proactive refresh, ROAST or general MPC provider** added here.
- **Public package agreement is not proof of correct computation by an arbitrary remote participant.** Each member MUST independently run FROST part3 and compare / attest to its locally derived `DkgPublicProposal` before activating the group; malicious invalid shares should be treated as attributable aborts only with independently verified evidence.

## Proposed native controller sequence (not yet wired into three conductors)

1. Pin identical `SessionSpec`, Holochain proposal ActionHash and participant-to-FROST identifier mapping. Negotiate `UnanimousAbort` before sending any DKG message.
2. Each local `DkgParty::begin` returns its own secret state and Round-1 public package; `EchoBroadcast::begin` announces the serialization to all peers.
3. Validate remote provenance, exact `BoundBroadcastV2` ceremony, and message sequence; journal the authenticated event before ACK. Send each returned `EchoDigest` to all peers; tolerate reordering.
4. After `echoes_complete`, persist the locally generated transcript hash, send `Attest` and collect all peer attestations; only `finalize()` produces `VerifiedTranscript`.
5. Run `DkgParty::part2` with packages matching that transcript. Encrypt each private Round-2 package separately for its pinned recipient; do not put decrypted shares in Holochain public entries.
6. Run `part3_with_evidence` with confidential packages and the same gate. Every party independently constructs and attests the exact `GroupDescriptor` using `DkgPublicProposal::group_descriptor` and pinned encryption-key-binding action hashes.
7. Persist encrypted secret shares only after a consistent group activation result; never enable signing merely because local part3 returned successfully. Abort and restart incomplete ceremonies with new IDs when recovery is ambiguous.

## Verification checklist

```bash
nix develop
cargo test -p holochain-mpc-security --test security_protocol
cargo test -p holochain-mpc-security --test group_activation
cargo test -p holochain-mpc-frost-ed25519 --test three_agents
cargo test -p holochain-mpc-runtime --test durable
npm run build:happ
npm run test:sweettest
```

New native tests: digest size/traffic estimate, out-of-order conflicting echoes, cross-proposal replay, unsupported asynchronous Byzantine policy, authenticated state reapplication semantics, DKG-derived group descriptors, matching **full** FROST public-key packages. The existing Sweettest does **not** yet execute native cryptography across real conductors; its completion remains a release blocker.
