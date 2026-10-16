## v0.3.3 — DKG research upgrade (source-only; not compiled)

- Compact, ceremony-bound echo digests reduce the byte cost of FROST Round-1 consistent-broadcast forwarding.
- Fail-closed broadcast guarantee declaration; no unsupported asynchronous Byzantine reliable-broadcast promise.
- Explicit broadcast-v2 binding to exact proposal action; legacy unbound replay refused.
- Verifier-gated reconstruction from authenticated events rather than authoritative serialized checkpoints.
- `part3_with_evidence` binds locally derived full FROST PublicKeyPackage to the Round-1 transcript before unanimous group activation.
- Native adversarial tests drafted; build, actual transport wiring and crash/recovery tests remain open. See `V033_DKG_RESEARCH_UPGRADE.md`.

# Roadmap and release verification gates

## v0.1 — protocol independent primitive
- [x] Portable SessionSpec/Envelope types; digest and replay helper

## v0.2 — Holochain coordination (source implementation)
- [x] Holochain 0.7 coordinator/integrity zomes
- [x] Session proposals/acceptances, assigned grants, private inbox, public result commitment
- [x] Three-conductor Sweettest source
- [ ] Verify compilation and run Holochain Sweettest on a supported machine
- [ ] Prove nonmember denial, crash/restart, network partition, concurrent send behavior
- [ ] Secure capability provisioning and transactional message effects

## v0.3 — FROST Ed25519 (source implementation)
- [x] Pinned ZF `frost-ed25519 =3.0.0` native crypto provider
- [x] Participant-specific dealerless DKG part1/part2/part3 state machines
- [x] Authenticated-identity identifier mapping, bound native wire protocol
- [x] Explicit DKG transcript agreement gate, documented reliable-broadcast requirement
- [x] Unique operation bound signing, one-shot nonce consumption, aggregate/verify
- [x] Native isolated 3-agent simulation including 2-of-3 signing and negative cases
- [ ] Run native test suite with Cargo, fix all compiler/runtime issues
- [ ] End-to-end 3-conductor/native sidecar orchestration and audited secure broadcast
- [ ] Durable keystore/key recovery, atomic replay cursor, malicious-peer and crash testing
- [ ] Audit cryptographic integration before production use

## v0.4 — other crypto and application integrations
- [ ] Native multi-device runtime controller with secure key storage and approval UI
- [ ] Pluggable ECDSA/generic private-MPC/ZK protocols
- [ ] Payments, identity recovery, governance with domain-specific consensus and safety

**Release status:** The v0.3 source is drafted; no compiler/test confirmation
from this authoring environment. It must not be called an operational release.

## v0.3.2 — Reliability/security source implementation (not yet compiled)
- [x] New native `mpc-runtime` crate: SQLite WAL/full-sync, atomic authenticated receipt+DB effects, duplicate/conflicting-slot rejection.
- [x] Durable one-time nonce reservations and public-commitment write-ahead burn records; no nonce rehydration after a crash.
- [x] Encrypted write-once key-share persistence with XChaCha20Poly1305 and external master-key injection.
- [x] Persisted round deadlines, abort journal and permanent nonce burns, with caller-provided trusted time.
- [x] Generic group activation and authorised signing-intent tokens bound to session, key epoch, verifier package, selected roster.
- [x] Native `ControlledSigner`, which checks activation, approvals, persist-before-publish nonce slots and round deadlines.
- [x] Authenticated attribution of aggregate signature shares, no payload-claimed identifier trust.
- [x] Append-only public Holochain key-epoch records, group activation and signing-approval attestations.
- [x] Native and Sweettest *source tests* for new interfaces; not executed by this environment.
- [ ] Run Cargo/Holochain compile and both full native and Sweettest suites; address failures.
- [ ] Implement native-controller service wired to three live Holochain conductors; execute real FROST DKG/signing over Holochain transport.
- [ ] Provision protected OS/Lair master keys, install anti-rollback controls and reliable backups/restore.
- [ ] Portable signed broadcast evidence, full key-possession challenges, adversarial partitions and process-kill testing.
- [ ] Independent audit before use with real-value assets or long-term cryptographic identities.

## v0.3.8 — Independently launchable local service (candidate)
- [x] Standalone `mpc-node` executable for independently provisioned per-ceremony controller processes, with 0700 private directories and 0600 key and socket access.
- [x] Reuse authenticated HMAC IPC and encrypted, non-resumable DKG journal; fail closed on wrong key, replay and used proposal.
- [x] Add source tests for independent local services, key isolation and permanent restart refusal.
- [ ] Compile and execute the new native process tests on Holonix.
- [ ] Implement conductor-backed bridge that verifies app WebSocket authentication, Holochain action authorship and signed inbox origin before forwarding to worker.
- [ ] Integrate secure OS/Lair-backed key provisioning, durable completed FROST key packages and global anti-rollback.
- [ ] Verify three real machine/VM deployments and isolated 2-of-3 signing.
