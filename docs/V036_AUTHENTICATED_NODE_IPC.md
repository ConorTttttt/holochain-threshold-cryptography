# v0.3.6 — Test-only authenticated worker/conductor-bridge IPC

## Scope and security boundary

v0.3.6 adds a **MAC-authenticated, bidirectional, ordered local command channel** for the three-process DKG integration test. It is an incremental authentication mechanism, **not a production conductor bridge**. The parent test harness still authenticates Holochain private inbox provenance and key-binding action authors. The worker cannot independently verify those Holochain facts: `authenticated_sender` is a host assertion.

The IPC bootstrapping mechanism (`--test-authenticated-stdio`) transmits a randomly generated 256-bit shared key over the worker's inherited private stdio pipe. An observer of that bootstrap, a compromised parent process, or a same-UID OS attacker who can access the pipes can impersonate a bridge. This is **explicitly test-only key provisioning**. Do not transport production key material with this mode. The legacy unauthenticated `--unsafe-test-stdio` executable mode is removed to prevent accidental downgrade.

## Implemented checks

- HMAC-SHA256 with independent direction labels for host-to-worker and worker-to-host. Use `hmac` verification (constant-time tag compare).
- Versioned frames, pinned Holochain 39-byte agent identity, exact 39-byte proposal ActionHash, 32-byte session ID and per-worker random channel ID.
- Strict, monotonically increasing per-direction sequence numbers (no retry, reordering or replay within one channel).
- An authenticated `Init` must match the pinned worker identity, proposal and session. Commands before `Init` are rejected.
- Worker aborts irreversibly on failed MAC, malformed input, wrong binding, out-of-order command or failed DKG operation. No weakened fallback from authenticated to plaintext mode.
- `Reply` frames are authenticated as well. The existing three-worker/three-conductor end-to-end test uses the authenticated IPC transport end to end.
- Each DKG worker still keeps private shares and its native encryption key exclusively inside its own process; network Round-2 shares stay end-to-end encrypted.

## Deliberate non-goals

- This is **not** Holochain `AgentPubKey` cryptographic attestation. Real conductor/app-protocol identity must be bound to the channel through a dedicated bridge and signed proof/attestation.
- MACs authenticate the known shared secret, not an arbitrary OS process or human. Parent remains a trusted policy/provenance component.
- No durable anti-replay across process restarts. Worker state is volatile and every interrupted ceremony must abort and use a fresh proposal and new key.
- No master-key provisioning, encrypted DKG checkpoint, crash recovery, cross-host transport, OS keyring, Lair-integration or production isolation guarantee.

## Tests

```sh
npm run check:holochain-versions
python3 scripts/check_release.py
npm run test:ipc
npm run test:ipc-process
npm run test:worker-unit
npm run test:dkg-process
npm run test:native
npm run test:sweettest
```

The new unit tests exercise duplex authenticity, tampering, replay, reordering, cross-ceremony misuse, wrong direction, invalid key provisioning and a wrong-agent `Init`. The real three-conductor DKG integration test now uses authenticated request and response envelopes.

Native compilation and multi-conductor runs were unavailable in the packaging environment; rerun in Holonix.
