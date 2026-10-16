# v0.3.4: Live DKG integration (experimental test milestone)

## Purpose

The v0.3.3 native security and FROST tests and the original three-conductor
coordination Sweettest passed in the developer's Holonix environment (27 tests).
They were separate paths. v0.3.4 joins those paths in a NEW Sweettest scenario:
`dnas/mpc/zomes/coordinator/mpc/tests/dkg_live.rs`.

**The v0.3.4 test has been authored and statically checked, but NOT built or
executed by the authoring environment.** Only the developer's Holonix test
results can confirm whether it compiles and passes.

## DKG ceremony across three real conductors

1. Launch three Sweettest conductors, install a shared Holochain DNA, retrieve
   the real agent identities, and create a FROST 2-of-3 `SessionSpec` with a
   unique Holochain `ActionHash` proposal.
2. All three accept this exact proposal. Each agent creates an assigned inbox
   grant; the test harness provisions recipient capability secrets in memory.
3. Three native `NativeChannelKey` secrets are created. Each conductor registers
   its corresponding public key on its own signed source chain, and every
   observer checks action hash, author identity and exact 32-byte key.
4. Each native controller runs FROST `DkgParty::begin` locally and sends its
   actual Round-1 public package via authenticated, per-recipient Holochain RPC.
5. Each other controller receives that announcement ONLY by querying its local
   private `get_inbox`. It processes `EchoBroadcast::receive_envelope` and sends
   the derived compact echo digests to all participants over Holochain RPC.
6. Echoes from the two other conductors are processed via `get_inbox`. Each
   controller locally checks unanimous agreement, creates a transcript
   attestation and again delivers it through Holochain RPC. Each independently
   obtains `VerifiedTranscript` via `finalize`.
7. Each controller runs `DkgParty::part2` with packages reconstructed from its
   own verified transcript. The outgoing recipient-specific FROST Round-2
   packets are encrypted with X25519 + XSalsa20Poly1305 before being handed
   to `send_protocol_message`; only sealed ciphertext reaches the inbox.
8. Each controller queries its own private inbox, attributes incoming packets
   to Holochain-authenticated authors, pins sender encryption keys against
   author-signed actions, decrypts Round-2 packets and calls
   `part3_with_evidence`.
9. The three resulting FROST public key packages and group descriptors must
   match. All three conductors publish activation attestations; each observer
   independently verifies author identity, transcript hash, public-key-package
   hash and descriptor hash before creating a local `ActivatedGroup`.
10. A **separate native-only** 2-of-3 FROST signing smoke test verifies that the
    key produced by the live-DKG ceremony can generate a valid signature.

## Trust boundaries and unimplemented requirements

- Conductor RPC provenance is checked in `receive_protocol_message` through
  `call_info().provenance`; `get_inbox` is a *local* source-chain query. The
  integration test relies on this specific coordinator implementation to
  authenticate `envelope.sender`. Exporting a JSON inbox entry alone does not
  furnish a portable cryptographic signature or receipt.
- The Rust test harness has access to all three native controller instances.
  A production deployment must use independent native processes, isolate
  secrets per peer, and provision capabilities over a secure channel.
- FROST key shares and ephemeral keys reside only in native test memory; this
  test does not exercise the `RuntimeStore` key vault, process restart, OS/Lair
  master-key delivery, anti-rollback mechanisms or nonce WAL. Those remain
  separately tested or unimplemented integration requirements.
- The Holochain DHT carries encryption public keys and author-signed group
  attestation declarations, not public evidence that a native DKG really ran.
- Echo-and-attest is unanimous agreement-or-abort. It does **not** provide
  asynchronous Byzantine reliable broadcast or guaranteed termination under
  malicious withholding or network partitions.
- The native signing smoke test does **not** implement the public signing
  approval workflow through conductors and does not exercise `ControlledSigner`.
- `npm run test:dkg-live` is a **test harness**, not a deployable application.

## Test commands

Run from the root of your existing project, inside `nix develop`:

```bash
npm run check:holochain-versions
python3 scripts/check_release.py
npm run test:security
npm run test:frost
npm run test:policy
npm run test:runtime
npm run test:dkg-live
npm run test:sweettest
```

`test:dkg-live` rebuilds the zomes/hApp and then starts three conductors.
`test:sweettest` repeats both three-agent integration suites sequentially.
The live-DKG test may take multiple minutes because of DHT consistency waits
and many separate remote zome calls. Duration is not a security metric.

## Next production integration milestone

Move each native controller into a separately authenticated, per-agent OS
process/service, connect it to its own conductor, durably authenticate and
transactionally consume inbound events, securely provision/grant capabilities,
retain encrypted FROST private state, fault-inject restarts and partitions,
and require a production-grade secure key provisioning model and external audit.
