# v0.3.1 security protocol: integration contract

This package is **experimental uncompiled source**, not a deployed or audited
Byzantine-tolerant MPC network. This is a reusable security adapter layer;
FROST is its first cryptographic user.

## Scope and state machine

`holochain-mpc-security::{Ceremony, EchoBroadcast, BroadcastMessage,
VerifiedTranscript}` implements a **unanimous fail-closed** echo-broadcast
handshake. `Ceremony` includes the precise accepted Holochain proposal's 39
raw ActionHash bytes and complete `SessionSpec`. Every inbound call MUST get
its authenticated sender from `call_info()?.provenance` in the coordinator;
pass that to `EchoBroadcast::receive`. Never trust the `Envelope.sender` alone.

1. **ANNOUNCE**: Each of N original senders directly sends its FROST DKG Round-1
   package to every other member (call `begin` locally for itself). The payload
   must be the exact `serde_json::to_vec(&round_one_package)` bytes.
2. **ECHO**: After receiving each sender's original package directly, every
   receiver calls `receive(authenticated_origin, Announce { package })`, then
   sends the returned `Echo { origin, package }` unchanged to all other members.
   Each recipient collects echoes under each *authenticated forwarder* identity.
3. **CONSISTENCY**: For each origin, the local state requires a directly
   authenticated original plus the exact same package bytes acknowledged by
   **all N** participants. Contradictory direct/echo packages abort; missing
   evidence blocks progress. Both the source and its participants may withhold
   messages: liveness is not guaranteed under faults/partitions.
4. **ATTEST**: When `echoes_complete()` returns true, call `attest()` and send
   the result to all peers. `EchoBroadcast::finalize()` requires all N distinct,
   authenticated attestation identities and the same transcript digest.
   Early attestations are buffered and compared after local computation.
5. **ROUND-2 GATE**: Pass the returned `VerifiedTranscript` to the native FROST
   provider's `DkgParty::part2(&package_map, &verified_transcript)` method. The
   provider compares the full actual package bytes, session spec, and proposal
   against the verified transcript. The old untrusted digest-map input is gone.

**Important:** `VerifiedTranscript` is local state evidence. It is not an
exportable cryptographic certificate that a remote party can trust without
checking authenticated events and/or signatures. Holochain private inboxes are
event journals, not a globally ordered consensus log. A malicious member can
force abort; unanimity deliberately prioritizes safety over availability.

## Event delivery and persistence

A transport/controller maps `Announce` and `Echo` into unique sequence numbers
in Holochain protocol round 1, and `Attest` into round 2. It distributes them
using assigned-capability `call_remote` calls with acknowledged delivery,
persisting event envelopes before acknowledgement. Retry with the **same**
round/sequence and payload. Do not let the UI supply an arbitrary claimed
sender or automatically execute cryptographic side effects from an inbox.

Recover state by replaying an authenticated, ordered event journal through
`EchoBroadcast::receive`. The state struct is Serde-serializable for trusted
local persistence only. A hostile serialized state or journal can fabricate
local protocol completion; storage authentication and rollback resistance
must be supplied by the host. Existing v0.2 Holochain inbox writes can race
under concurrent calls; a transactional native journal is still required for
exactly-once irreversible cryptographic operations.

## Authenticated, recipient-specific confidential shares

- Generate one native `NativeChannelKey` (X25519 secret), or integrate a secure
  Lair/OS-backed service. Publish only its public key via the new Holochain
  `register_encryption_key` function. Each public `EncryptionKeyBinding`
  source-chain action is authenticated by the committing agent.
- **Pin the exact entry ActionHash, author and public key** for each intended
  member. The system intentionally offers no implicit "latest key" selection
  on the eventually consistent DHT. A key-registration action does not prove
  private-key possession or secure storage; establish that separately.
- After the broadcast gate passes, `seal_dkg_round_two` encrypts a FROST
  `DkgRound2` frame into `SealedPacket` using RustCrypto `SalsaBox`
  (X25519 + XSalsa20Poly1305). Sender public key, destination public key,
  random 24-byte nonce and ciphertext appear on the wire. The encrypted
  plaintext **contains the full ceremony fingerprint, sender, recipient,
  round, sequence and data**, which are compared on decrypt. XSalsa20Poly1305
  has no external AAD in this construction, so these fields MUST be checked
  after successful authenticated decryption.
- The generic HDK RPC `send_protocol_message` stores only a serialized
  `SealedPacket` in FROST protocol **round 3** (`DkgRound2` in the FROST
  provider). Cleartext/private shares fail this zome's structural guard.
  That guard cannot cryptographically prove ciphertext authenticity; the
  recipient must call `open_dkg_round_two` using independently pinned sender
  key data and trusted transport caller identity.
- A recipient never exposes the recovered DKG share to DHT. Native memory is
  not automatically a secure key store: the sample key is deliberately
  **ephemeral and not persisted or recoverable**.

Holochain HDK 0.7 also provides `create_x25519_keypair()` and
`x_25519_x_salsa20_poly1305_encrypt/decrypt` via Lair. Those can support a
future alternative adapter; do not implicitly treat the test's native key as
a Lair key or send plaintext secret shares through zome WASM.

## Optional public checkpoint

After local successful echo completion, a member may call
`publish_transcript_checkpoint(proposal, transcript_hash)`. These public,
immutable entries are signed by their author and discoverable through
`get_transcript_checkpoints`. **Never infer protocol completion from mere DHT
entry presence**. A malicious member can publish a false digest or multiple
digests; DHT propagation can lag or partition.

## Tests and hardening tasks

Native `security_protocol.rs`: unanimous success, real echo forwarding,
equivocation, incomplete echoes, conflicting attestations, unauthorised
senders, serializable state recovery, encryption/decryption, tampering,
context swapping, incorrect pinned keys and logical replay. Native FROST
`three_agents.rs`: genuine DKG, echo gate, encrypted per-recipient Round-2
packages and 2-of-3 signature verification. The Holochain Sweettest file
covers public key registration in three conductors.

**Not yet verified:** Cargo compilation, these tests' execution, conductor
crash/restart/partition recovery, concurrent replay transactions, DoS limits,
cryptographic key erasure, certificate/key rotation, client-side grants,
network-level protocol scheduling, production app consent, malicious native
runtime, formal protocol security or professional audit.

## DNA upgrade compatibility

Adding public entry/link types changes the DNA hash, even though new variants
have been appended to preserve the earlier type ordering. This is a **new
network/installed DNA**, not an in-place upgrade of a running v0.2/v0.3
network. Plan export/import or parallel operation for existing users.
