> **v0.3.1 override:** `DkgParty::part2` now takes `&VerifiedTranscript`
> from `holochain_mpc_security::EchoBroadcast::finalize()`, **not** a map
> of caller-supplied round-one digest attestations. The Round-2 frame MUST
> be transferred as a sealed packet via `seal_dkg_round_two` and decrypted
> via `open_dkg_round_two`. See [SECURITY_PROTOCOL.md](SECURITY_PROTOCOL.md)
> for the canonical integration contract. Historical v0.3 examples below
> referring to the old digest-map API are superseded.

# v0.3 native FROST Ed25519 provider — implementer guide

**Security status:** Experimental, source-checked only. `frost-ed25519 =3.0.0`
implements the cryptographic primitives; this integration has not been audited
or compiled in the authoring environment. No payment or production credentials.

## How the components fit

```
Application / native controller  (each user's device)
  ├─ accepted Holochain proposal; consent and UI authorization
  ├─ private FROST runtime: DkgParty / Signer / aggregate / verify_artifact
  │      ↕ Frame { proposal_action, operation_id, Message }
  ├─ Holochain Envelope transport and local private message journal
  │      ↕ call_remote + restricted capability grant
  └─ Holochain DHT: public proposal, acceptances, unverified result commitment
```

No FROST code runs in an HDK coordinator or integrity WASM callback. DKG
secret packages, KeyPackages, ephemeral signing nonces and signing consent
remain local to the native controller. `SignedArtifact` and public keys are
safe to share, but need an application-anchored trusted group key.

## Session configuration and round mapping

Use `SessionSpec` with:

- `protocol_id = "frost-ed25519"`, `protocol_version = 1`, `max_round >= 6`.
- `threshold >= 2`, `threshold <= participants.len()`; identifiers are derived
  from sorted 39-byte `AgentPubKey`s as FROST identifiers `1..=n`.
- Set a **fresh random** `session_id` and a distinct `context_hash` for the
  application operation or group key policy.
- Accept `SessionProposal` on every member before delivering messages.
- Bind native `Binding` to **the real 39-byte proposal action hash**. Never
  synthesize an action hash in production. Supply actual `AgentPubKey` raw 39s.

| Envelope round | `Message` | Delivery | Ceremony |
|---|---|---|---|
| 1 | `DkgRound1` | Consistent authenticated broadcast, NOT simply N unicast calls | `session_id` |
| 2 | `DkgRound1Digest` | Authenticated consensus/checkpoint of the *same* complete commitment list | `session_id` |
| 3 | `DkgRound2` | Authenticated confidential unicast to each recipient | `session_id` |
| 4 | `SigningCommitment` | Authenticated unicast to signing coordinator | unique operation ID |
| 5 | `SigningPackage` | Authenticated unicast to each selected signer | unique operation ID |
| 6 | `SignatureShare` | Authenticated unicast to coordinator | unique operation ID |

`Frame::encode` produces a valid v0.2 `Envelope` body (`Vec<u8>`). To send,
pass the resulting `envelope.payload` to `send_protocol_message` with the
same round and sequence; the zome builds/authenticates the outer envelope.
To receive, get the recipient's logical inbox with `get_inbox`, then feed
*previously authenticated* envelopes into `Frame::decode`. The originating
remote zome's `call_info()?.provenance` is the trusted sender. **Do not blindly
pass a user-supplied `envelope.sender` as the authenticated sender!**

A host must validate the signed proposal, session status and inbox provenance
before invoking the native provider. The shipped example simulates identities
and transport with `Frame::encode` and `Frame::decode`; it does NOT exercise a
running Holochain conductor with FROST inside its transport loop.

## DKG — one group without trusted dealer

Each participant, on its own machine:

1. Calls `DkgParty::begin(binding, local_agent_id)`; broadcasts its public
   `DkgRound1` package to every other member over *consistent broadcast*.
2. Collects an authenticated, unique round-one package from each agent,
   including its own. Computes `round_one_digest` over the canonical ordered
   list. Broadcasts its digest via `DkgRound1Digest`.
3. Checks authenticated equal digests for **all** participants and aborts on
   any conflicting commitment, missing digest or timeout. The native
   `DkgParty::part2` enforces an equal set of digests, but **the host must
   implement the consistent-broadcast primitive and assure identity and
   availability of signed attestations**. A list of equal hashes is NOT a
   proof of Byzantine reliable broadcast or equivocation resistance by itself.
4. Calls `DkgParty::part2`, then sends only the *recipient's* DKG round-two
   package as a private point-to-point message. **Never publish DKG round-two
   packages**; possession can compromise key secrecy.
5. Collects each other sender's private round-two package (authenticated sender
   ID maps to FROST ID). Calls `DkgParty::part3`. Keep the private `KeyPackage`
   in a secure keystore and agree on the same `PublicKeyPackage` and group key.

A genuine reliable-broadcast / authenticated-consistency implementation remains
an integration blocker before production DKG over adversarial networks.
A Holochain DHT cannot be assumed to supply instant finality or atomic
agreement during a partition; don't use 'observed all peers' as finality.

## Signing — threshold subset, separate authorization

1. The application chooses a **fresh, unique** `operation_id` for this signing
   request and the complete, human-reviewable message. Users approve intent.
2. Every selected signer calls `Signer::commit(operation_id, message)`,
   generating **new** secret nonces and a public signing commitment.
3. The coordinator collects at least `threshold` authenticated commitments,
   builds `signing_package(...)`, and sends it to the selected signers.
4. Each signer displays the operation intent and uses `Signer::sign` exactly
   once. It checks the signing package binds the proposal, session,
   `context_hash`, operation ID and entire message; it also checks its own
   commitment is unchanged. `Signer::sign` takes and destroys its active nonce
   even on failure. Do **not** retry after an uncertain outcome; restart with
   an entirely NEW `operation_id` and fresh nonces.
5. Coordinator collects the shares mapped to *authenticated* FROST ids, calls
   `aggregate`, then calls `verify_artifact` with an independently authenticated
   group key. The returned `SignedArtifact` can be serialized and committed to
   the existing `publish_result_commitment` API, but the v0.2 DHT entry itself
   is still merely an unverified commitment.

**Crash/restart rule:** This source prototype stores signer and DKG state in
process memory only, so a process crash aborts the active ceremony. Re-run
DKG if it has not completed, or restart the signing operation with a new ID
and fresh nonces. There is no automatic recovery or durable keystore in v0.3.

## Native API

```
Binding::new(real_proposal_action_raw39, session_spec)
DkgParty::begin(binding, own_agent) -> (DkgParty, RoundOne)
round_one_digest(binding, all_round_one_packages)
DkgParty::part2(&all_round_one_packages, &authenticated_digests)
DkgParty::part3(&same_round_one_packages, &all_private_incoming)
Signer::new(binding, own_agent, KeyPackage)
Signer::commit(operation_id, application_message)
signing_package(binding, operation_id, application_message, commitments)
Signer::sign(operation_id, &signing_package)
aggregate(binding, operation_id, message, &package, &shares, &PublicKeyPackage)
verify_artifact(binding, message, &artifact, trusted_group_public_key)
```

## Tests / source verification

```bash
nix develop
cargo test -p holochain-mpc-frost-ed25519 --test three_agents -- --nocapture
cargo test -p holochain-mpc-core
npm run build:happ
npm run test:sweettest
```

`three_agents.rs` simulates native isolated participants, uses real FROST
cryptography and Holochain-compatible envelopes, and tests DKG, 2-of-3
signing, context verification, altered data, wrong authenticated sender,
broadcast inconsistency and once-only nonce consumption.

The suite has not been run by the authoring environment (no Rust toolchain).

## Required before production

- End-to-end tests across three *real* Holochain conductors with a native
  controller for **each** agent/device (source suite currently only simulates).
- Implement a proper authenticated consistent-broadcast primitive and
  evaluate Byzantine fault assumptions; do not mistake sequential DHT gossip
  for consensus.
- Confidential capability-secret exchange, durable secure KeyPackage storage,
  process-isolated per-device native secrets, zeroization of host buffers.
- Per-operation policy enforcement, unique operation-id registry, pinning
  of group key material, and nonce-safe crash recovery.
- Transactional processing of inbox replay state, and tests for concurrent
  delivery, malicious shares, corrupted transcript, revocation and partitions.
- Independent security audit and dependency supply-chain review.

Cryptographic references:
- https://frost.zfnd.org/tutorial/dkg.html
- https://frost.zfnd.org/tutorial/signing.html
- https://docs.rs/frost-ed25519/3.0.0/frost_ed25519/
