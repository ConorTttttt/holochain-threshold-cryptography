# Security properties and limitations — v0.2.0

**Not production ready. Do not process real money, keys, identities or secret
shares with this release.** There is no MPC protocol or independently audited
cryptographic implementation here.

## Implemented in source (not runtime-tested)

1. Public immutable session specifications and participant signed acceptances.
   Session membership is sorted and unique; every ID must decode as a 39-byte
   Holochain AgentPubKey. `threshold` is metadata, not a permission to omit
   other listed members' consent.
2. Caller provenance checked against the claimed envelope sender. Recipient
   must be the actual local agent; sessions are context/protocol version bound.
3. Inbound RPC access uses `CapAccess::Assigned` with a host-generated random
   secret and `GrantedFunctions::Listed` covering only the receiver function.
   No unrestricted RPC grants are installed.
4. Inbound envelope stored as a **private** entry before returning success.
   Logical inbox is sorted/deduplicated by `(sender, round, sequence)` and
   rejects conflicting envelopes using the same ID.
5. Public links verify author/target relationships. Entries cannot be edited
   or deleted via application validation rules.

## Explicitly not secured

- **No protocol confidentiality guarantee.** Private source-chain entries are
  not DHT-public, but they are readable by the local conductor or compromised
  environment, and private actions reveal some metadata. Remote calls are not
  end-to-end application-layer AEAD messages under an MPC-specific key. Never
  send secret shares until the chosen protocol's authenticated encryption
  requirements have been implemented and verified.
- **Capability provisioning is manual.** The demo gives a generated secret to
  its caller, who must provision it securely to the assignees. The program
  does not automatically establish confidential channels or rotate/revoke
  grant secrets. A local `revoke_inbox_grant` endpoint exists; each grant must
  be explicitly revoked by the application/user. Grant tags are informative, not scoped authorization.
- **No exactly-once crypto execution.** The local append-only event journal
  protects sequential retries but cannot atomically enforce uniqueness during
  concurrent receives; no MPC effects are executed. A native transactional
  store or carefully proven alternative is required for nonrepeatable effects.
- **No full crash/partition proof.** Persistence relies on the Holochain
  conductor; Sweettest source covers multi-agent and replay cases but does not
  simulate process failure or network partitions yet.
- **No canonical global readiness.** The `ready_observed` flag is based on
  one node's DHT observations and may change as links arrive.
- **No output correctness validation.** A result hash and attached artifact are
  not a cryptographic proof; the integrity zome checks only bounded metadata,
  session/protocol fields and the author's membership.
- **No authenticated DKG, threshold signatures, secret sharing, zero-knowledge
  proofs, distributed consensus, Byzantine safety or double-spend prevention.**
- **No robust DoS controls.** Payloads and journal sizes have limits but peer
  rate limits, external abuse handling, and source-chain retention policies
  are not implemented.

## Required before v0.3 with secrets

- Complete Holonix compilation and Sweettest runs.
- Add forged caller and capability denial tests on three conductors.
- Complete process crash, restart, connection interruption, concurrency and
  equivocation integration tests.
- Establish authenticated encrypted peer transport suitable for the chosen
  MPC protocol and a protected transactional cryptographic state store.
- Review transcript binding, nonce uniqueness and secret zeroization with
  protocol-specific security expertise.

## v0.3 native FROST provider additions

- Uses pinned `frost-ed25519 =3.0.0`. The cryptographic implementation's own
  audit/history does NOT mean this *integration* has been audited.
- Full DKG private round-two packages can leak secrets; only transfer via
  confidential channels to intended recipients. They persist inside the
  Holochain private inbox unless the application's retention policy removes
  them; a locally compromised node can read them.
- DKG `round_one_digest` and `DkgParty::part2` require all-agent matching
  observations, but do not implement Byzantine reliable broadcast themselves.
- `Signer::sign` consumes nonce on invocation even when validation fails;
  no nonce recovery, no signing after restart. A new operation must use a
  new identifier and new nonces.
- `SignedArtifact` does not authenticate the group public key. Applications
  must pin the group key independently after DKG.
- The external native controller must authenticate inbox message sender,
  preserve operation authorization and enforce once-only application effects.


## v0.3.1 changes (supersede older v0.2 and v0.3 broadcast/confidentiality notes)

The native `mpc-security` crate now has a unanimous authenticated announce,
echo and digest-attestation state machine and a local `VerifiedTranscript`
gate required by FROST DKG `part2`. Native X25519/XSalsa20Poly1305
recipient-specific encryption protects DKG Round-2 payloads from the
Holochain private inbox. The coordinator enforces ciphertext-only *structure*
for FROST provider round 3. Public author-signed encryption key registrations
and optional transcript checkpoint records are available.

These mechanisms do not solve secure capability provisioning, Byzantine
liveness, malicious participant DoS, client-side native/Holochain integration,
secure secret persistence, crash-safe nonce management, or exactly-once
cryptographic execution. Consult `SECURITY_PROTOCOL.md` for the new contract.
