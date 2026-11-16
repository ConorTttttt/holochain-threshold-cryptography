# Sprint 1.8B — INV-13 independent Round-2 key-admission proposal

**Status: DESIGN FOR REVIEW ONLY — NOT APPROVED OR IMPLEMENTED. Live secret-bearing Round 2 remains blocked.**

Baseline: PR #18 `edd7a7757d36da2faca0b566fd850429cce6e10f`. This document is not an operator approval, cryptographic audit, or evidence of a live DKG. The present `ConductorBridge::require_round_two_key_approval` must continue to reject all live sends until a separately approved admission contract has been implemented and tested.

## 1. Explicitly undecided authority (mandatory human gate)

**DECISION INV13-A:** The project operator must designate *who* may authorise a ceremony's exact X25519 registrations, and *how* the native bridge authenticates that authorisation. No authority is implicitly delegated to a participant, the proposal author, a DHT publisher, a local conductor, a developer, CI, or this design. The decision must name the trust anchor, key custody, delegation/revocation policy, and whether multiple approvals are required.

Two candidate mechanisms require explicit selection and threat-model review:

- **Signed, offline-approved roster**: the designated approval principal signs a versioned approval manifest, and a trusted native component validates the signature against an independently provisioned, pinned verification key. The signature algorithm, canonical bytes and key-update procedure are operator decisions, not defaults to silently assume.
- **Trusted local operator provisioning**: a privileged administrator installs a read-only, access-controlled immutable manifest into the native trust boundary; the reviewer must establish that a conductor process, DHT response, ordinary SDK caller or remote peer cannot write or replace it. This does not provide portable, third-party-verifiable signatures and requires separate local deployment evidence.

Neither mechanism is currently authorised. An approval manifest obtained by copying `get_encryption_key_bindings` results into an `approved` parameter is **not independent approval**.

## 2. Exact admission record (proposed `Round2RosterApprovalV1`)

Approval should bind all of the following **together**, under a domain-separated, versioned approval statement:

| Field | Required binding |
| --- | --- |
| Format | Protocol-specific domain tag, schema version and approval identifier; no implicit v0 or legacy fallback |
| Application | Installed Holochain app ID **and** application namespace `SessionSpec.application_id` |
| Cell | Exact DNA hash, zome role and locally pinned Holochain cell / agent identity; no cloned-role substitution |
| Ceremony | Full approved `SessionSpec`: protocol ID/version, `session_id`, `context_hash`, `threshold`, `max_round` and exact sorted participant list |
| Proposal | Real `SessionProposal` `ActionHash`, not merely matching spec bytes |
| Keys | Exactly one tuple `(member AgentPubKey, X25519 public key [32], registration ActionHash [39])` for **every** participant, including self |
| Lifecycle | One-time approval scoped to this proposal and no implicit key rotation, renewal, or cross-ceremony use |
| Authority | Verifiable issuer identity and authorisation evidence chosen in INV13-A; optional counter/expiry only after a credible time/rollback model exists |

A human-readable JSON preview is **not** by itself the cryptographic signing preimage. Decide exact deterministic encoding and domain-separated hash before implementation; include fixed interoperability vectors. Do not silently reuse the wire encoding for a policy signature without reviewing canonicalisation.

## 3. Proposed enforcement order (not yet executable)

1. A privileged host verifies a separately provisioned approval against the authorised trust anchor, and verifies complete app/cell/proposal/SessionSpec binding against the independently pinned connection policy. Do not import a roster from a coordinator response as approval.
2. Retrieve the full set of author-signed key registrations through the authenticated, pinned conductor interface. This is **observation**, not consent or independent key ownership proof. Do not accept partially observed rosters as authorisation.
3. Require exact one-to-one correspondence between approved tuples and observed tuples; reject missing, extra, duplicate-author, duplicate-action, reused-key, forked or newly rotated records. Reject stale/mismatched proposals and any local public key not derived from the currently held native X25519 secret.
4. Inside the trusted native boundary, connect the already present `verify_explicit_key_roster(ceremony, binding, local, approved, observed)` only **after** authority verification and full `ConductorPin` checks. It presently verifies the exact two sets and local derived key, but **does not** verify the human approval itself, Holochain action signatures independently, app ID, or role; those checks must not be omitted.
5. Tie the resulting approved roster to the single `BeginRoundTwo` invocation and the exact `VerifiedTranscript`; prevent a second or stale admission across retries and restarts. Continue to reject ambiguous publications automatically. No code should call `Command::BeginRoundTwo` merely because `pins_from_conductor` succeeded.
6. Once approved, each round-2 sender must encrypt only to the approved recipient key for that same proposal. If an unexpected registration appears later, abort all remaining processing and require a new proposal/approval; already delivered ciphertext cannot be unsent. Do not rely on the DHT proving absence of hidden forks or globally ordered finality.

**Trusted verifier:** a privileged native host/bridge policy-verifier ahead of `ConductorBridge::round_two`, with a checked admission capability or immutable approved digest conveyed over the existing authenticated local IPC to the secret-owning worker. Precisely where authority verification and the consumed admission token live is **DECISION INV13-B**; approval must not be enforced solely in the public SDK, untrusted caller or coordinator zome. Binding a roster via `pins_from_conductor` alone is insufficient.

## 4. Restart, rotation, and fork semantics

**Proposed default for operator approval:** DKG interruption is terminal. No DKG secret package or X25519 secret is reloaded to resume Round 2. Retained approval evidence can support later review but cannot reopen an abandoned proposal or be recycled for a fresh one. Unexpected key rotation (even with the same public key but a different registration ActionHash) and registration forks require failure and a **new** ceremony with independently renewed approval; no silent “latest” selector.

A durable approval record does not by itself prevent rollback of local state. The current custody/rollback boundary needs independent review before any claim of adversarial rollback resistance. **DECISION INV13-C:** define policy persistence, invalidation across restart, and whether a monotonic external anti-replay/rollback anchor is required. Even if operational policy chooses an auditable manifest file, it cannot override the native DKG tombstone.

## 5. Regression and real-conductor evidence required before unblocking

- Approved manifest with tampered signature / unauthorised issuer / missing trust anchor **cannot** authorise Round 2.
- Same observed DHT records, passed to both `observed` and `approved` without independent approval, **cannot** authorise Round 2.
- Wrong installed app, application namespace, DNA, role, cell, local agent, proposal ActionHash, session, context, threshold, protocol version or roster must fail closed.
- Exact roster accepted with shuffled observation ordering **only** when an authentic independent approval is supplied.
- Missing, duplicated, extra/forked registrations and duplicate public keys must fail; unapproved key rotation and action-hash-only changes must fail.
- Local derived secret key must match its approved public key, including after restart.
- Invalid or stale approval across process exit, new proposal or rotated key cannot restore an interrupted DKG.
- A late-discovered fork after earlier observation must abort remaining work; validate the distinction between unknown eventual-consistency state and actual evidence of uniqueness.
- Inject worker/bridge publication failures and hard process stops: no new or repeated Round-2 ciphertext is sent from an uncertain state.
- Real disposable Holochain conductors must exercise authenticated caller provenance and signed registration ActionHashes with the approval delivered **outside** the DHT. Native mocked registration tests are E3/E7, not E5/E6.

Existing `key_pinning.rs` and `round_two_security.rs` demonstrate only parts of this contract at source/native level. They do not satisfy the admission-authority and live-conductor portions. Do not enable live Round 2 on their strength alone.

## 6. Gate decision log

- **INV13-A:** approval principal, verifier trust anchor and provisioning channel — **OPERATOR DECISION REQUIRED**.
- **INV13-B:** native verifier placement, protected approved-digest delivery, exact approval schema and canonical encoding — **SECURITY/ARCHITECTURE APPROVAL REQUIRED**.
- **INV13-C:** restart/rollback, expiry, rotation, revocation and fork handling — **OPERATOR DECISION REQUIRED**.
- **INV13-D:** permission for any wire, native state-schema or release-inventory changes — **OPERATOR APPROVAL REQUIRED**.
- **INV13-E:** independent FROST and Holochain review of code and adversarial E7 evidence — **E8 NOT PERFORMED**.

Until these gates close, retain `INV-13: independently authorised Round-2 encryption-key roster unavailable; live delivery blocked`. **Do not claim E6 distributed DKG**.
