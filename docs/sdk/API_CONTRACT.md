# Holochain DKG SDK — Public API Contract (initial foundation)

## Scope and status

SDK package: crates/holochain-dkg-sdk/ (v0.1.0 foundation). Existing FROST DKG,
security activation, signer policy, coordinator and native custody remain the
implementation authorities. This package NEVER creates FROST key shares or
directly operates on a node master key.

**Implemented:** typed configuration, participant/ceremony/group/operation IDs,
public group descriptor conversion and validation, strict read-only
group_status through a backend, mock tests, and optional native coordinator
adapter for the existing signed get_session_status zome RPC.

**Not implemented:** propose_group, participant acceptance or approval,
start/retry/abort DKG, public descriptor discovery, get_activated_group,
propose_signing, get_signature, any guarantee of deployment readiness.
Unsupported calls return SdkError::Unsupported. Do not claim these operations
have succeeded or are wired into live worker orchestration.

## Rust contract

~~~rust
let config = SdkConfig::new("org.example.app", local_agent)?;
let sdk = DkgSdk::new(config, authenticated_backend)?;
let observed: CeremonyStatus = sdk.group_status(exact_proposal_action).await?;
// observed.state can be Proposed, AwaitingAcceptance or ReadyToStart;
// NEVER Running/Active from this coordinator read alone.
~~~

An exact CeremonyId is the 39-byte Holochain proposal **ActionHash**.
SessionId is a separate 32-byte value from SessionSpec. ParticipantId is the
39-byte raw Holochain AgentPubKey; its SDK length/nonzero check does not prove
Holochain identity, which MUST originate from authenticated conductor
provenance. GroupId is the domain-separated canonical GroupDescriptor digest,
not an activation certificate. OperationId is a nonzero 32-byte value.

The SDK application namespace is fixed at client construction. Each status
response must have a valid SessionSpec with matching application ID,
frost-ed25519 protocol v1, a listed local participant, valid Holochain-sized
participants, unique in-roster acceptance authors and consistent locally
observed readiness. A malicious or malformed response is rejected, never
normalised into a more advanced state. A real backend MUST verify that
the response comes from the pinned local app, cell, agent, DNA, proposal action
and session ID.

### Lifecycle states

| State | Evidence required | Initial SDK can return? |
| --- | --- | --- |
| Proposed | Coordinator reports valid session and no accepted authors | Yes |
| AwaitingAcceptance | Coordinator reports incomplete non-empty acceptance roster | Yes |
| ReadyToStart | Coordinator locally observes all participants accepted | Yes |
| Running | Durable native DKG journal and authority to start | No |
| AwaitingActivation | Locally completed share AND pending activation votes | No |
| Active | Independently verified unanimous group activation, exact descriptor and trusted native state | No |
| Aborted | Durable abort journal / terminal native evidence | No |
| Failed | Authoritative native terminal failure evidence | No |

ReadyToStart is an extra state. It deliberately prevents mapping coordinator
ready_observed to Running. Neither local DKG completion nor a public
GroupActivationAttestation alone authorises Active. Participants must explicitly
accept the exact proposal (all N, even for threshold T<N). Activation requires
all N independent matching attestations with authenticated authors as checked
by the existing mpc-security::activation::GroupActivation mechanism.

### Public group metadata

PublicGroupDescriptor::try_from(mpc_security::activation::GroupDescriptor)
validates the native public descriptor (including sorted membership,
threshold, commitments and key-binding action set), the v1 FROST protocol,
39-byte identities and nonzero verifying key. It derives GroupId using the
existing digest implementation. This DOES NOT indicate the group's activation
or safely unlock a secret share. ActivatedGroup is intentionally not publicly
constructible in this release.

### Signing

SigningRequest binds a GroupId, OperationId, raw application message and
selected signer roster. SigningApprovalState distinguishes pending, approved,
rejected and expired. A future signing backend must require an operator-approved
canonical intent and all selected author approvals; it must invoke existing
native nonce burning, FROST signing and signature verification. No application
or TypeScript caller should hold native secret material.

### Errors

SdkError categories: InvalidConfiguration, InvalidIdentifier, InvalidResponse,
NotFound, NotReady, Unauthorized, Conflict, Transport, Backend, Unsupported.
Transport/Backend display is intentionally redacted; do not log private
capabilities, tokens, signed call bytes, messages, journal contents or shares.
A transport error after a write is ambiguous: NEVER automatically retry an
approval, proposal, nonce-consuming operation or rejected write.

## Real native read and FROST status-only policy (Agent 4 continuation)

With feature `native-holochain` on Unix, `NativeCoordinatorBackend::connect`
probes the local signer socket and authenticates/pins the loopback Holochain
app interface before exposing the backend. It now **requires a complete
independently approved SessionSpec**, which must match the local FROST v1
session, agent, context and proposal pin. Do not source this expected spec
from the status result.

Each `group_status` makes exactly one distinct
`SignIntent::ReadFrostCeremonyStatus` request. The SDK signer IPC sends
`frost_ceremony_status_v1` to the new opt-in
`mpc-lair-signer --frost-status-profile` policy; this translates to the
existing conductor `get_session_status` zome read and signed
`MpcCall::GetProbeSessionStatus` wire shape. The old
`SignIntent::ReadProbeSession` retains its existing different signer-IPC
operation. The FROST DKG, transport-probe and signing profiles do not gain
new permissions.

The native backend checks the exact proposal action before signing and
compares the complete returned `SessionSpec` (including `application_id`,
`context_hash`, roster, threshold, protocol and session ID) against the
expected approved one. The facade validates acceptance authors, protocol and
`ready_observed` consistency, mapping full consent only to
`ReadyToStart`. Unexpected/malformed or old coordinator responses are
rejected without compatibility downgrades.

**Validation status:** this is an implementation patch, not an end-to-end PASS.
The agent environment has no Rust toolchain, Nix or live Holochain conductor;
compilation and actual signed-read tests remain NOT RUN. Run the
`examples/live_status.rs` executable with test-only credentials and a
disposable conductor following `docs/sdk/LIVE_FROST_STATUS.md`. The existing
`examples/read_status.rs` remains an offline fixture.

## Future TypeScript ↔ native service boundary

TypeScript will be a **client of a trusted native SDK host**, NOT a new FROST
engine, Holochain signer or browser-side custody provider. Proposed protocol:

- Transport: versioned, bounded authenticated local IPC (Unix socket on
  native Node.js; a separately permissioned host-app bridge for browser UI).
  Never expose existing worker IPC, raw Lair keys or the app auth token to
  web content. Avoid permissive CORS/remote binds. Require local peer
  credentials and an operator-bound application+origin capability.
- Wire schema: JSON with explicit protocol_version, request_id, application_id,
  exact ceremony/action ID and operation discriminator; use strict schemas,
  max-length checks, timeouts, and no unknown security-relevant fields.
  Identifiers are canonical hex-encoded fixed-size bytes. No arbitrary
  zome function, signer policy, cell, transport envelope or worker command
  can be selected by the TypeScript request.
- Initial operations: get_ceremony_status (read-only), future
  get_public_group_descriptor, get_activation_status, get_signing_status.
  Every write (propose, accept, activate, approve, sign) requires a separately
  authorised native operator interaction with exact ceremony, message hash,
  roster, threshold and expiry; a web "approve" field is never consent.
- Response: status uses the lifecycle enum above, accepted roster, threshold,
  observed_at and source="local_coordinator"; activation responses must expose
  a separately evidenced_verified flag rather than reusing ready_observed.
  Errors use stable public categories and redact tokens/private metadata.
- Replay and confinement: contextual request IDs, nonce/deadline and
  exact application/agent/cell/proposal binding. No implicit write retries.
  Separate administrator-granted host app scopes, least authority, and
  never a browser-accessible raw native signing socket.

No TypeScript bridge or protocol version has shipped in this foundation.
