# Rust SDK Design — Stage 2C foundation

## Existing architecture and why this SDK is thin

The Stage 2C branch already has:
- coordinator get_session_status (spec, accepted, ready_observed);
- signed_call_policy::MpcCall::GetProbeSessionStatus and the exact-pinned,
  authenticated conductor_client::submit_signed_mpc_call decoder;
- signed_relay::SignIntent::ReadProbeSession and UnixMpcSigner;
- mpc-security::activation::GroupDescriptor / GroupActivation;
- mpc-dkg-worker's durable node journal, share custody and signing path.

The SDK reuses these, with no FROST round code, envelope codec or generic
RPC-to-arbitrary-function escape hatch. Its default build is a small facade
over holochain-mpc-core and holochain-mpc-security. Optional
native-holochain enables the existing worker's conductor client and the
local signer socket; the app must still provision and authorise those.

## Layering

~~~text
Rust application
  DkgSdk<B: DkgBackend>
    SdkConfig + typed IDs + public descriptor converter
    group_status()  --> validate spec/identity/accepted/observed state
    proposal/sign/activation --> explicit Unsupported
                   |
                   v
 DkgBackend::get_session_status(proposal_action)
    |                                |
    v                                v
 fixture/mocks            NativeCoordinatorBackend (opt-in)
                            UnixMpcSigner [fresh signed read]
                              |
                            existing signed conductor client
                              |
                            local MPC coordinator get_session_status
~~~

There is no direct SDK→worker key-share access. Conductor status alone cannot
attest a native process is running, that a share is durably persisted, or
that group activation is unanimous and verified. PublicGroupDescriptor
conversion is intentionally a separate pure function; its source must be a
trusted native descriptor and it is never returned as an ActivatedGroup.

### API extension policy

When the lifecycle and signer integration work lands, extend DkgBackend with
narrow methods for verified native journal states and activation verification
(instead of generic call_zome or worker IPC pass-through). Use
mpc-security::activation::GroupActivation on authenticated per-member records,
not an unverified DHT count. Inactive locally-completed groups must not be
reported as Active, and no group activation should release key shares without
a native verified certificate and operator authorisation.

Before implementing propose_group:
1. Generate unique session ID and application-context commitment in trusted
   native controller; validate sorted, unique and exact 39-byte membership.
2. Obtain separately operator-authorised signed coordinator proposal call.
3. Require each listed agent's exact-action acceptance, including non-signers.
4. Orchestrate durable DKG through existing worker; preserve F1/F2 abort and
   partial-completion guards. Never hide or auto-retry ambiguous writes.
5. Explicitly gate activation on matching all-member attestations and local
   trustworthy custody / anti-rollback evidence.

Before implementing propose_signing/get_signature:
- bind GroupId + exact canonical intent hash + operation ID + selected signers,
  run native approval and single-use nonce lifecycle, verify aggregate
  signature and return only public artifact. Don't send plaintext to the DHT.
- reject replay across applications/groups and all policy substitution.

## Test matrix and local build

Files:
- crates/holochain-dkg-sdk/Cargo.toml
- crates/holochain-dkg-sdk/src/lib.rs
- crates/holochain-dkg-sdk/src/native.rs
- crates/holochain-dkg-sdk/examples/read_status.rs

Mock tests exercise proposed/partial/full acceptance, forged and inconsistent
rosters, protocol/application mismatch, backend authorisation failure,
identifier/agent pin checks, descriptor validation, and fail-closed unsupported
operations. Example is **fixture only**, clearly not a live conductor demo.

Once the integration agent has added workspace membership and refreshed
Cargo.lock:

~~~sh
cargo test -p holochain-dkg-sdk
cargo test -p holochain-dkg-sdk --features native-holochain
cargo run -p holochain-dkg-sdk --example read_status
~~~

No live FROST integration test or authenticated conductor deployment is
included. A successful Rust unit test must not be called proof of activation,
live conductor auth, or production key custody.

## Required integration-agent patch (intentionally not made here)

Add "crates/holochain-dkg-sdk" to root Cargo.toml [workspace].members, then
regenerate Cargo.lock with cargo under the pinned toolchain. Add the SDK to
release/source inventories only after independent review; no inventory or
WASM identity hashes should be silently edited.

Separately coordinate with the native signer owner to make a **read-only**
get_session_status intent available under an explicitly authorised FROST
ceremony policy. Preserve proposal, local-agent, cell, application, DNA,
protocol, session and operator-policy checks. Do NOT relabel a DKG signer as
a transport-probe signer or broaden a signing profile's write authorisations.

The crate was prepared without changing root workspace, coordinator, worker,
security or release-owned files. Build verification must be performed by the
integration agent in a full checkout with the pinned Rust toolchain.
