# v0.4.0 Phase 3 candidate: ceremony-scoped automatic DKG relay

## Exactly what is implemented

- `relay::RelayEngine` automatically starts a local DKG worker, publishes its Round-1 announcements, polls a trusted authenticated inbox, feeds each new message through authenticated local IPC, publishes resulting echo messages, computes a separate compact-echo quorum gate, sends unanimous transcript attestations, checks unanimous attestations, fetches the *complete* conductor-authenticated encryption-key roster, publishes individually sealed Round-2 shares, and finalizes only after all other members' shares are received.
- Round advancement is **automatic within a bounded `poll_once()`**. The caller schedules subsequent polls (there is **no long-running daemon yet**). `RelayEngine` is generic over the native node and transport so the controller and network can be tested in isolation.
- `signed_relay::SignedAppTransport` is an optional feature-gated concrete transport for the existing authenticated Holochain 0.7.1 app WebSocket. It requests one fresh `ZomeCallParamsSigned` from a caller-provided `FreshMpcSigner` for **every** inbound read, key-roster read and outbound send. `submit_signed_mpc_call` independently pins the app agent and DNA cell on each request. The signer must be authorised and must build the correct `SendMessage` with recipient capability secret; the bridge never stores the agent signing private key.
- `signed_call_policy::validate_signed_envelope` checks that the **actual signed bytes** describe the precise outgoing envelope produced by the MPC worker, preventing substituted recipient, sequence, round or ciphertext.
- `tests/relay_simulation.rs` exercises the automatic transitions of three native FROST controllers and a deterministic in-memory conductor simulation, plus abort-on-uncertain-send and inbox-conflict tests. This simulation is NOT a live Holochain network test. The existing 0.3.9 Sweettest still tests native node processes against actual conductors via the prior relay harness.

## Security invariants

1. `MpcTransport::get_inbox()` and `get_encryption_keys()` must return **only** trusted local zome responses. Do not substitute arbitrary unverified JSON. Authentication of local Holochain app connections does not authenticate an arbitrary external conductor.
2. `start()` permanently consumes the ceremony in the worker. A failure after worker init, a partial/uncertain RPC result, or a crash means **abort and restart under a fresh Holochain proposal and fresh randomness**. No automatic retry of possibly applied calls; never replay signed nonces. The existing encrypted journal blocks unsafe DKG re-entry.
3. Every outbound worker batch must have exactly the expected recipients for initial announcements, attestations, or encrypted shares; each send must return an authenticated, well-formed acknowledged action hash. The transport does not infer success from attempting a call.
4. The relay tracks cumulative logical inbox IDs and rejects conflicting duplicates. For broadcast rounds it maintains an independently computed `EchoBroadcast` state bound to the exact proposal ActionHash; no Round-2 command can be submitted until unanimity is established.
5. The bridge still uses test/native Holochain transport context for `authenticated_sender`. `FreshMpcSigner` is **only an interface**, not a production Lair client or delegated signing capability. An attacker who controls the local conductor, its app interface, the signer, or node credentials is outside this milestone's protections.

## Holonix commands

Apply this patch **on top of Phase 2 with the v0.4.0 conductor-client compile fix**:

```bash
npm run check:holochain-versions
python3 scripts/check_release.py
npm run test:relay-unit
npm run test:relay-signed
npm run test:signed-call-policy
npm run test:conductor-client
npm run build:conductor-call
npm run test:native
npm run test:sweettest
```

## Remaining work (do NOT claim deployed yet)

- Wire an authorised Lair/Holochain signer to `FreshMpcSigner` and implement a standalone polling service with operator-managed credential lifecycle. This implementation does not contain the node's signing key or start a permanent relay daemon.
- Execute a real app-WebSocket integration test using independently launched conductors and signed remote zome calls; the Phase 3 simulation does **not** cover an actual signature or remote Holochain transport.
- Durable atomic outbox or reconciliation for ambiguous RPC responses, IP compromise/rollback resistance, completed-key persistence, crash-safe restart of signing sessions, host-approved authorisation, app capability lifecycle, and operations across independent machines remain outstanding.
- Protocol is **unanimous abort**, not Byzantine reliable broadcast or a liveness-guaranteed coordinator.

This patch was statically checked for manifest/source inventory and patch applicability only; Rust compilation and all new tests must be run on Holonix.
