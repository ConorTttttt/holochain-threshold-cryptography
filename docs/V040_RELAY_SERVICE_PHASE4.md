# v0.4.0 Phase 4 candidate — independently launchable relay supervisor and Unix signer IPC

This is **not yet a verified production MPC node**, multi-machine deployment, Lair signer, or persistent FROST secret-key store. The implementation has not been compiled or run in the authoring container. Run the Holonix commands below before treating this increment as tested.

## What was added

- `mpc-relay-service`: a separate daemon-like process running one ceremony on one node; it connects to an already-running `mpc-node` Unix service in a private node state directory. It checks the local app-interface token, pinned app/agent/DNA, ceremony JSON and available signer socket **before** initiating the native worker's DKG.
- `relay_supervisor.rs`: bounded polling, per-RPC deadlines, SIGINT/SIGTERM interruption and fail-closed exit. A relay with an uncertain publish, delayed signed RPC, missed quorum, received equivocation, or interruption **must use a fresh Holochain proposal and DKG randomness**. Do **not** retry an old ceremony by deleting SQLite markers.
- `socket_signer.rs`: client-side, length-prefixed JSON protocol to a separately provisioned signer over a Unix socket (owned 0700 directory, mode 0600 socket, same-UID Linux `SO_PEERCRED`). A fresh `ZomeCallParamsSigned` must be produced for **every** RPC, using the local Holochain agent's authorised signing authority and nonce/expiry enforcement at the conductor.
- Actual signed `register_encryption_key` RPC added to the allowlist. At ceremony start, the local worker's newly generated **public** X25519 transport key is author-signed onto its local conductor's source chain. Before Round 2, the worker independently checks the author/action/key records of every participant. The Phase 3 simulation now performs this registration instead of inventing the roster.
- `test:relay-supervisor`, `test:signer-socket`, `test:relay-phase4`, and `build:relay-service` scripts.

## Critical preconditions

1. A real **local Holochain 0.7.1** conductor app interface, installed app, fully accepted DKG proposal, and recipient capability grants already exist. A valid local app authentication token must be stored in a private `0600` file. The app WebSocket is limited to a trusted **loopback** interface; token authentication is not remote-server authentication.
2. Run `mpc-node serve --state-dir ...` using a **fresh**, provisioned `0700` state directory (see `docs/V038_INDEPENDENT_NODE_SERVICE.md`). The node retains its encrypted journal across process exits. Never delete or reuse the journal to bypass an aborted proposal.
3. The external **signer server is NOT included**. It must already be running and independently authorised by the operator to sign MPC calls, and must enforce the pinned agent, app, DNA, proposal, recipient grants, nonce freshness, expiry and user policy. Merely returning correctly shaped bytes or listening on a private socket does **not** prove proper signature authorisation.
4. Store the validated FROST `Binding` JSON as an owner-controlled regular `0600` file, e.g. `binding.json`. This is a JSON serialization of the `holochain_mpc_frost_ed25519::Binding` with `proposal_action` and `spec`, and must match the provisioned node. Binding includes agent roster, threshold and `session_id`.
5. The signer must know the recipient capability secret for outgoing `send_protocol_message`; the relay never generates one. The local source chain must have fully accepted the proposal before `register_encryption_key` can succeed.

## Signer socket protocol (schema version 1)

The daemon opens a **new Unix stream connection per request**. Both directions use a four-byte big-endian unsigned length followed by one UTF-8 JSON object. Maximum request is 384 KiB; maximum response is 512 KiB; deadline 15 seconds. The parent directory must be `0700` and socket `0600`, owned by the same uid as the daemon.

Request:

```json
{
  "version": 1,
  "operation": "get_inbox",
  "binding": {
    "installed_app_id": "your-app-id", "role": "mpc",
    "dna_hash": [0], "agent": [0], "proposal_action": [0],
    "session_id": [0], "channel_id": [0]
  },
  "envelope": null,
  "public_key": null
}
```

**This is illustrative only**: each hash/agent is actually 39 bytes and each session/channel ID is 32 bytes. `operation` is exactly one of `get_inbox`, `get_encryption_key_bindings`, `register_encryption_key`, `send_protocol_message`. A registration request supplies `public_key` as a 32-byte JSON array, while a send request supplies the exact `Envelope` in `envelope`. The signer must sign the corresponding ZomeCallParams, with fresh random nonce and expiry; the Holochain conductor verifies the cryptographic signature. The client rejects a signed response whose actual signed parameters do not match the operation, the pinned node, proposal, or worker-produced public key/envelope.

Response:

```json
{"version":1,"signed":{ "bytes":"<use ZomeCallParamsSigned's serde encoding>", "signature":"<Holochain signature encoding>" }}
```

The response illustration is **not** a tested canonical JSON representation: use the actual `serde_json::to_vec` serialization of Holochain 0.7.1 `ZomeCallParamsSigned` from Rust. Do not hand-construct a JSON signature from these placeholders. The provided signer tests use structurally valid **dummy** signatures strictly for offline policy tests; they are not capable of authenticating to a real conductor.

## Build and smoke tests

```bash
npm run check:holochain-versions
python3 scripts/check_release.py
npm run test:relay-supervisor
npm run test:signer-socket
npm run test:relay-unit
npm run test:signed-call-policy
npm run build:relay-service
npm run test:native
npm run test:sweettest
```

## Running the daemon (only after the external signer is implemented)

```bash
cargo run -p holochain-mpc-dkg-worker --features conductor-client --bin mpc-relay-service -- \
  --state-dir /absolute/private/node-state \
  --binding-file /absolute/private/binding.json \
  --app-socket 127.0.0.1:YOUR_APP_PORT \
  --origin http://localhost:YOUR_CONFIGURED_ORIGIN_PORT \
  --app-token-file /absolute/private/app-token \
  --installed-app-id YOUR_INSTALLED_APP_ID \
  --dna-hex YOUR_DNA_HASH_39_BYTES_HEX \
  --signer-socket /absolute/private/signer-dir/agent.sock \
  --poll-ms 500 --max-polls 600
```

This process does not create proposals, recipient cap grants, signer keys, authentication tokens or the `mpc-node` service. Its SIGINT/SIGTERM handler aborts an in-flight DKG; it intentionally does not auto-resume it. After DKG completes, the FROST `KeyPackage` remains memory-only in the worker and **does not survive its process exit**. This is not yet suitable for durable MPC signing.

## Remaining security/operational work

- Implement and test an actual Lair-backed local signing service that enforces independent authorisation. This patch provides a **protocol client**, not the server or key-management integration.
- Integration test independent Holochain app WebSockets and a real signer, including capability-grant lifecycle and registration record consistency; the current live conductor bridge integration still uses a harness.
- Prevent compromised/rolled-back databases and key theft with independent secure storage and key custody. The local Unix same-uid boundary is insufficient against an attacker controlling the same uid.
- Add durable reconciliation or a deliberately reviewed restart protocol for ambiguous signed zome RPCs; current behaviour is strict abort, not availability under outages.
- Persist completed FROST key packages safely; prevent nonce reuse during distributed signing; validate actual threshold signatures across separately deployed nodes.
