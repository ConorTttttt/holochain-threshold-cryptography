# v0.4.0 phase 2 candidate: approved, externally signed MPC zome calls

## Scope

This increment adds two pieces to the feature-gated `conductor-client`:

1. `signed_call_policy::validate_signed_call` deserializes the **actual signed bytes** into Holochain 0.7.1 `ZomeCallParams` and checks the exact pinned agent, DNA, cell, coordinator function, and ceremony proposal. It recognizes only `get_inbox`, `get_encryption_key_bindings`, and `send_protocol_message`.
2. `conductor_client::submit_signed_mpc_call` connects to a **loopback** app WebSocket, authenticates with a pre-issued private token, queries `AppInfo` and verifies the exact pinned cell, then submits `AppRequest::CallZome` using the caller-supplied `ZomeCallParamsSigned`. It accepts only correctly typed MPC responses.

An optional `mpc-conductor-call` executable accepts an existing **0600 regular** JSON file containing `ZomeCallParamsSigned`. The JSON is a serialized Rust struct; no default/empty/placeholder signature is accepted as a real Holochain signature. The signer must generate canonical Holochain `ZomeCallParams` serialization, SHA-512 hash, and signature through an authorised Holochain/Lair signing workflow. The conductor verifies the Ed25519 signature, unique nonce, timestamp and capabilities. The app token is a different credential and does **not** sign zome calls.

The helper checks target and request shape but **cannot independently establish provenance** for a key record or an inbox message from arbitrary data. That provenance comes from the trusted local conductor and the zome's authenticated record handling; the existing `ConductorBridge` still validates the messages against the FROST session, deduplicates, and verifies DKG key evidence. Never pass raw unverified messages directly to the worker.

## Controls

- App interface MUST be a numeric loopback address; Origin is restricted to `http://localhost` with optional nonzero port.
- Token and signed-call files MUST be regular files owned by the current user, mode 0600, without symlink or hardlink aliases.
- Signed zome parameters are parsed **from the bytes inside the submitted signed call**, not from independently supplied metadata.
- No arbitrary zome calls, no admin calls, and no in-process Holochain agent secret key.
- Exact proposal hash, cell DNA, agent and function name must match.
- Read-only queries must contain an exact proposal ActionHash and **no capability secret**.
- The send operation enforces local proposal, destination, bounds and sealed Round-2 packets; the coordinator validates all recipient capabilities and its own sender provenance.
- Output must decode into the required inbox, key-binding or receipt type.
- The client does not create or recover persistent signed call nonces; caller must obtain fresh signed calls from the signer on retries.

## Holonix commands

```bash
npm run check:holochain-versions
python3 scripts/check_release.py
npm run test:signed-call-policy
npm run test:conductor-client
npm run build:conductor-connect
npm run build:conductor-call
npm run test:native
npm run test:sweettest
```

Use `mpc-conductor-call` with `--state-dir`, `--app-socket`, `--origin`, `--app-token-file`, `--installed-app-id`, `--dna-hex`, `--role mpc`, `--operation get-inbox|get-encryption-key-bindings|send-protocol-message`, and `--signed-call-file`. **Do not** hand-create fake agent signatures. Save the signer-produced `ZomeCallParamsSigned` serialized as JSON to a private file.

## What this does NOT yet prove

- No production Lair signer integration or lifecycle-managed agent signing client.
- No continuously running conductor relay or automatic delivery loop.
- No crash-safe durable retry-outbox, dedup under non-atomic failure, or re-synchronisation with the local sidecar.
- No remote TLS/peer conductor attestation or real multi-machine deployment.
- No complete external WebSocket integration test: tests currently exercise policy offline; the local conductor handshake and signed calls still need Holonix execution.

This patch is a candidate and **has not been Rust-compiled here**. Keep it on a separate Git branch from any unresolved v0.3.9 and v0.4.0 preflight changes.
