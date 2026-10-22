# v0.4.0 phase 1 — authenticated local app WebSocket preflight

**Status: candidate, not yet Rust-compiled in the assistant environment.**

This is the **first increment** of the v0.4.0 standalone conductor client. It is **not** the complete independent conductor relay or 2-of-3 remote signing milestone. v0.3.9's zomes, DKG envelopes, encrypted journals and tests remain unchanged.

## Why this is separate from the v0.3.9 test bridge

v0.3.9 successfully carries messages via Sweettest's trusted in-process conductor API. It does not authenticate an external app WebSocket. The new opt-in `mpc-conductor-connect` executable connects to an already-running **loopback** Holochain 0.7.1 app interface using an **operator-issued app authentication token**. It asks the actual app interface for `AppInfo` and refuses to proceed unless the installed app ID, provisioned MPC role, agent and DNA hash exactly match its configuration. The node's pinned agent identity is read from the existing private `node.json` directory.

The integration uses **exact `holochain_websocket = 0.7.1` and `holochain_conductor_api = 0.7.1`** behind `--features conductor-client`. The Holochain 0.7 compatibility table specifies Rust client 0.9.x; we deliberately avoid the 0.8.x client, which targets Holochain 0.6. The built-in 0.7.1 WebSocket primitives require a receiver task to dispatch RPC replies.

## Checks

`connection_policy.rs` rejects wrong app IDs, agent keys, DNA hashes, missing/duplicate roles, incorrectly bound cells and remote/unparseable addresses. `conductor_client.rs` refuses unsafe authentication token files (symlinks, hardlinks, non-0600 mode, wrong owner, empty/oversized token), authenticates using `AppWebsocket` and verifies the actual installed app and cell identities. It never contacts the admin interface or issues new credentials.

These restrictions matter because an app token **authenticates the client to the conductor, not the conductor to the client**. Loopback pinning reduces network token exposure, but does not protect against a malicious local OS account, administrator or spoofed app interface. Use a conductor you administrate. No TLS/pinning of remote servers or hardware-backed secrets is implemented.

## Holonix commands

Starting from your successfully applied v0.3.9 plus the small `let mut worker` fix, apply the v0.4.0 patch. Run:

```sh
npm run check:holochain-versions
python3 scripts/check_release.py
npm run test:conductor-pin
npm run test:conductor-client
npm run build:conductor-connect
npm run test:native
npm run test:sweettest
```

The `test:conductor-client` command checks only local token-file validation, not a live conductor handshake. You must run the executable against a real local app interface with a securely issued app token to validate the live handshake.

Example after you have provisioned a node directory, installed the app and **securely** written the binary authentication token to a private mode-0600 file:

```sh
cargo run -p holochain-mpc-dkg-worker --features conductor-client \
  --bin mpc-conductor-connect -- \
  --state-dir /absolute/private/node-a \
  --app-socket 127.0.0.1:12345 \
  --origin http://localhost:3000 \
  --app-token-file /absolute/private/auth.token \
  --installed-app-id YOUR_INSTALLED_APP_ID \
  --role mpc \
  --dna-hex YOUR_39_BYTE_DNA_HASH_AS_78_HEX_DIGITS
```

Both the node directory and token must already exist. Use the exact permitted `Origin` for your app interface; it is not an authentication secret. The command does not provision an agent, conductor or token, and will fail if the role, agent or DNA hash differs from the response returned by the authenticated app interface.

## Explicit non-goals / future phases

- The executable currently performs **read-only** authenticated app-info discovery and exits. It does **not yet** invoke `get_inbox` / `send_protocol_message` through the socket or forward messages to `mpc-node`.
- Zome calls will need Lair- or otherwise securely managed **agent signing credentials and capability grants**; app authentication alone does not authorize signed zome calls.
- AppInfo is an API response, not independent proof of source-chain provenance. The conductor and local operating environment remain trusted.
- A real multi-machine deployment needs independent bridges, network routing, rollback-resistant journal operation, confidential signer provisioning, and crash/fault-injection tests.
- Do not deploy valuable MPC keys with this experimental component.

## Baseline

The v0.3.9 code passed the new 3-node/3-conductor integration test on Holonix. Other v0.3.9 tests may still be under validation by the project operator, and this candidate must not be described as having passed the full v0.3.9 suite or as a completed v0.4.0 milestone.
