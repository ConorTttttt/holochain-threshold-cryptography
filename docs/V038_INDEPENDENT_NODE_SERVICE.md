# v0.3.8 — Standalone MPC node service (first increment)

This release implements a **separate, independently launchable local native DKG service** (`mpc-node`) while preserving the v0.3.7 Holochain three-conductor tests. The service is experimental and **not production ready**.

## What is implemented

- Linux/Unix process service (`mpc-node serve`) with a Unix-domain socket (`controller.sock`) in an operator-owned `0700` directory. Each run accepts **one authenticated controller connection**. Socket is `0600`.
- `mpc-node provision` generates separate CSPRNG-derived 256-bit keys for IPC authentication and encrypted DKG checkpoint storage. Keys are in `0600` files, not in argv or environment variables; private configuration files must have owner-only permissions. A state directory can only be provisioned once via that command.
- HMAC-SHA256 frame authentication, direction, ceremony binding and monotonically increasing frame sequences reuse the v0.3.6 `AuthChannel`. A forged or malformed command aborts the controller; the v0.3.7 journal stores the durable tombstone.
- `mpc-node` reads its pinned Holochain agent, proposal action, session and random IPC channel from `node.json`. The existing FROST `DkgParty` stays in one node process and is never serialized.
- A process-level Rust integration test starts two **separate OS processes**, verifies a valid local DKG Init on the first, rejects a cross-node forged Init on the second, and rejects process restarts of the used proposals.
- No DNA entry types or network messages change. Existing three-conductor and three-worker tests remain as regression coverage.

## Setup in Holonix

```sh
# Build the two native binaries and run the new tests:
cargo build -p holochain-mpc-dkg-worker --bins
npm run test:node
npm run test:node-service
npm run test:native
npm run test:sweettest
```

For manual provision, obtain the **verified, exact raw 39-byte** Holochain `AgentPubKey` and `ActionHash` from the conductor and the 32-byte `session_id` from the validated proposal. Convert these *public bytes* to hex (78, 78 and 64 characters respectively). Never use a guessed hash, a test fixture or an unverified front-end assertion.

```sh
# Each node uses a DIFFERENT directory, owner identity and authentication key.
# The directory must not exist and its parent should be private to the owner.
./target/debug/mpc-node provision /absolute/private/node-a \
  <agent-39-byte-hex> <proposal-39-byte-hex> <session-32-byte-hex>
./target/debug/mpc-node serve /absolute/private/node-a
```

A locally trusted controller/bridge reads `node.json` and its **own** matching `ipc.key`, then sends newline-delimited `AuthFrame<Command>` values over `controller.sock`. The node returns newline-delimited `AuthFrame<Reply>` values. The trust assumption for the bridge is unchanged: it must verify the Holochain authenticated sender, proposal authorship, and encryption-key binding before forwarding events. There is **no conductor WebSocket client in this binary yet**.

The state directory contains `node.json`, `ipc.key`, `storage.key`, `journal.sqlite`, and a transient `controller.sock`. Neither the key files nor SQLite databases should be committed to Git or copied between identities. For a *new* proposal after a crash, create a different directory and supply the new signed proposal action. Retain old journals as permanent tombstones.

## Boundaries and unimplemented guarantees

1. **Not yet multi-machine Holochain integration.** The new service can run separately, but its socket client is still a trusted *local* bridge; it does not connect to an app WebSocket, verify Lair signing credentials, or independently authenticate Holochain provenance. The already passing three-conductor tests still use the earlier test-only controller/harness path.
2. **Key files are OS-permission protected, not Lair/HSM-backed.** Another process running as the same Unix account or a compromised administrator can read them. Multi-user deployment must isolate accounts and provisioning. Future work should use keystore/keyring integration and OS-backed anti-rollback.
3. **No completed key recovery or cross-process signing.** The completed FROST key package is volatile and lost when the node exits. Crash recovery is an abort, never an unsafe attempt to rebuild the secret. Signing across independently deployed nodes is not yet implemented.
4. **Rollback remains possible** if an attacker restores an older directory/database snapshot or reprovisions the same Holochain proposal into another directory. This local journal alone does not provide global proposal uniqueness or trusted monotonic state.
5. **No general-purpose production daemon controls.** No systemd unit, resource-limiting, structured metrics, max-session scheduling, multi-client access or remote administration. Unix file-mode restrictions protect from different unprivileged UIDs, not compromise by same-UID processes.
6. Unix socket messages are bounded to 512 KiB. A malicious local client can deny service; this is deliberate fail-closed behaviour and should be paired with a trusted bridge.

## Next increment

Implement a separate conductor-connected controller with Lair-backed call authorisation and independently verified Holochain incoming message origins. Then test three `mpc-node` instances with three **independent conductor processes**, and persist completed group key packages under reviewed lifecycle rules before implementing 2-of-3 distributed signing.
