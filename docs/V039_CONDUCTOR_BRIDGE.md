# v0.3.9: Conductor-facing bridge and independently launched node integration

## What is implemented

This increment joins two previously tested components in an end-to-end Holochain
Sweettest: (1) three separately provisioned `mpc-node` OS services, each with
its own `0700` directory, HMAC key and encrypted SQLite DKG journal, and (2)
three Holochain 0.7.1 conductors transporting FROST DKG messages.

`ConductorBridge` connects over a local `0600` Unix socket and pins the local
agent, proposal ActionHash, session and channel against the node's protected
config. IPC commands and replies use v0.3.6's ceremony-bound HMAC and strict
sequence numbers. The bridge performs structural validation on each outgoing
FROST envelope before passing it to `send_protocol_message` on the **sender's**
cell, and on each incoming envelope read from the **recipient's** trusted
`get_inbox` response. It treats duplicate inbox IDs idempotently and rejects
conflicting entries, wrong recipients, wrong sessions, altered payload hashes,
nonmembers and unsealed FROST Round-2 packets. It also checks the exact full
roster of `{action, author, public_key}` records retrieved from
`get_encryption_key_bindings` before advancing to encrypted Round 2.

In the integration test, the native processes **never** receive another node's
private shares. Group public descriptors are compared and participant-authored
activation attestations are checked through Holochain.

## Commands

```sh
npm run check:holochain-versions
python3 scripts/check_release.py
npm run test:bridge-unit
npm run test:node-service
npm run test:conductor-bridge # builds zomes and starts 3 Sweettest conductors
npm run test:native
npm run test:sweettest        # also runs earlier DKG integration tests
```

## Trust boundaries and non-goals

- **Not a production conductor client.** The external Holochain app interface
  connection, app-interface token authentication, source-chain author validation,
  independent replay-safe retrieval of actual authored actions and privileged
  connector lifecycle are still performed by **Sweettest**. The `ConductorBridge`
  API accepts decoded results supplied by that trusted host. It cannot tell a
  dishonest host's fabricated inbox entry from a genuine local conductor result.
- This is **not proof of verified author signatures at the Rust IPC boundary**.
  `Envelope.payload_hash` is a digest, not an authenticator. The Holochain zome's
  remote-call provenance checks provide the verified sender used by its local
  inbox, but only when the bridge caller honestly supplies that zome response.
- `ipc.key` and `storage.key` remain local permissioned development files,
  **not Lair/TPM/HSM-backed secrets**. Same-user compromise permits key theft.
- Temporary filesystem directories, app installation and three conductor
  processes are managed by one test harness. **Multi-machine independent
  operation has not been demonstrated**.
- Worker crash recovery still requires a **fresh proposal**. Neither finished
  FROST secret KeyPackages nor protected signing state are persisted. The
  resulting public group descriptor is not proof of signing availability.
- No network-partition/fault-injection tests, rollback-resistant storage,
  independent-conductor-WebSocket client, or multi-machine deployment yet.
- The full unanimous DKG still fails closed if any required participant is
  unavailable or equivocates; this does not create Byzantine reliable broadcast.

## Next implementation

Introduce a dedicated conductor WebSocket client whose authenticated app token,
cell selection, public-key and action provenance are checked before allowing
commands on each node's local socket. Run one such client per node without a
central test orchestrator. Only then proceed to independently deployed 2-of-3
FROST signing and completed key-package storage/recovery design.
