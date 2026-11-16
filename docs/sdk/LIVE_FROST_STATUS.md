# Agent 4 — live FROST SDK ceremony-status read (draft)

**Branch:** `agents/sdk-live-frost-status-20261116` (derived from the validated Sprint 1 integration branch at `899e433d057a4d1a0533e2304a2493edb75ad82f`).

**Status:** SOURCE PATCH / NEGATIVE TESTS ADDED; **RUST BUILD NOT RUN; LIVE CONDUCTOR NOT RUN** in the agent environment. This document is an execution runbook and evidence checklist, **not** a record of a successful end-to-end rehearsal. No production-key or release approval is implied.

## Why a separate signer profile is required

The ordinary FROST DKG signer intentionally refuses `get_session_status`. The existing `mpc-transport-probe-v1` policy is confined to a *different* protocol and cannot act as FROST status authority.

The new explicit profile `mpc-frost-status-read-v1` is selected using `mpc-lair-signer --frost-status-profile` and accepts just the dedicated signer-IPC operation `frost_ceremony_status_v1`. It creates a fresh, 30-second, capability-free Lair-signed call to the existing coordinator `get_session_status` extern, whose **only payload** is the approved proposal ActionHash. It cannot sign approvals, messages, registrations, start DKG, activation or signing. Request `get_session_status` (transport-probe IPC name) remains rejected by this profile; the probe profile rejects `frost_ceremony_status_v1`.

The signer checks exact IPC binding (installed app ID, role, DNA hash, agent, proposal action, session and channel) and accepts a policy only if the complete operator-approved spec passes FROST `Binding::new`, matches the local session and contains the agent. The existing signed-call admission then checks actual **signed bytes**, including cell, provenance, function, no capability secret and exact action payload. The trusted local conductor verifies the Ed25519 signature, expiry and nonce.

The SDK's `NativeCoordinatorBackend::connect` now requires that same **full approved `SessionSpec` as a separate argument**, before any network/signer interaction. It verifies the FROST v1 protocol, session/agent match, context hash, roster and threshold. On the live result, it rejects **any** difference in `SessionSpec` fields, including application namespace and canonical application `context_hash`. `group_status` additionally checks individual acceptances and readiness consistency. Ready means only `ReadyToStart`, **never** Running/Active.

**Trust boundary:** The input policy and spec must be populated from the operator-reviewed, independently authenticated proposal/ceremony record, **not from the status reply itself**. The conductor is a local trusted endpoint; an app token does not authenticate a remote server. No private FROST shares, worker IPC secrets, Lair unlock passphrases, raw signed-call bytes or capability grants enter the SDK.

## Reproducible disposable-conductor rehearsal

Use an ephemeral Linux/Nix workspace and **disposable Holochain 0.7.1 conductors** only. Refer to `docs/V040_LAIR_LIVE_PROBE_PHASE5B.md` for the existing real app-WebSocket interface, token, and operator Lair preparation and `dnas/mpc/zomes/coordinator/mpc/tests/dkg_live.rs` for existing disposable-conductor fixture patterns.

1. Enter the pinned shell and build the integrated app, signer and SDK example:

   ```sh
   nix develop --no-write-lock-file
   export TMPDIR="$(mktemp -d /tmp/sdk-frost-status.XXXXXX)"
   npm run build:happ
   cargo build --locked -p holochain-mpc-dkg-worker --features lair-signer --bin mpc-lair-signer
   cargo build --locked -p holochain-dkg-sdk --features native-holochain --example live_status
   ```

2. Provision **new test identities** in a disposable Holochain 0.7.1 conductor and install the just-built MPC hApp. Start its app interface **on loopback** with a configured local Origin. Store a pre-issued app token in an owned, regular, single-link `0600` file; this read-only example does not use the admin interface. Optionally bring up a second isolated test conductor/cell to exercise shared acceptance observations. Publish a **new FROST v1 SessionProposal** through the test coordinator and independently record its real ActionHash and the whole `SessionSpec` (including `application_id`, `context_hash`, sorted `participants`, `threshold` and `max_round`). Confirm the local test cell's installed app ID, AgentPubKey, DNA hash and proposal/session/channel pin. Never use persistent operator nodes or funds.

3. Create a `status-policy.json` from those approved values (the `binding` schema is the existing `SignerBinding` and `spec` is `SessionSpec`). All hashes, agent IDs, proposal action and DNA are **JSON byte arrays** in the existing Rust serde representation; `session_id`/`channel_id`/`context_hash` are 32-byte arrays. Fields are shown symbolically below and must be replaced with **actual** test data, not fake byte patterns:

   ```json
   {
     "profile": "mpc-frost-status-read-v1",
     "binding": {
       "installed_app_id": "<TEST_INSTALLED_APP_ID>",
       "role": "mpc",
       "dna_hash": "<39-byte JSON array>",
       "agent": "<39-byte JSON array>",
       "proposal_action": "<39-byte JSON array>",
       "session_id": "<32-byte JSON array>",
       "channel_id": "<32-byte JSON array>"
     },
     "spec": {
       "session_id": "<same 32-byte JSON array>",
       "application_id": "<APP_PROTOCOL_NAMESPACE>",
       "protocol_id": "frost-ed25519",
       "protocol_version": 1,
       "context_hash": "<approved 32-byte JSON array>",
       "participants": ["<sorted participant byte arrays>"],
       "threshold": 2,
       "max_round": 6
     }
   }
   ```

   The quoted placeholders above are **not executable**: substitute actual JSON arrays from the test ceremony. The installed Holochain app ID need not equal the application-level SessionSpec namespace, but **each must match its own independently approved value**. Write and restrict the file:

   ```sh
   chmod 600 /absolute/private/status-policy.json
   mkdir -p /absolute/private/status-signer
   chmod 700 /absolute/private/status-signer
   ```

4. Use an **ephemeral test Lair identity which is exactly the installed Holochain cell's agent** (no key export or raw Lair credential import into the SDK). In a separate terminal, start the profile with the private policy and private Unix socket. The signer prompts interactively for a test Lair passphrase; no passphrase or capability goes into CLI args/environment:

   ```sh
   cargo run --locked -p holochain-mpc-dkg-worker --features lair-signer --bin mpc-lair-signer -- \
     --frost-status-profile \
     --policy-file /absolute/private/status-policy.json \
     --signer-socket /absolute/private/status-signer/signer.sock \
     --lair-root /absolute/private/test-lair-root
   ```

5. In another terminal, invoke the **actual SDK backend**. This is not the original `read_status` fixture example:

   ```sh
   cargo run --locked -p holochain-dkg-sdk --features native-holochain --example live_status -- \
     /absolute/private/status-policy.json \
     127.0.0.1:APP_INTERFACE_PORT http://localhost:ALLOWED_ORIGIN_PORT \
     /absolute/private/app-token \
     /absolute/private/status-signer/signer.sock
   ```

   An actual, verified success prints `PASS: live signed FROST coordinator read: state=... accepted=x/y ready_observed=...`. That line is emitted **only** after the authenticated conductor has accepted the signed read and the SDK has decoded and checked the exact approved status. A read returning `ReadyToStart` does not start DKG, create a group, activate anything, or grant signing authority.

6. Perform fail-closed live negatives: wrong installed app ID; wrong DNA/agent/cell role; wrong proposal; modified `spec.application_id`, context hash or participants; a probe-profile signer socket; a DKG signer socket; old coordinator lacking `ready_observed`; malformed response; no app token or socket; and unapproved write intent. Each must fail without success output. Use new disposable sessions/cells to test actual changes; do not change approved runtime files mid-protocol.

## Commands required for build/test evidence

```sh
cargo test --locked -p holochain-mpc-dkg-worker --features lair-signer --lib frost_status_signer::tests
cargo test --locked -p holochain-mpc-dkg-worker --features conductor-client --lib socket_signer::tests
cargo test --locked -p holochain-mpc-dkg-worker --features conductor-client --lib conductor_client::tests
cargo test --locked -p holochain-dkg-sdk --all-targets
cargo test --locked -p holochain-dkg-sdk --features native-holochain --all-targets
cargo check --locked --workspace --all-targets
npm run test:sweettest
```

**Status for all commands above at drafting:** NOT RUN: the agent container has no `cargo`, `rustc`, `nix`, `hc`, locally trusted disposable Holochain conductor or network access to clone/install tooling. The lockfile was adjusted manually using existing versions and still requires `cargo check --locked` (no lock regeneration has occurred). Source/test presence is **not** a compiler pass. Attach exact command, exit code, timestamps, identity-pinned app/cell metadata and redacted conductor log for any future live PASS. Do not expose app tokens, agent keys or private shares in evidence.

## Compatibility and explicit non-goals

- **No coordinator zome, DNA, entry schema, source-chain or message-wire change.** The coordinator already provides `get_session_status(ActionHash) -> SessionStatus`.
- Existing default FROST DKG signer, transport-probe signer and signing-plan signer profiles are unchanged; **only** the new opt-in profile authorises the new IPC operation. Old status clients keep their existing wire behavior.
- The draft SDK `NativeCoordinatorBackend::connect` signature now takes `expected_spec` to avoid silently trusting the live response as its own pin. This is a **source API change** for draft consumers; review before SDK versioning.
- `propose_group`, `get_activated_group`, `propose_signing` and `get_signature` remain explicitly `Unsupported`.
- No automatic ambiguous write retry, local credential export, grant provisioning, DKG initiation, activation or signing has been added.
- The integration owner must review shared signer changes before merging into the Sprint 1 integration branch. No release approval inventories/hashes have been updated.
