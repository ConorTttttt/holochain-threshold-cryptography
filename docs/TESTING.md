# Build and test instructions (not executed in this environment)

This source release has been checked for TOML/YAML syntax, file path references,
manifest structure and archive integrity. Rust compilation, Holochain host
execution and all integration tests remain **unverified** because the authoring
environment has no Rust, Nix or `hc` toolchain.

## Reproducible commands

```bash
# On a machine with Nix installed, within the repository root:
nix develop
cargo test -p holochain-mpc-core
RUSTFLAGS='--cfg getrandom_backend="custom"' \
  cargo build --release --target wasm32-unknown-unknown \
  -p mpc_integrity -p mpc
hc app pack workdir --recursive
cargo test -p mpc --test mpc_network -- --nocapture
```

Alternatively use `npm run build:happ`, `npm run test:sweettest`, or `npm test`.

## v0.2 test matrix

| Case | Covered in source | Executed |
| --- | --- | --- |
| Three conductors and DHT proposal propagation | yes | no |
| All three members independently accept | yes | no |
| Result reports observed readiness | yes | no |
| Assigned grant remote transport | yes | no |
| Round 2 arrives before round 1 | yes | no |
| Sequential retry returns `AlreadyStored` | yes | no |
| Bob's private inbox invisible to Charlie | yes | no |
| Public result commitment propagated | yes | no |
| Malicious envelope sender on remote call | core unit test; not end-to-end | no |
| Nonmember assigned capability denied | pending end-to-end | no |
| Conductor crash/restart with inbox retrieval | pending | no |
| Network partition and reconnection | pending | no |
| Concurrent duplicate receive race | known limitation, not a safety guarantee | no |
| Cryptographic protocol correctness | not in scope until v0.3 | n/a |

## Release gate

Do not mark v0.2 operationally complete until Rust checks pass on real Holonix
0.7, the three-conductor test runs, nonmember capability denial is confirmed,
and crash/restart/partition tests are added and pass. The code is a concrete
source implementation of the adapter, not an audited runtime release.

## v0.3 native FROST suite (new; not executed in authoring environment)

```bash
cargo test -p holochain-mpc-frost-ed25519 --test three_agents -- --nocapture
npm run test:native
```

Native source test scenarios:

- Three independently generated dealerless DKG parties agree on one public key
- Two parties sign a session-and-application-bound Ed25519 FROST operation
- Crypto verification rejects modified message, key, and Holochain proposal
- DKG refuses conflicting public-round-one attestations
- Envelope rejects forged caller provenance and modified payload / round
- Signing-package swapping consumes the secret nonce; replay sign fails

These simulate Holochain envelopes only, not real host-side secure broadcast or
three live conductors running the native FROST runtime. Holochain integration
and security gates remain open as listed in `docs/ROADMAP.md`.


## v0.3.1 additions (source tests; not executed here)

```bash
cargo test -p holochain-mpc-security --test security_protocol -- --nocapture
cargo test -p holochain-mpc-frost-ed25519 --test three_agents -- --nocapture
npm run test:native
```

The native tests model authenticated provenance but are not live three-
conductor FROST controller integration. They exercise unanimous echo
forwarding, missing peers, equivocation, conflicting attestations, encrypted
DKG Round-2 shares, wrong crypto public key, tampering and nonce/replay
rejection. Sweettest's three-conductor scenario now includes author-signed
public encryption-key registration and discovery.

**Open gates:** compile tests and WASM, real capability denial, actual
controller↔conductor integration, crash/restart/partitions, transactional
message side effects, native key storage and audit.

## v0.3.2 source test additions (unexecuted)

```bash
npm run test:runtime
npm run test:policy
npm run test:frost
npm run build:happ && npm run test:sweettest
```

`test:runtime` checks SQLite replay and conflict detection, transaction
rollback, once-only signing nonce slots across database reopen, deadline abort
and encrypted key-share recovery. `test:policy` checks group unanimity, signer
approval and pinned key epochs. The FROST native suite includes controlled
signing with persisted nonce slots and authenticated share attribution.
The Holochain Sweettest source has additional append-only public key-epoch
registrations and author-linked activation/approval records.

A three-conductor end-to-end **cryptographic** flow, process-kill tests,
physical storage rollback resilience and portable signature proofs remain
not implemented; see `docs/V032_SECURITY_DESIGN.md`.
