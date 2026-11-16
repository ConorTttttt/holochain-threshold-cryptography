# DKG SDK developer guide (Sprint 1)

This is an engineering preview, **not** a production custody or security
attestation. The reference baseline is
`feature/v0.4.0-stage2c` / `122679a7239b97584c153d7ed1feecd35b914061`.
Use a feature branch off that checkpoint. The repository's current `main`
does not contain the full Stage 2C worker and release tooling.

## Local development

On Linux x86_64, install Nix with flakes enabled and work from the repo root:

```sh
nix develop --no-write-lock-file
rustc --version
hc --version
cargo fetch --locked
export CARGO_NET_OFFLINE=true
mkdir -p /tmp/dkg-s1
export TMPDIR=/tmp/dkg-s1
python3 -I scripts/check_holochain_versions.py
python3 -I scripts/check_release.py
npm run test:release-tools
cargo check --offline --locked --workspace --all-targets
npm run test:native
```

The flake pins the Holochain 0.7 development shell via `flake.lock`,
with Holochain HDK =0.7.1 and HDI =0.8.1 in `Cargo.toml`. Avoid using the
unversioned Holonix `main` or Holochain client 0.8 for this code.
`flake.nix` supplies PyYAML for the inventory/validator scripts.

For a clean local Holochain integration build:

```sh
npm run build:happ
npm run test:sweettest
```

These create disposable artifacts and local Sweettest conductors. Some tests
use Unix sockets, so use a short `TMPDIR`. A full release validation additionally
rebuilds WASM in a clean target folder and checks approved identities:

```sh
npm run check:release
```

That command is expected to flag Stage 2C coordinator artifact drift until
the reviewed change is approved. Do **not** run `--record` as a workaround.

## SDK package contract

Agent 4 proposes `crates/holochain-dkg-sdk/`. It is not present at the
Stage 2C baseline. When adding it:

- Reuse `mpc-frost-ed25519`, `mpc-security`, `mpc-runtime` and the worker
  coordinator/transport primitives. Do not implement a second FROST protocol.
- Expose typed, application-independent ceremony, activation and signing
  operations. Keep cross-application domain separation and replay protection.
- Model state transitions explicitly: proposed, authorised, active, failed,
  aborted and not-yet-activated are not interchangeable.
- Require participant consent and operator authorisation. A successful local
  DKG share is not proof of global activation.
- Keep secret shares, nonces and credentials inside the existing native
  custody boundary. Do not return secrets through coordinator RPC or SDK
  public result types.
- Reject ambiguous or equivocated protocol slots; do not silently select
  one competing envelope or retry a rejected/ambiguous write automatically.
- Include negative tests (unauthorised calls, replay, wrong context, late
  equivocation, interrupted DKG, activation failure) alongside happy paths.

Add the crate to the root workspace, document its minimum public API and
write `cargo test --offline --locked -p holochain-dkg-sdk --all-targets` tests.
The CI job automatically attempts these tests once the crate manifest exists;
until then its log explicitly says **NOT RUN**.

## Branch and integration discipline

Agent 1 reviews security; Agents 2 and 3 modify native client and lifecycle
behaviour; Agent 4 creates the SDK; Agent 5 owns CI/test docs; Agent 6
integrates reviewed changes. Keep independent branches and provide the
integration agent with: base SHA, commit(s)/patch, changed paths, commands
actually run, exit codes, and outstanding findings.

Do not assume that individually green branches compose. After integration,
rerun affected native/feature tests, coordinator Sweettests, DKG fault
rehearsals in disposable environments, SDK tests and the release gates.
Classify missing reports or toolchain-dependent tests as **NOT RUN**.

`scripts/check_release.py` and `scripts/release_check.py` are deliberate
fail-closed mechanisms:

- `scripts/release_inventory.json` approves workspace members, dependency
  manifests, `Cargo.lock` and shipped binaries.
- `scripts/release_hashes.json` approves integrity/coordinator WASM and
  .dna/.happ bundle identities.
- Changing the workspace for an SDK should trigger inventory review. A
  changed coordinator should trigger artifact-identity review.
- Neither approval file may be rewritten by CI or without explicit
  operator authorisation following source review.

## Safety boundaries

Use ephemeral credentials and temporary Sweettest cells. Do not point
development commands at the persistent operator Holochain conductor, update
coordinators, connect real Lair secrets, or handle funded/significant keys.
CI must never have deployment or long-lived signing credentials.

See `docs/sdk/TESTING.md` for the command matrix, manual release process,
and evidence conventions. The integration ledger is
`docs/sdk/SPRINT1_INTEGRATION_REPORT.md`.
