# SDK testing and release verification

Status: Sprint 1 CI foundation, based on `feature/v0.4.0-stage2c` at
`122679a7239b97584c153d7ed1feecd35b914061`. Commands below are a test
plan, **not claims that the tests passed**. Refer to CI job logs for evidence.

## Environment and lockfiles

Use Linux x86_64 with Nix flakes enabled and enough RAM/disk for Holochain
native builds. The checked-in `flake.lock` pins Holonix's Holochain 0.7 shell;
`flake.nix` supplies Node 24, binaryen, Perl, Python with PyYAML, and Holonix's
Rust/Cargo/`hc` tools. `Cargo.lock` pins Rust dependencies. CI uses
`ubuntu-24.04`; the runner image and unpinned Action tags can still change, so
this is a pinned **dependency environment**, not a bit-for-bit host image.

From the repository root:

```sh
nix develop --no-write-lock-file
rustc --version
cargo --version
hc --version
node --version
cargo fetch --locked
export CARGO_NET_OFFLINE=true
mkdir -p /tmp/dkg-s1
export TMPDIR=/tmp/dkg-s1
```

A short `TMPDIR` matters: Unix-domain socket paths in worker/process tests
can exceed the platform length limit under deeply nested temp directories.
Never replace `Cargo.lock` just to make a build pass.

## Test matrix

Each command is from the root in the environment above. `NOT RUN` is the
correct status until its invocation and exit code appear in a log.

| Layer | Command | CI |
| --- | --- | --- |
| Workspace and all-targets compilation | `cargo check --offline --locked --workspace --all-targets` | PR/native |
| Holochain version pins | `python3 -I scripts/check_holochain_versions.py` | PR/static |
| Approved package and dependency inventory | `python3 -I scripts/check_release.py` | PR/static |
| Release validator unit tests | `npm run test:release-tools` | PR/static |
| Core unit tests | `cargo test --offline --locked -p holochain-mpc-core` | PR/native via `test:native` |
| FROST and three-party signing | `npm run test:frost` | PR/native via `test:native` |
| Security protocol / activation / input validation | `npm run test:security && npm run test:policy && npm run test:input-validation` | PR/native via `test:native` |
| Native runtime durability / DKG journal | `npm run test:runtime && npm run test:dkg-durable` | PR/native via `test:native` |
| Worker IPC, relay, restart, share custody, signing | `npm run test:native` | PR/native |
| Conductor-client optional feature unit tests | `cargo test --offline --locked -p holochain-mpc-dkg-worker --features conductor-client --lib` | PR/native |
| SDK units and API contracts | `cargo test --offline --locked -p holochain-dkg-sdk --all-targets` | PR/native **only if SDK manifest exists** |
| Coordinator native unit tests | `npm run test:coordinator-unit` | PR/native via `test:native` |
| Coordinator, FROST DKG and worker/bridge Sweettests | `npm run test:sweettest` | Push/manual integration |
| Capability revocation Sweettest | `cargo test --offline --locked -p mpc --test revoke_cap_grant -- --nocapture --test-threads=1` | Push/manual integration |
| Fresh WASM build/import rules, pack, artifact identity, binaries, native tests and lockfile | `npm run check:release` | **Manual** release |
| Process-kill / partition / operator workflows | See `scripts/phase6_faults.py` and `docs/V040_PHASE6_FAULT_TESTS.md` | **Not in CI** |

`npm run test:native` and `npm run test:sweettest` originate in `package.json`
and currently omit `--locked` from individual Cargo calls. CI runs them with
`CARGO_NET_OFFLINE=true` after `cargo fetch --locked` and verifies that
`Cargo.lock` remains unchanged. New standalone Cargo commands use both
`--offline` and `--locked`. The SDK crate does **not** exist in this Stage 2C
baseline; report SDK tests as **NOT RUN**, never PASS, until it is added.

The release validation also checks the 13 currently approved binaries and
their `--help`/`-h` notices. Adding a new SDK workspace package, binary or
dependency will intentionally fail `check_release.py` against the approved
inventory until the change is reviewed and expressly approved.

## Running CI

`.github/workflows/ci.yml` runs static and native jobs on PRs; pushing to
`main` or `feature/v0.4.0-stage2c` also starts the slower ephemeral Holochain
integration job. GitHub's **Run workflow** supports `quick`, `integration`,
`release` and `all`. A manual release run performs a fresh offline WASM/DNA/hApp
build and comparison against recorded approved hashes. Its failure is a
**blocking artifact-approval signal**, not something to suppress or auto-fix.
The release logs are uploaded from `target/release-check-logs/`.

Sweettests use temporary conductors and test fixtures. Never configure CI
with live Lair authentication, actual operator capability secrets, persistent
agent databases, or fund-bearing keys. External fault scripts that need
multiple managed conductors, port forwarding or operator sandboxes remain
manual and must use disposable environments.

## Artifact identity approval procedure

Stage 2C previously reported a failing `identity` step because its
coordinator WASM, `.dna` and `.happ` bytes differ from the approved Stage 2B
artifacts. The integrity WASM and DNA hash were reported unchanged.
`scripts/release_hashes.json` must **not** be rewritten by CI.

After independent security and source review, the integration operator must:

1. Build from the exact reviewed commit with the pinned toolchain.
2. Record old and newly measured SHA-256 values and the DNA hash.
3. Explain the changes and obtain explicit operator approval.
4. Only then use the documented, confirmation-gated recording mechanism
   (`python3 -I scripts/release_check.py --record --confirm-record`) from the
   reviewed source and attach its evidence. Recording is NOT a passing
   verification run.
5. Re-run `npm run check:release` *without* recording and require a real PASS.

`scripts/check_release.py --record-inventory --confirm-record` is a **separate
approval** of package manifests/lockfile/binary inventory; use it only after
reviewing intentional SDK and dependency changes. Do not mutate either
approved inventory to satisfy a red CI run.

## Honest evidence reporting

For each test record: full command, exact git commit, runner/tool versions,
exit status, counts where parsed from actual output, and relevant logs. Use
`PASS` only for an executed command with a successful exit, `FAIL` for an
executed failing command, and `NOT RUN` when blocked (including missing tools,
SDK crate, disk capacity, lack of ephemeral conductor, or absent agent patches).
Historical results in `docs/V040_STAGE2C_COORDINATOR_HARDENING.md` are
development history, not evidence of tests on an integrated Sprint 1 tree.

Passing unit tests alone does not establish an audited or releasable SDK.
