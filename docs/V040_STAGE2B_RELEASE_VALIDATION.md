# v0.4.0 Stage 2B — release validation repaired (I-1, I-2)

27 October 2026 (Europe/London). Done by the coding assistant as the release
integration engineer. **Development evidence on one host, not production
custody, not an independent audit, not a release.** The release checker
passing is not a release decision: R3, R10/R11, F1, F2, V1 and the Agent 7
review remain open.

## Result

**Both findings are fixed, and `npm run check:release` passes (all 11 steps)**
on the Stage 2A integrated source.

- **I-1.** The manifest check now compares the workspace with an explicit
  approved inventory of nine packages: names, paths, versions, dependency
  tables, manifest hashes, `Cargo.lock` and binaries. It accepts the reviewed
  `holochain-mpc-vault` addition and still names any missing, extra, renamed,
  moved or drifted package, and any dependency change.
- **I-2.** `mpc-custody` and `mpc-vault` now print the repository notice and
  "Development build. Not production custody. Do not use with real funds." for
  `--help` and `-h`, and exit 0. `help-notices` now checks every workspace
  binary (13) against an approved binary list, for both flags and the exact
  notice text.
- **Unchanged:** cryptographic, custody, DKG, signing and Holochain behaviour,
  dependencies, the lockfile and the DNA identity.

## Starting point (verified before any change)

| Check | Result |
|---|---|
| Stage 1 `integration-source-manifest.sha256` (183 files) and `integration-manifest.sha256` (186) in `dkg-v040-integration/holochain-mpc-core` | OK. Hashes `3c4bc3c6…` and `c5ef3aef…`, equal to `STAGE2_HANDOVER.md` |
| Stage 2A patch `dkg-v040-stage2a/stage2a-partition-harness.patch` | SHA-256 `9cb6fbee…a062`, as reported in Stage 2A |
| Patch scope | 6 paths: `scripts/{faults_env,faults_scenarios,phase6_faults,faults_portfwd}.py`, `docs/V040_PHASE6_FAULT_TESTS.md` and `docs/V040_STAGE2A_PARTITION_HARNESS_FIX.md`. No product file |
| Application | New copy `dkg-v040-stage2b/holochain-mpc-core` (rsync of the Stage 1 tree, then the Stage 1 manifest verified on the copy). `patch -p1 --dry-run`, then a real apply: exit 0, no fuzz, offset or reject (`logs/stage2a-apply.log`) |
| Result equals the Stage 2A tree | All 190 files equal `dkg-v040-stage2a/evidence/stage2a-tree-manifest.sha256`. `diff -rq` against Stage 1 lists only the 6 Stage 2A paths |
| Build cache | Stage 1 `target/` copied with rsync (`target/tmp` excluded). `target/debug` binaries equal the integrated set |
| Stage 2A suite reproduced | Yes, on the Stage 2B binaries; see "Stage 2A coverage" |

## Root cause of I-1

`scripts/check_release.py` hard-coded the package set:

```python
expected = {'holochain-mpc-core', …, 'mpc', 'mpc_integrity'}   # 8 names
if set(packages) != expected:
    errors.append(f'wrong package inventory: {packages}')
```

Agent 5 added `crates/mpc-vault` (`holochain-mpc-vault`) to the workspace, which
makes nine packages, so the check failed. Reproduced in
`logs/reproduce-I1-I2.log`: `FAIL: wrong package inventory: […, 'holochain-mpc-vault', …]`.

The check also had blind spots. It saw only package *names*, so it missed any
version, path, dependency or lockfile change. Its failure message did not say
which package was wrong.

The vault addition is legitimate. Against the `b96ffdf` baseline, the integrated
`Cargo.toml` differs only by the `"crates/mpc-vault"` member. `Cargo.lock`
differs only by the 18-line `holochain-mpc-vault` entry: no registry package
added or changed (Stage 1 inventory, re-checked here with `diff`). The other 8
member manifests are byte-identical to the baseline.

## Root cause of I-2

The notice is printed by `holochain_mpc_dkg_worker::notice::exit_on_help`. Only
the worker's 11 `[[bin]]` targets call it. `mpc-custody`
(`crates/mpc-runtime/src/bin/`, an auto-discovered binary) and `mpc-vault` are in
crates that do not depend on the worker, and neither handled `--help`: both
printed usage to stderr and exited 1 (`logs/reproduce-I1-I2.log`).
`release_check.py` built only the worker and read the binary list from the
worker's `Cargo.toml`, so it never saw the two binaries.

Other shipped binaries. The workspace builds exactly 13 `bin` targets
(`cargo metadata`). The 11 worker binaries already carried the notice; only these
two were missing it. The examples (`opaque_roundtrip`, `phase5c_live_writes`) are
not shipped binaries. The operator scripts are not binaries and were not changed.
Several have no notice (for example `scripts/phase5b_preflight.py` and
`scripts/phase5c_b_audit.sh`), which is reported below as an observation.

## Changes

| File | Change |
|---|---|
| `scripts/check_release.py` | Refactored into functions. Compares the tree with `scripts/release_inventory.json` and reports each discrepancy by name. `--record-inventory --confirm-record` re-records it (an operator action after review; refused without `--confirm-record`). `--root DIR` checks another tree. The existing YAML/JSON checks are kept. The source-file list is kept and extended with the custody, fault-harness, vault and Stage 2B files |
| `scripts/release_inventory.json` *(new)* | The approved inventory: ordered members, `default-members`, resolver, `[workspace.dependencies]`; per package its path, version, every dependency table (target-specific included) and its `Cargo.toml` SHA-256; the `Cargo.lock` SHA-256 and all 861 `name version` entries; the 13 shipped binaries with their package, build features and `custody_warning` |
| `scripts/release_check.py` | New `validator-tests` step. `help-notices` lists every workspace `bin` target with `cargo metadata --offline --locked --no-deps`, fails on any binary missing from, added to or moved within the inventory, builds every package that ships one, and runs each with `--help` **and** `-h`. Each must exit 0 and print the exact `NOTICE` parsed from `notice.rs`; `custody_warning` binaries must also print the custody line. Pure helpers for the tests. The unused `tomllib` import was removed |
| `scripts/tests/__init__.py`, `test_check_release.py`, `test_release_check.py` *(new)* | 19 validator tests (below) |
| `crates/mpc-runtime/src/bin/mpc-custody.rs` | `--help`/`-h` as the first argument prints `mpc-custody`, the notice (a word-for-word copy), the custody line and the usage, then exits 0 before any file access. `USAGE` became `pub` inside the private `cli` module. No other line changed |
| `crates/mpc-vault/src/main.rs` | The same for `mpc-vault` (custody line plus "Devnet only."), before any config, key or network access |
| `crates/mpc-runtime/tests/cli_notice.rs`, `crates/mpc-vault/tests/cli_notice.rs` *(new)* | 2 + 2 regression tests |
| `package.json` | New `test:cli-notices`, appended to `test:native`, so `check:release` runs it. New `test:release-tools` |
| `docs/V040_RELEASE_HARDENING.md` | Step table and notice paragraph updated |
| `docs/V040_STAGE2B_RELEASE_VALIDATION.md` *(new)* | This report |

Not changed: any `Cargo.toml`, `Cargo.lock`, the toolchain, `release_hashes.json`,
any product library code, the zomes, `notice.rs`, examples or formatting.

The notice is copied, not shared, because a dependency from `mpc-runtime` or
`mpc-vault` on the worker would change `Cargo.lock`. Instead, the release check
parses the canonical text from `notice.rs` and requires it in every binary's
output, and `test_cli_copies_are_word_for_word_the_canonical_notice` compares
the two source copies with it. Drift therefore fails both.

## Tests and outcomes

All commands ran in `dkg-v040-stage2b/holochain-mpc-core` through
`../run_tests.sh` (offline, `TMPDIR=/tmp/v040s2b`, logs in `../logs/tests/`). They
ran with `CARGO_BUILD_JOBS=4` inside `systemd-run --user --scope -p MemoryMax=16G`
to bound host memory (12 GB for the fault suite).

| Command | Exit | Result |
|---|---|---|
| Stage 1 `check_release.py` on the Stage 1 tree (reproduction) | 1 | `wrong package inventory` (I-1) |
| Stage 1 `mpc-custody`/`mpc-vault` `--help`, `-h` (reproduction) | 1 ×4 | no notice (I-2) |
| `npm run test:release-tools` | 0 | **19 tests OK** |
| `python3 -I scripts/check_release.py` | 0 | `PASS: 9 Cargo packages match the approved inventory; …` |
| `npm run test:cli-notices` | 0 | 4 passed (2 `mpc-custody`, 2 `mpc-vault`) |
| **`npm run check:release`** | **0** | **`RESULT: PASS`**, 11/11 steps (table below) |
| `cargo build --offline --locked --workspace --all-targets --features holochain-mpc-dkg-worker/lair-signer` | 0 | builds |
| `cargo build --offline --locked -p holochain-mpc-dkg-worker --features lair-signer,conductor-client --bins` | 0 | builds |
| `cargo test --offline --locked -p holochain-mpc-vault` | 0 | **45 passed** (43 + 2 new) |
| `cargo test --offline --locked -p holochain-mpc-runtime` | 0 | **23 passed** (21 + 2 new) |
| `npm run test:share-custody` | 0 | 10 passed |
| `npm run check:holochain-versions` | 0 | PASS |
| `npm run check:wasm-imports` | 0 | `mpc.wasm` 48 and `mpc_integrity.wasm` 11 Holochain 0.7.1 host functions only |
| `python3 -I scripts/phase6_faults.py --list` / `--self-check` | 0 / 0 | 19 scenarios; rootless netns available |
| `python3 -I scripts/phase6_faults.py --suite --with-control --jobs 2` | 0 | 19/19 as documented: 13 PASS, 6 FINDING |
| `sha256sum Cargo.lock` before and after every step | — | `34f5cd14…2ede8`, unchanged and equal to Stage 1 |

`npm run check:release` (final run on the final tree, `logs/check-release-final.log`):

```
validator-tests  PASS  19 release-validator tests
manifest         PASS  (9 Cargo packages match the approved inventory)
versions         PASS
wasm-build       PASS  fresh target dir, offline, locked
wasm-imports     PASS  mpc_integrity.wasm imports 11 Holochain 0.7.1 host functions only
pack             PASS  dna hash uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu
identity         PASS  WASM, .dna, .happ and DNA hash match the recorded values
help-notices     PASS  13 approved binaries, none extra; all print the notice for --help and -h and exit 0; 2 also print the custody warning
native           PASS  21 commands, 22 result groups: 146 passed, 0 failed, 0 ignored
lockfile         PASS  Cargo.lock unchanged by the run
RESULT: PASS (development evidence only, not a security audit or build attestation)
```

Native is 146: Stage 1's 142 plus the 4 CLI tests.

## Evidence: the nine-package inventory is validated, not bypassed

The 19 validator tests each copy the tree, change one thing and run the checker:

| Test | Change | Reported (exit 1 unless noted) |
|---|---|---|
| approved workspace | none | exit 0, `PASS: 9 Cargo packages match the approved inventory` |
| inventory content | — | the 9 names and paths, and the member order, are exactly the approved list |
| missing package | `crates/mpc-vault` removed from `members` | `missing approved package: holochain-mpc-vault (crates/mpc-vault)`, `workspace members differ` |
| removed package | directory deleted | `workspace path missing: crates/mpc-vault`, `missing approved package: …` |
| unexpected package | new `crates/mpc-extra` member | `unexpected workspace package: holochain-mpc-extra (crates/mpc-extra)` |
| renamed package | `holochain-mpc-vault` → `holochain-mpc-safe` | `renamed package at crates/mpc-vault: approved holochain-mpc-vault, found holochain-mpc-safe` |
| dependency change | `serde_json "1.0"` → `"1.0.200"`, plus `hex` added | `[dependencies] serde_json changed: approved "1.0", found "1.0.200"`, `unapproved dependency hex = "0.4"` |
| workspace pin | `hdk "=0.7.1"` → `"=0.7.2"` | `[workspace.dependencies] hdk changed: …` |
| version | vault `0.1.0` → `0.2.0` | `version '0.2.0', approved '0.1.0'` |
| other manifest drift | vault `edition` changed | `crates/mpc-vault/Cargo.toml changed (manifest drift outside version and dependencies)` |
| lockfile | `bs58 0.5.1` → `0.5.0` in `Cargo.lock` | `Cargo.lock differs from the approved lockfile: added bs58 0.5.0; removed bs58 0.5.1` |
| inventory missing | file deleted | `cannot read scripts/release_inventory.json` (fails closed) |
| recording | `--record-inventory` without confirmation | refused, file unchanged |

## Evidence: the CLI warnings are present

The output of `target/debug/mpc-custody --help` is shown below; both binaries'
full output is in `logs/help-mpc-custody.txt` and `logs/help-mpc-vault.txt`.

```
mpc-custody

NOT PRODUCTION SOFTWARE. EXPERIMENTAL, UNAUDITED DEVELOPMENT SOURCE.
Do not use it with real keys, funds, identities or secret shares. Custody is
development-grade and no independent audit has been done (see SECURITY.md).

Development build. Not production custody. Do not use with real funds.

usage:
  mpc-custody verify <state-dir> …
```

`mpc-vault --help` prints the same notice and "Development build. Not production
custody. Do not use with real funds. Devnet only.". Both exit 0 for `--help` and
`-h`, write nothing to stderr and create no file (`cli_notice.rs`).

The other paths are unchanged:

- No argument, an unknown command or a missing argument still exits 1 with the
  same `FAIL: … usage:` text and no help on stdout.
- `--help` after a subcommand is still an ordinary argument.

The release check asserts the notice for all 13 binaries and both flags.
`test_release_check.py` covers its rules: a missing or altered notice, a missing
custody line, a non-zero exit, and an unexpected, missing or moved binary.

## DNA and bundle identity

Preserved. The fresh `check:release` build (new target directory, offline,
locked) produced these artifacts (`evidence/stage2b-fresh-artifacts.sha256`). They
equal both `scripts/release_hashes.json` (unchanged) and the Stage 1 evidence
(`dkg-v040-integration/logs/tests/artifact-hashes.log`):

| Artifact | SHA-256 |
|---|---|
| `mpc_integrity.wasm` (frozen, L2) | `2d6aa14170e4e1d40a78fc270d89a7534e943813b18811a66a84c88c6bb4ffdb` |
| `mpc.wasm` | `432d4d7d2e0244cad46c1c747f4fd2bdb2f9b15cf510218dd4a4b6ef8ee19614` |
| `mpc.dna` | `7f77af71ba633536139f77702de1d8e74b77b8f437f33bf9328ec3856d7f7452` |
| `holochain-mpc-core.happ` | `38efb4a9bcc3accd2eff2da0fbf451c8f1d981b366819d00c1eac52655bac1e5` |
| DNA hash | `uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu` |

## Stage 2A coverage

- The 6 harness scripts in the Stage 2B tree match Stage 2A's
  `harness-as-run.sha256` (`logs/stage2a-harness-hashes.log`). Stage 2B changes no
  harness file.
- `--self-check`: rootless netns is available, custody stays in the host
  namespaces.
- The full suite on the **Stage 2B-built** binaries
  (`faults-suite-20261027T192823Z`, 19:28–19:43 UTC, `--jobs 2`) gives the same
  statuses as both Stage 2A suites: 13 PASS, 6 FINDING, 0 FAIL, 0 HARNESS-ERROR,
  0 SKIP.
  - The FINDINGs are F1 in `dkg-kill-r1/r2/r3`, `dkg-stop` and `dkg-partition`,
    and F2 in `dkg-kill-r3-partial`.
  - `dkg-partition` executed (FINDING F1). `sign-partition` executed and passed;
    its drop rules dropped 192 conductor packets.
  - Both partition runs released their namespaces, and no harness process was
    left.
- F1 and F2 are reported exactly as before; their expected behaviour was not
  changed.

## Security implications

- **No product behaviour change.** The only product-source edits are the help
  branches at the top of two `main` functions, and they run only when the first
  argument is `--help` or `-h`. No library, custody check, anti-rollback, nonce,
  DKG, signing, FROST or zome code changed. The DNA identity is byte-identical.
- **Stricter, not weaker, release gate.**
  - Any manifest, dependency, lockfile or binary-set change now fails until an
    operator reviews it and re-records the inventory.
  - The notice check now covers every binary, both help flags and the exact text.
  - The validator tests itself.
- **Trust anchor.** `scripts/release_inventory.json` is now the approved state.
  Re-recording it approves whatever is on disk, so treat it like
  `release_hashes.json`: re-record only after reviewing the diff, and review
  changes to it in code review.
- **It is a consistency check, not supply-chain assurance.** The inventory pins
  the lockfile but does not audit it (R9: `cargo audit` not rerun).

## Remaining findings and risks (all still open)

| ID | State |
|---|---|
| R3 | Custody residual risks (same UID, root, whole-disk rollback) unchanged |
| R10/R11, A1-1 | Coordinator inbox fix missing (Agent 1) |
| F1, F2 | Reproduced unchanged (product findings) |
| V1 | Vault signing incompatible with Solana transactions; devnet blocked |
| Agent 7 | Independent review of Agents 2 and 5 not started |
| R7, R9 | Unchanged (app-interface origins; advisories, `cargo audit` not rerun) |
| I-4, I-6, I-7 | Unchanged (UI contract gaps; live-contract default; adoption of pre-existing state) |
| I-8 | Featureless `--all-targets` build of the `phase5c_live_writes` example: out of scope, not touched |
| I-9 | rustfmt backlog: out of scope, no formatting applied |
| Observation | Operator scripts (`phase5b_preflight.py`, `phase5c_b_audit.sh` and others) print no non-production notice; they are not binaries and are not covered by `help-notices` |
| Observation | Help is printed only when the flag is the first argument (the worker's existing rule) |

## Untouched

The following were verified unchanged at the end of the run (see the handover
notes):

- the Stage 1 integration tree and its manifests;
- the Stage 2A tree and patch;
- the original repository (`git --no-optional-locks status` 75 lines, HEAD
  `544270f`, `refs/checkpoints/*`);
- the agent work copies.

The persistent sandboxes were never named in any command. Nothing was committed
or pushed.
