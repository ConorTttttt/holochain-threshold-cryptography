# v0.4.0 Stage 1 — integration report

27 October 2026 (Europe/London). Written by the Stage 1 integration
coordinator (coding assistant). **Integration evidence on one development
host, not production custody, not an independent audit, not a release.**
No persistent conductor, sandbox, Lair, credential, nonce journal or live
key was touched. No commit, branch, ref or push was made.

Companion documents: [V040_BASELINE_PROVENANCE.md](V040_BASELINE_PROVENANCE.md)
and [V040_AGENT_PATCH_INVENTORY.md](V040_AGENT_PATCH_INVENTORY.md). The
records and logs are under `dkg-v040-integration/` (see section I).

## A. Executive summary

**Stage 1 completed, with open integration blockers.**

- **Baseline.** The authoritative baseline is checkpoint `b96ffdf` plus
  the untracked `docs/agent-briefs/`. It is identical to the operator's
  live working tree. `ecc08a6` is an older sibling snapshot, not an
  ancestor.
- **Integrated.** The patches from Agents 2, 3, 4, 5 and 6 are in one
  isolated tree. All five applied cleanly, and no file is touched by two
  of them. Every applied file is byte-identical to the file in that agent's
  own copy.
- **Not integrated.** Agent 1 left no patch. Its coordinator fix does not
  exist, although its draft doc says it does.
- **Verified here.**
  - The workspace builds `--offline --locked`.
  - `test:native` passes 142/142, the vault 43/43 and the UI 15/15.
  - The fresh offline WASM, `.dna` and `.happ` builds are byte-identical
    to the 22 October deployed build (DNA hash `uhC0kp2j…P6Mwu`).
  - The disposable fault suite reproduces F1 and F2 on the integrated
    binaries, and its control run signs and verifies.
- **New integration blockers.** I-1: `check:release` fails its manifest
  step because of the vault crate. I-5: Agent 2's custody root check
  makes both partition fault scenarios unrunnable (HARNESS-ERROR).

## B. Authoritative baseline

| Item | Value |
|---|---|
| Source | `/mnt/holochain/offloaded/sf/Downloads/holochain-mpc-core-v0.3.3-dkg-source/holochain-mpc-core` |
| Commit | `b96ffdffd70fba065d3951ada416d4b39d17d73a` (`refs/checkpoints/security-review-20261022`, local only) |
| Extra | `docs/agent-briefs/` (8 files, untracked, docs only) |
| Dirty / clean | The original tree is dirty against its HEAD `544270f` (75 status lines). It is clean against `b96ffdf` plus the briefs, apart from one `__pycache__` file |
| `ecc08a6` | 18 Oct NO-GO archive, parent `544270f`. **Not** an ancestor of `b96ffdf`; 41 files differ |
| GitHub | `main` = `8dec223` (v0.3.3). Every `feature/v0.4.0-*` = `544270f` (v0.3.8). No checkpoint refs. All Phase 3–8 code (73 files, +14,787 lines over `544270f`) is local only |
| Evidence | (1) `git archive b96ffdf` equals the live tree under `diff -r`. (2) The agents' three preserved baselines equal it. (3) The other agent copies differ only by their own files. (4) The handover names `b96ffdf` as the latest checkpoint. Details are in the provenance doc |

## C. Agent integration matrix

| Agent | Patch found | Applies cleanly | Integrated | Tests run | Result |
|---|---|---|---|---|---|
| 1 — Coordinator | No. Copy has 1 test and 1 draft doc; fix absent | Derived patch dry-runs (`-p2`) | **No** | None (Sweettest needs the fix) | **Incomplete.** R10/R11 remain open |
| 2 — Custody | Yes, `e7230116…` | Yes | Yes (+ chmod) | native, runtime, share-custody, signing-session, runtime-all, live fault suite | Unit/integration PASS. **I-5** breaks the partition scenarios. Pre-existing state needs `mpc-custody init` |
| 3 — Fault injection | Yes, `3ec3f668…` | Yes | Yes | `--list`, `--self-check`, 2 full suites on integrated binaries | 12 PASS, 5 FINDING (F1, F2), 2 HARNESS-ERROR (I-5) per suite |
| 4 — Release | Yes, `8a340f28…` | Yes | Yes | input-validation, `check:release` | 8/9 release steps PASS. **manifest FAIL (I-1)**. Notice coverage gap (I-2) |
| 5 — Vault | Yes, `16dce45c…` | Yes | Yes | `cargo test -p holochain-mpc-vault`, demo service | 43/43 PASS. Devnet signing still blocked (V1, not rerun) |
| 6 — UI | Yes, `a8e4b672…` (binaries missing) | Yes | Yes + 4 screenshots restored | `node --test`, live contract vs demo | 15/15 PASS. Live contract PASS (run 3). Contract gaps (I-4, I-6) |

No agent is marked complete here on the strength of its own report.

## D. Change inventory (integration tree vs baseline)

| Kind | Count | Detail |
|---|---|---|
| Added files | 50 text + 4 binary + 3 Stage 1 docs | Agent 2: 6. Agent 3: 5. Agent 4: 8. Agent 5: 21. Agent 6: 10 text + 4 PNG. Stage 1: these 3 `docs/V040_*` reports |
| Modified files | 27 | Agent 2: 8. Agent 4: 17. Agent 5: 2 (`Cargo.toml`, `Cargo.lock`) |
| Removed files | 0 | — |
| Textual conflicts | 0 | No path is shared between patches |
| Semantic conflicts | I-1, I-2, I-3, I-5 | Section F |
| Dependency changes | 1 lock entry | `Cargo.lock` +18 lines: the `holochain-mpc-vault` package. No version changed or added from the registry. `--offline --locked` succeeds. `Cargo.lock` hash is unchanged by every test step |
| Workspace | +1 member | `crates/mpc-vault` |
| Binary assets | 4 PNG | `ui/vault/screenshots/*` restored from `agent6-vault-ui-work/`. Hashes are in the inventory |
| Mode fixes | 1 | `scripts/custody_check.sh` → 0775 |
| Outside literal ownership | Agent 2: `tests/signing_session.rs`. Agent 4: `notice.rs`, `lib.rs`, 11 `*_main.rs`, 2 test files, `phase5b_bootstrap_main.rs` | All are required or implied by the agents' own brief tasks. No patch edits another agent's area, the integrity zome or any SDK pin |
| Integrity zome / DNA | unchanged | Rebuilt integrity WASM `2d6aa141…ffdb`; DNA hash `uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu` |

The full file manifest is `evidence/integration-manifest.sha256`.

## E. Test results

Environment: rustc 1.99.0 (b940084d7 2026-09-28), cargo 1.99.0, node
v20.20.2, Python 3.14.4, rustfmt from the same toolchain. PATH `hc` and
`holochain` are 0.7.0; the harnesses use Nix-store holochain and
lair-keystore 0.7.1.

All cargo calls ran with `CARGO_NET_OFFLINE=true` and `TMPDIR=/tmp/v040i`
(SUN_LEN). Working directory: `dkg-v040-integration/holochain-mpc-core`.
The build cache is a copy of the main tree's `target/` (build output only,
`target/tmp` excluded).

Logs: `dkg-v040-integration/logs/tests/<name>.log`. Summary TSV:
`logs/test-results.tsv`.

| Command | Exit | Passed | Failed | Skipped | Status |
|---|---|---|---|---|---|
| `cargo build --offline --locked --workspace --all-targets` | 101 | — | — | — | **FAIL**, pre-existing: baseline example `phase5c_live_writes.rs` (unchanged) needs `lair-signer` but declares no `required-features` |
| `… --all-targets --features holochain-mpc-dkg-worker/lair-signer` | 0 | — | — | — | **PASS** (whole workspace, all tests, vault) |
| `cargo build --offline --locked -p holochain-mpc-dkg-worker --features lair-signer,conductor-client --bins` | 0 | — | — | — | PASS |
| `cargo fmt --all -- --check` | 1 | — | — | — | **FAIL**, pre-existing: 1,502 hunks. The baseline already has 987, so the project is not rustfmt-clean. Not a gate |
| Clippy | — | — | — | — | NOT RUN: not configured in `package.json` or any script |
| `npm run check:holochain-versions` | 0 | — | — | — | PASS |
| `python3 -I scripts/check_release.py` (manifest) | 1 | — | — | — | **FAIL (I-1)**. Baseline: PASS ("8 Cargo packages") |
| `npm run test:native` (19 commands) | 0 | 142 | 0 | 0 | PASS |
| `npm run test:runtime` | 0 | 12 | 0 | 0 | PASS |
| `npm run test:security` | 0 | 14 | 0 | 0 | PASS |
| `npm run test:share-custody` | 0 | 10 | 0 | 0 | PASS |
| `npm run test:signing-session` | 0 | 9 | 0 | 0 | PASS |
| `npm run test:input-validation` | 0 | 11 | 0 | 0 | PASS |
| `cargo test --offline --locked -p holochain-mpc-runtime` | 0 | 21 | 0 | 0 | PASS |
| `npm run test:signing-signer` | 0 | 2 | 0 | 0 | PASS |
| `npm run test:transport-probe` (`--offline --locked`) | 0 | 22 | 0 | 0 | PASS |
| `npm run test:phase5c-b-unit` | 0 | 18 | 0 | 0 | PASS |
| `cargo test --offline --locked -p holochain-mpc-vault` | 0 | 43 (19 lib, 20 state_machine, 4 http_api) | 0 | 0 | PASS |
| `node --test ui/vault/test` | 0 | 15 | 0 | 0 | PASS |
| UI live contract vs `mpc-vault demo`, run 1 (script defaults) | 1 | — | — | — | FAIL: the script defaults the recipient to the vault itself (I-6) |
| … run 3 (`VAULT_RECIPIENT` = random 64-hex) | 0 | — | — | — | PASS: create → `hash_mismatch` refusal → approve → confirmed 2/2 |
| `npm run build:happ` | 0 | — | — | — | PASS. `.dna` `7f77af71…`, `.happ` `38efb4a9…`, both equal to the 22 Oct reference |
| `npm run check:wasm-imports` | 0 | — | — | — | PASS: 48 and 11 Holochain 0.7.1 host functions |
| `npm run check:release` | 1 | native 142 | 0 | 0 | **FAIL (manifest, I-1)**. versions, fresh wasm-build, imports, pack, identity, help-notices (11), native and lockfile all PASS |
| `mpc-custody --help`, `mpc-vault --help` | 1, 1 | — | — | — | No non-production notice (I-2). `mpc-node --help`: 0, notice present |
| `python3 -I scripts/phase6_faults.py --list` | 0 | 19 listed | — | — | PASS |
| `python3 -I scripts/phase6_faults.py --self-check` | 0 | — | — | — | PASS (tools, 6 binaries, `.happ`, rootless netns) |
| `phase6_faults.py --suite --with-control --jobs 4`, suite 1 | 1 | 12 PASS + 5 FINDING | 0 FAIL | 2 HARNESS-ERROR | See below |
| suite 2 (consecutive) | 1 | 12 PASS + 5 FINDING | 0 FAIL | 2 HARNESS-ERROR | Identical to suite 1 |
| `npm run test:sweettest` (`mpc_network`, `dkg_live`, `three_processes`, `conductor_bridge`; Sweettest conductors, in process) | 0 | 4 | 0 | 0 | PASS (469 s) |
| Agent 1 `inbox_availability` Sweettest | — | — | — | — | NOT RUN: not integrated; the fix it tests is absent |
| `scripts/phase6_rehearsal.py` | — | — | — | — | NOT RUN: E1 makes it fail at `propose` on this host. The fault harness `control` scenario covers the same flow |
| Vault devnet end-to-end (`vault_rehearsal.py`) | — | — | — | — | NOT RUN: needs network and devnet funds; blocked by V1 regardless |
| `scripts/custody_check.sh` on real state | — | — | — | — | NOT RUN: would mean reading persistent state directories |

**Fault suite, integrated binaries.** Suite 1:
`~/mpc-phase6-rehearsal/faults-suite-20261027T121449Z` (resolved
`/mnt/holochain/offloaded/sf/...`), 12:14–12:23 UTC.

| Scenario | Status | Note |
|---|---|---|
| control | PASS | DKG, activation, one OpenSSL-verified 2-of-3 signature |
| dkg-kill-r1, -r2, -r3, dkg-stop | FINDING | F1: both survivors journal `running`, not `aborted` |
| dkg-kill-r3-partial | FINDING | F2: one node completes |
| dkg-stop-short, dkg-seal-kill-before, dkg-seal-kill-after, dkg-restart-refused | PASS | |
| sign-kill-reserved, -commit, -share, -aggregate, sign-recover-new-op, sign-unselected-mid, -early | PASS | Nonce never reused; repeats refused; unselected node reserves nothing |
| dkg-partition, sign-partition | **HARNESS-ERROR** | `mpc-node provision` inside `unshare -Urmn`: "unsafe custody layout: custody must not run as root" (I-5) |

Suite 2: `faults-suite-20261027T122416Z`, 12:24–12:32 UTC, run
immediately after suite 1. Statuses, check results and finding tags are
identical in all 19 scenarios (`logs/tests/faults-suite-{1,2}-checks.txt`).
Both partition scenarios fail at `node-provision-1` with the same I-5
refusal. The harness exits 1 because HARNESS-ERROR is not a documented
outcome. Run directories are kept under `~/mpc-phase6-rehearsal/` and
contain only disposable state and throwaway passphrases (redacted in logs).

### Reported versus verified

| Claim (source) | Status here |
|---|---|
| Agent 2: native 130/130 | **Superseded and verified.** Native is 142/142 with the patches combined: the baseline's 115, plus Agent 2's 15, plus Agent 4's 11 and 1 |
| Agent 2: rollback test fails before the change and passes after | **Passes after: verified.** Fails before: REPORTED ONLY (the test uses new APIs; not rebuilt against the baseline) |
| Agent 2: live rehearsal not rerun | Now partly run: the fault-suite `control` and signing scenarios pass on Agent 2's binaries. Partition fails (I-5) |
| Agent 3: two suites of 12 PASS / 6 FINDING | **Not reproduced as stated.** Integrated binaries give 12 PASS / 5 FINDING / 2 HARNESS-ERROR. `dkg-partition` (an F1 finding before) and `sign-partition` cannot run |
| Agent 4: `check:release` passes, 127 native, 11 notices | Passes alone: REPORTED ONLY. **Fails when integrated (I-1).** All other steps verified |
| Agent 5: 43 tests | **Verified** 43/43 |
| Agent 5: devnet signature invalid over the tx (V1) | REPORTED ONLY (logs `agent5-vault-work/e2e-run*.log`). The code path is confirmed: `sign_main.rs:91` writes `signed_message()`, and the vault refuses at `engine.rs:705` |
| Agent 6: 15 tests, works against the demo service | **Verified** 15/15, and live contract PASS with an explicit recipient |
| Agent 1: "Availability target: Met" | **False.** The coordinator is unchanged (byte-identical source and DNA) |

## F. Security and integration findings

Severity is the coordinator's triage rating, not an audit rating. None is
closed by passing tests.

### Newly found in Stage 1

| ID | Severity | Finding | Evidence | Files | Proposed owner | Next stage |
|---|---|---|---|---|---|---|
| I-5 | **High (integration)** | Agent 2's `check_location` refuses `euid()==0`. Agent 3's partition scenarios run nodes in a rootless user namespace (`unshare -Urmn`) where the UID maps to 0, so `mpc-node provision` fails. Partition fault coverage (DKG #3, signing #8) is lost. Production behaviour (never run custody as root) is intended. The conflict is with the test method | suite 1 `dkg-partition`/`sign-partition` logs; `node-provision-1.log` | `crates/mpc-runtime/src/custody.rs:176`; `scripts/faults_env.py:311` | Agents 2 and 3 jointly; operator chooses | Stage 2: map a non-root UID in the namespace, or an explicit test-only allowance reviewed by Agent 7. Do not weaken the production check silently |
| I-1 | Medium (release gate) | `check_release.py` requires the package set to equal 8 names. The vault crate makes it 9, so `check:release` fails | `logs/tests/check-release.log`; baseline PASS | `scripts/check_release.py` (the `expected` set) | Agent 4 | Stage 2: add `holochain-mpc-vault` to the expected inventory (and its files to the source list) after review |
| I-2 | Low | `help-notices` only enumerates worker binaries. `mpc-custody` and `mpc-vault` lack the `--help` non-production notice (both exit 1) | `logs/tests/new-binaries-help.log` | `scripts/release_check.py` `check_help_notices`; `mpc-runtime/src/bin/mpc-custody.rs`; `mpc-vault/src/main.rs` | Agents 4, 2, 5 | Stage 2 |
| I-3 | Medium (evidence) | Agent 3's and Agent 5's live results were on 22 Oct binaries. Agent 2 changes `mpc-node`, `mpc-sign` and `activate-group` | binary hashes in `agent3-fault-injection/binaries.sha256` vs `logs/tests/faults-suite-1.log` header | — | Coordinator | Re-baseline all live evidence on the integrated binaries (started here) |
| I-4 | Medium (UX/safety) | The UI never calls `POST /proposals/{id}/broadcast`, `POST /vaults` or `GET /vaults/{id}`. A `signed` proposal on a node with auto-broadcast off cannot be broadcast from the UI, and the UI cannot tell whether auto-broadcast is on (Agent 6 gap 2). No raw message hex (gap 1); `replay` has no `proposal_id` (gap 5); `group_status` has one value (gap 6) | `ui/vault/api.js:51-61` vs `crates/mpc-vault/src/api.rs:91-106` | `ui/vault/*`, `crates/mpc-vault/openapi.yaml` | Agents 5 and 6; operator decides | Stage 2. No endpoint was added in Stage 1 |
| I-6 | Low | `ui/vault/scripts/live_contract.mjs` defaults the recipient to the vault's own address, which the service refuses. Its usage line omits `VAULT_RECIPIENT` (64 hex on the mock chain) | `logs/tests/ui-live-contract.log`, `…-run3.log` | `ui/vault/scripts/live_contract.mjs:15` | Agent 6 | Stage 2 |
| I-7 | Medium (operator) | After Agent 2, every state directory provisioned before the patch, including the persistent 5C node state, is refused by `mpc-node serve`, `recover_share`, `mpc-sign` and `activate-group` until `mpc-custody init` adopts it **on trust** | `docs/V040_PHASE7_CUSTODY_HARDENING.md` "Migration of existing state directories" | `crates/mpc-runtime/src/custody.rs` | Operator | Decide before any persistent-cell work. Not run here |
| I-8 | Low (build) | `--workspace --all-targets` without features fails on the baseline example `phase5c_live_writes` (no `required-features`). Pre-existing | `logs/tests/locked-build.log` | `crates/mpc-dkg-worker/Cargo.toml`, `examples/phase5c_live_writes.rs` | Agent 4 | Stage 2 |
| I-9 | Info | `cargo fmt --check` fails in the baseline (987 hunks) and when integrated (1,502). Formatting is not enforced | `logs/tests/fmt-check*.log` | workspace | Operator | Decide whether to adopt rustfmt (a big diff; do it separately) |
| A1-1 | **High (process)** | Agent 1's draft doc asserts an implementation and "Met" availability, but no code exists. If merged, it would misstate R11 as fixed | Inventory, Agent 1 section | `agent1-r10-r11/.../docs/V040_COORDINATOR_INBOX_HARDENING.md` | Agent 1 (re-run) | Stage 2: redo Agent 1 from `b96ffdf`. Keep the test as the failing reproduction |

### Existing findings, still open (not fixed in Stage 1)

| ID | Severity | Status here | Code path | Reproducibility |
|---|---|---|---|---|
| F1 — incomplete abort journaling | Low (Agent 3) | Reproduced on integrated binaries in 4 scenarios (suite 1) | `dkg_abort` only on controller error: `crates/mpc-dkg-worker/src/lib.rs:352`; EOF returns Ok: `node_service.rs` `serve_connection`; relay exit `relay_service_main.rs` | `--scenario dkg-kill-r2 --keep` |
| F2 — partial Round-3 completion | Medium (L1) | Reproduced (`dkg-kill-r3-partial`). Activation stays blocked | `lib.rs:390` `seal_share` on local completion; no wipe path | `--scenario dkg-kill-r3-partial` |
| E1 — rehearsal symlink | Environment | Still present: `~/mpc-phase6-rehearsal -> /mnt/holochain/offloaded/sf/mpc-phase6-rehearsal` | lexical check `crates/mpc-dkg-worker/src/lair_signer.rs:248`; `scripts/phase6_rehearsal.py` builds `Run.root` unresolved | `npm run rehearse:three-nodes` (not run) |
| E2 — relay start race | Environment | Not seen in suite 1. The harness waits for `controller.sock` (`scripts/faults_env.py:648`). `phase6_rehearsal.py` still has the race | `scripts/phase6_rehearsal.py` start order | Intermittent under load |
| V1 — Solana signing incompatibility | **High (functional)** | Code path confirmed. Devnet result REPORTED ONLY. The vault fails closed | `crates/mpc-frost-ed25519/src/lib.rs:251` `signed_message`; `crates/mpc-dkg-worker/src/signing.rs:312`; `sign_main.rs:91`; refusal at `crates/mpc-vault/src/engine.rs:705` | `agent5-vault-work/e2e-run3.log` |
| R3 — remaining custody risks | High | Unchanged in substance: same-UID compromise, root, whole-system rollback (the anchor can be rolled back with the disk), incomplete signer/Lair separation, recovery refused if the anchor is lost | `docs/V040_PHASE7_CUSTODY_HARDENING.md` threat table | — |
| R10/R11 — coordinator inbox | High / Medium | **Open.** Agent 1 produced no fix | `dnas/mpc/zomes/coordinator/mpc/src/lib.rs` (unchanged) | Agent 1's test (not run) |
| R7 — app-interface origins | Medium | Agent 4 added `check-app-interfaces` and `attach-app-interface` (admin write; operator-only). `conductor_client.rs` is unchanged | `phase5b_bootstrap_main.rs` | Not run (needs a conductor) |
| R9 — advisories | Medium | Per Agent 4: `lru 0.17.0` ships in lair-signer binaries. REPORTED ONLY; `cargo audit` not rerun | — | — |
| Agent 7 review | — | Not started. Required before merging Agents 2 and 5 into the operator's tree | — | — |

## G. Remaining operator decisions

1. Agent 1: re-run the coordinator brief (R11). Decide the quota size and
   reject-vs-ignore, and whether to bundle the result with
   `update_coordinators` (R10). Do not merge the current draft.
2. I-5: choose how the partition tests run under the root refusal: a
   namespace UID mapping, or a reviewed test-only allowance.
3. I-7: whether and when to adopt pre-existing state directories with
   `mpc-custody init` (on trust), and where the anchors live (separate
   user or `chattr +a`).
4. V1: whether to add a raw-message signing mode (a separate signer
   profile, plan field and security review), or to keep the vault on the
   mock chain.
5. I-4: whether the UI may broadcast manually, and whether auto-broadcast
   is shown or configurable.
6. Whether to approve Stage 2 fixes for I-1, I-2, I-6 and I-8 (small,
   mechanical) before Agent 7's review or with it.
7. Whether to preserve this integration as a checkpoint ref (exact command
   in section I). Commits and refs are operator-only.
8. E1: fix the symlink (resolve the path in `phase6_rehearsal.py`, or
   stop using a symlinked rehearsal root).

## H. Recommended integration status

**Ready for Stage 2 with specified blockers.**

- The baseline is certain.
- The integrated tree builds offline and locked, and passes every native,
  vault and UI suite.
- The tree keeps the deployed DNA identity byte for byte.

These blockers must be cleared before the tree is proposed for the
operator's tree:

1. I-5: partition fault coverage is lost.
2. I-1: `check:release` is red.
3. A1-1 / R11: the coordinator work is missing.
4. Agent 7's independent review of Agents 2 and 5.

Stage 2 may start from this tree for any work that does not depend on
those four items.

## I. Reproducibility and records

| Record | Path (under `dkg-v040-integration/`) |
|---|---|
| Integration tree | `holochain-mpc-core/` |
| Pristine baseline (read-only) | `baseline/` |
| Original patches, screenshots, Agent 3 checksums (read-only) | `patches/original/` |
| Agent 1 derived patch (record only) | `patches/derived/agent1-derived-from-copy.patch` |
| Ordered application record | `PATCH_APPLICATION_RECORD.md`, `logs/patch-application.log`, `logs/dryrun-individual.log` |
| Baseline manifest | `evidence/baseline-manifest.sha256` (`2803c864…2419`) |
| Integration file manifest | `evidence/integration-manifest.sha256` (see `STAGE2_HANDOVER.md` for its hash) |
| Test runner and logs | `run_tests.sh`, `logs/test-results.tsv`, `logs/tests/*.log`, `logs/release-check-logs/` |
| Fault suites | `~/mpc-phase6-rehearsal/faults-suite-20261027T121449Z`, `…T122416Z`; logs `logs/tests/faults-suite-{1,2}.log` |
| Stage 2 handover | `STAGE2_HANDOVER.md` |

Suggested operator action (not performed). To preserve this tree without
touching the branch or index, run in the original repo:

```bash
cd /mnt/holochain/offloaded/sf/Downloads/holochain-mpc-core-v0.3.3-dkg-source/holochain-mpc-core
export GIT_INDEX_FILE=$(mktemp -u) GIT_WORK_TREE=../dkg-v040-integration/holochain-mpc-core
git read-tree b96ffdf && git add -A . && \
  git update-ref refs/checkpoints/stage1-integration-20261027 \
  "$(git commit-tree "$(git write-tree)" -p b96ffdf -m 'checkpoint: v0.4.0 Stage 1 integration (Agents 2-6), 27 Oct 2026')"
rm -f "$GIT_INDEX_FILE"; unset GIT_INDEX_FILE GIT_WORK_TREE
git status --short | wc -l   # must still be 75
```

`.gitignore` excludes `/target`. Run `git status --short` before and after;
the real index must not change (see the earlier `git-export-without-index`
lesson).
