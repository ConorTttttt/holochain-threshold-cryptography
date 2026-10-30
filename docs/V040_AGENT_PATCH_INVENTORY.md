# v0.4.0 Stage 1 — agent patch inventory

27 October 2026 (Europe/London). Written by the Stage 1 integration
coordinator. **Integration evidence, not an independent review of the
patches.** "Applies" means that `patch --dry-run` and `git apply --check`
were run against the baseline in
[V040_BASELINE_PROVENANCE.md](V040_BASELINE_PROVENANCE.md) (`b96ffdf` plus
`docs/agent-briefs/`) and both succeeded. It says nothing about whether the
code is correct.

## Result

Five patches were found: Agents 2, 3, 4, 5 and 6. Each one applies to the
baseline alone and in sequence, with no fuzz, no offsets and no rejects. No
two patches touch the same file. Agent 1 left no patch. Its copy holds a
failing reproduction test and an unfinished document that claims
coordinator changes. Those changes do not exist. Agent 1 is classed as
**available but incomplete** and was not integrated.

Every originally named patch is in
`dkg-v040-integration/patches/original/` (read-only copies, byte-compared
with the source files).

## Summary

| Agent | Directory | Patch | SHA-256 | Format | Files | Lines | Status |
|---|---|---|---|---|---|---|---|
| 1 Coordinator | `agent1-r10-r11/` | none | — | — | 2 in copy | +377 | Available but incomplete |
| 2 Custody | `agent2-custody-work/` | `agent2-custody-hardening.patch` | `e723011682d6875b7be6ed38d817e5bbd50b4156460036f1c7b04fab38484f33` | `diff -ruN`, `-p1`, no modes | 14 (6 A, 8 M) | +2904 −32 | Available and applicable |
| 3 Fault injection | `agent3-fault-injection/` | `fault-injection.patch` | `3ec3f6687fe3a42a17a245e5f4854127a454910de73e1b8726c05ff5387a2c8f` | unified (`--- /dev/null`, `+++ b/`), `-p1` | 5 (5 A) | +2152 | Available and applicable |
| 4 Release | `agent4-release-hardening/` | `agent4-release-hardening.patch` | `8a340f280f09f5e15e8cbf9e9583c64e1a0e2a9483f004eb3e511908e006b84c` | `diff -ruN`, `-p1` | 25 (8 A, 17 M) | +1323 −8 | Available and applicable; semantic conflict with Agent 5 (I-1) |
| 5 Vault | `agent5-vault-work/` | `agent5-vault-app.patch` | `16dce45cf5db4e5b4480f9b237c3ce7f15167f286be02133c6822ef33150b1ca` | `diff -ruN`, `-p1` | 23 (21 A, 2 M) | +5156 | Available and applicable |
| 6 UI | `agent6-vault-ui-work/` | `agent6-vault-ui.patch` | `a8e4b67261597cf51c9f3d20a7618bcf6ee291b5e69427e500cdb8940d6cfe12` | `diff -ruN` from `empty-base`, `-p1` | 10 text (10 A) + 4 binary not embedded | +1413 | Available; binaries restored from the copy |

Every patch's baseline: its preserved `baseline/` directory (Agents 2, 4
and 5), or its copy minus its own new files (Agents 1 and 3), is identical
to `b96ffdf` plus the briefs. Agent 6's patch is relative to an empty tree,
and all its paths are new.

Every applied file was then compared with the same file in the agent's own
copy. All 77 patched files and 4 screenshots are byte-identical. The only
metadata difference: `scripts/custody_check.sh` is mode 0775 in Agent 2's
copy, but the patch format carries no modes (fixed in the integration tree,
step 7 of the application record).

## Agent 1 — coordinator inbox hardening (R10/R11)

- **Directory**: `agent1-r10-r11/holochain-mpc-core/` (a `cp -a` with
  `.git`, HEAD `544270f`). No patch, no report, no baseline directory.
- **What exists**, compared with the baseline:
  - `dnas/mpc/zomes/coordinator/mpc/tests/inbox_availability.rs`: new,
    232 lines, 26 Oct 21:05. Three-conductor Sweettests for a conflicting
    pair, sender-quota refusal and `AlreadyStored`.
  - `docs/V040_COORDINATOR_INBOX_HARDENING.md`: new, 145 lines, 26 Oct 21:08.
- **What is missing**: the doc says "All changes are in
  `dnas/mpc/zomes/coordinator/mpc/src/lib.rs`". That file is
  **byte-identical to the baseline** (SHA-256 `ba81cd22…d94364`). The sections
  `{{RESULT}}`, `{{TESTS}}`, `{{DNA}}` and `{{UPDATE}}` are unfilled
  placeholders. Its claims ("Availability target: **Met**", refusal kinds
  `conflict` and `sender-quota`, per-sender shares) describe code that does
  not exist.
- **Corroboration**: the copy's `dnas/mpc/workdir/mpc.dna` and
  `workdir/holochain-mpc-core.happ` were rebuilt at 26 Oct 21:26, after the
  doc. They are byte-identical to the main tree's 22 October build
  (`7f77af71…`, `38efb4a9…`). The coordinator therefore compiled unchanged.
  A search for `sender-quota` and `READABLE_INBOX_ENVELOPES` across the
  agent directories, `/tmp` and `$HOME` (excluding `target/`) found only
  the test.
- **Test state**: the test imports types that exist in the baseline
  (`DeliveryReceipt`, `PreparedGrant`, `ReceiptStatus`, `SendMessage`). It
  asserts refusal strings the baseline never produces, so it is expected
  to fail. That is a reproduction of R11 with no fix. Not run here
  (Sweettest; see the integration report).
- **Preserved as**: `patches/derived/agent1-derived-from-copy.patch`
  (SHA-256 `1b8e460fd057fa355da5a4442d6cb709e95a870cc1e4353f6b617099e533d0e0`,
  apply with `patch -p2`; the dry run on the baseline passes). It was made
  by this stage with `diff -ruN` from the copy. It is not an agent
  deliverable.
- **Not integrated**, for three reasons. The fix is absent. The doc would
  put false claims ("Met") in the tree. The test would turn
  `test:sweettest` red with no fix to review.
- **Scope**: both files are inside the brief's ownership
  (`dnas/mpc/zomes/coordinator/**` and its Sweettests; docs named in the
  brief).
- **DNA identity**: the coordinator is unchanged, so the DNA identity
  question does not arise.

## Agent 2 — custody hardening (R3)

| Path | Change | In brief scope |
|---|---|---|
| `crates/mpc-runtime/src/{chain,custody,lifecycle}.rs` | new | yes (`crates/mpc-runtime/**`) |
| `crates/mpc-runtime/src/bin/mpc-custody.rs` | new binary `mpc-custody` | yes |
| `crates/mpc-runtime/src/{lib,dkg}.rs` | +98/−11, +14/−6 | yes |
| `crates/mpc-runtime/tests/durable.rs` | +355 | yes |
| `crates/mpc-dkg-worker/src/node_service.rs` | +48/−15 | yes (custody parts) |
| `crates/mpc-dkg-worker/src/signing.rs` | +4 | yes (custody parts) |
| `crates/mpc-dkg-worker/tests/share_custody.rs` | +410 | yes |
| `crates/mpc-dkg-worker/tests/signing_session.rs` | +46 | **not in the ownership list**, but task 2 says "extend `test:signing-session`" |
| `scripts/custody_check.sh` | new, needs mode 0755 | yes (`scripts/custody_*`) |
| `docs/V040_PHASE7_CUSTODY_HARDENING.md`, `docs/V040_PHASE7_SHARE_CUSTODY.md` | new, +7 | yes (`docs/V040_PHASE7_*`) |

- No Cargo manifest or lockfile change. `mpc-custody` is picked up
  automatically from `src/bin/`.
- **Behaviour change for existing state** (from the patch's own doc,
  "Migration of existing state directories"): a directory provisioned
  before this patch has no `custody.json`. `mpc-node serve`,
  `recover_share`, `mpc-sign` and `activate-group` will refuse it. Adoption
  is `mpc-custody init <dir> --anchor <path>`, "on trust". This affects the
  persistent 5C node state; adoption is an operator decision.
- Reported: native 130/130, rollback test fails before the change and
  passes after, live rehearsal not rerun. These are claims, re-checked in
  the integration report.

## Agent 3 — fault injection

- Five new files: `scripts/phase6_faults.py`, `scripts/faults_env.py`,
  `scripts/faults_signing.py`, `scripts/faults_scenarios.py` and
  `docs/V040_PHASE6_FAULT_TESTS.md`. All are inside the brief's scope.
  `scripts/phase6_rehearsal.py` is not modified; it is imported.
- `--list` shows 19 scenarios: `control` plus the 18 in `--suite`.
- Extra evidence in the directory: `binaries.sha256` and
  `faults-scripts.sha256` (copied to `patches/original/`).
- Reported: two consecutive 18-scenario suites, each 12 PASS and 6 FINDING
  (F1, F2). Agent 3 ran against the 22 Oct binaries, not rebuilt ones.

## Agent 4 — release hardening

| Path | Change | In brief scope |
|---|---|---|
| `docs/THREAT_MODEL.md`, `docs/V040_RELEASE_HARDENING.md`, `docs/SECURITY.md`, `docs/V040_PHASE5B_BOOTSTRAP.md` | new / +7 / +7/−4 | yes (`docs/**`) |
| `SECURITY.md` (root), `README.md` | new / +7 | yes |
| `scripts/release_check.py`, `scripts/release_hashes.json` | new | yes (`scripts/release_*`) |
| `scripts/check_release.py` | +9/−1 | yes (`scripts/check_*`) |
| `package.json` | `check:release`, `test:input-validation`, `test:native` extended | yes (task 2 names `check:release`); extending `test:native` is implied |
| `crates/mpc-dkg-worker/src/notice.rs`, `lib.rs` and 11 `*_main.rs` (1 line each) | `--help` non-production notice | task 6 requires it; **outside the literal file list** |
| `crates/mpc-dkg-worker/src/phase5b_bootstrap_main.rs` | +145/−2: `check-app-interfaces`, `attach-app-interface` | R7 "related provisioning code". `conductor_client.rs`, which the brief names, is **unchanged** |
| `crates/mpc-dkg-worker/tests/input_validation.rs`, `crates/mpc-security/tests/wire_validation.rs` | new | task 3 implies tests |

- `attach-app-interface` is an admin write to a conductor. Running it on a
  persistent conductor is operator-only.
- `release_hashes.json` records the 22 Oct coordinator
  (`432d4d7d…9614`), integrity WASM (`2d6aa141…ffdb`), `.dna`
  (`7f77af71…`) and `.happ` (`38efb4a9…`). It is valid only while the
  coordinator is unchanged (Agent 1 is not integrated, so it is unchanged).
- Reported: `check:release` passes (127 native tests, byte-identical WASM,
  11 binaries print the notice).

## Agent 5 — vault service

- New crate `crates/mpc-vault/` (package `holochain-mpc-vault`,
  binary `mpc-vault`). It contains `openapi.yaml`, a Solana devnet adapter
  (`solana.rs`), a mock chain and a mock node, a bearer-token HTTP API
  (`api.rs`), `scripts/vault_rehearsal.py`, and the tests `state_machine.rs`
  and `http_api.rs`. Also `docs/V040_VAULT_APP.md`.
- `Cargo.toml`: one member line, `"crates/mpc-vault"`. No other workspace
  edit.
- `Cargo.lock`: one new `[[package]]` entry for `holochain-mpc-vault`
  (+18 lines). Every dependency resolves to a version already in the
  baseline lock: `axum 0.8.9`, `ureq 3.4.2`, `bs58 0.5.1`,
  `ed25519-dalek 2.2.0`, `base64 0.22.1`, `libc 0.2.190`, `rand 0.8.8`,
  `sha2 0.10.9`, `tokio`, `serde`, `serde_json`, `tempfile`. No version is
  changed. `--locked` builds confirm this (integration report).
- All paths are inside the brief's scope.
- `ureq` gives the vault outbound HTTP, for the Solana RPC only.
- Reported: 43 tests (19 lib, 20 state_machine, 4 http_api). Devnet signing
  is blocked by V1.

## Agent 6 — vault UI

- 10 new text files under `ui/vault/` plus `docs/V040_VAULT_UI.md`. All are
  inside scope.
- The patch lists 4 `Binary files … differ` lines and embeds no data.
  These screenshots were restored from `agent6-vault-ui-work/` into the
  integration tree only:

  | Screenshot | SHA-256 | Size (px) |
  |---|---|---|
  | `approve-panel-400px-light.png` | `63f306c5b0f632df38594b8f9738e4dcfcab656da3c984c0d5413759aa6b5f67` | 485 × 3344 |
  | `mismatch-400px-light.png` | `d34465100e9d571a691614d5c4db5f768a860556c33af594d2ad13d9d5a47cdb` | 400 × 1800 |
  | `new-preview-400px-dark.png` | `7ce38821917ad8341b40ebc4a57558c131fd42322c679256cf9e4929b2cd978c` | 485 × 1634 |
  | `proposals-desktop.png` | `a495036d7b3bf2a67dc517573cf45f7f26e7ab724d4277403ccb00ae7f86d944` | 1100 × 1500 |

  `file` identifies each one as valid PNG image data.
  `approve-panel-400px-light.png` and `new-preview-400px-dark.png` are
  485 px wide although their names say 400 px. This is cosmetic, but it
  means they are not proof of a 400 px rendering.
- Reported: 15 UI tests, integration with Agent 5's demo service.

## Overlaps and order

No file is changed by two patches (checked on the `+++` path lists).
Cross-patch interactions without a textual conflict:

| ID | Patches | Interaction |
|---|---|---|
| I-1 | 4 × 5 | `scripts/check_release.py` requires the workspace package set to **equal** a fixed set of 8. Agent 5 adds a 9th (`holochain-mpc-vault`), so the `manifest` step of `check:release` fails |
| I-2 | 4 × 2, 4 × 5 | `release_check.py`'s help-notice step lists binaries only from `crates/mpc-dkg-worker/Cargo.toml`. `mpc-custody` (Agent 2) and `mpc-vault` (Agent 5) are not covered |
| I-3 | 2 × 3, 2 × 5 | Agent 3's fault harness and Agent 5's vault rehearsal were run on the 22 Oct binaries. Agent 2's anchored custody changes `mpc-node serve`, `mpc-sign` and `activate-group`, so their live results do not carry over |
| I-4 | 5 × 6 | The UI uses 11 of 15 contract operations. There is no manual broadcast (`POST /proposals/{id}/broadcast`), no vault creation or detail view, and no `/health` |

Application order used: 2, 3, 5, 6, then 4 (all clean, see
`logs/patch-application.log`). Agent 4 went last so that its `package.json`
and checks would see every other change. Because no file overlaps, the
order does not change the resulting tree.
