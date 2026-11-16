# Sprint 1 — GitHub Actions runner recovery and CI failure report

Status: **PARTIALLY DIAGNOSED / NOT YET GREEN**. Compiled evidence below
is from the isolated CI PR #4, **not** the integrated SDK workspace. All
timestamps are UTC. No production credentials, persistent conductors or
release-identity recording were used.

## Execution chronology

| Run / attempt | Job / ID | Runner / steps | Result |
| --- | --- | --- | --- |
| [43771483501](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43771483501), attempt 1, 2026-11-15 22:50 | static `132988144386`, native `132988144169` | `runner_id=0`, no runner name, steps `[]` | Both failure before any commands |
| [43771920518](https://github.com/ConorTttttt/holochain-threshold-cryptography/actions/runs/43771920518), attempt 1, 2026-11-15 22:55 | static `132989495724`, native `132989495878` | `runner_id=0`, no runner name, steps `[]` | Both failure before any commands |
| Run 43771920518, **attempt 2**, started 2026-11-15 23:46 | static `133004337346` | Ubuntu 24.04, runner version 2.338.2, steps executed | **PASS:** inventory/version checks and 23 Python tests |
| Run 43771920518, **attempt 2** | native `133004337705` | Ubuntu 24.04, runner version 2.338.2, Rust/Cargo actually executed | **FAIL:** 12 Rust imports missing while compiling feature-gated test example |
| Run 43771920518, attempt 2 | integration `133004338865`, release `133004338897` | Skipped by event conditions | **NOT RUN** (intentional) |

The second attempt conclusively establishes that hosted runners for
`runs-on: ubuntu-24.04` can run this workflow. In that attempt, one
hosted runner was provisioned in AWS `us-west-2`, another in Azure
`centralus`. The repository is public, and steps successfully used the
workflow's read-only `contents: read` token, checkout action, and
`cachix/install-nix-action@v31`.

### What the missing-runner failures prove and do not prove

The zero-step attempts are **pre-execution job scheduling/provisioning
failures**: no workflow shell command ran, and their logs were unavailable.
The accessible run and job APIs did **not** provide a scheduler rejection
reason. They are **not** evidence of a YAML parse error, Rust compilation
failure, a lack of billing balance, a disabled Actions account, or a
specific GitHub outage. The second attempt running successfully rules out
a *persistent* universally incompatible `ubuntu-24.04` label or blanket
inability to execute Actions, but it does not identify the transient
no-runner reason. **Scheduler-level root cause remains unverified.**

The linked account exposes repository/PR, run and job metadata, but not
repository Actions permission, billing, runner inventory or private
scheduling diagnostics through the available API. Do **not** change
billing, disable security controls, or swap runner types as a guessed fix.

## Confirmed repository-controlled execution failure

The actually executed native job first completed checkout, Nix installation,
version reporting, `cargo fetch --locked`, and began
`cargo check --offline --locked --workspace --all-targets`. Its 12
`E0432`/`E0433` errors arose from
`crates/mpc-dkg-worker/examples/phase5c_live_writes.rs`, including imports of
`conductor_client`, `signed_relay`, `holochain_conductor_api`,
`holochain_keystore`, `url2`, `rpassword`, and related modules.

**Cause:** Cargo auto-discovered an interactive test-only example when asked
for `--all-targets`, while `holochain-mpc-dkg-worker` has optional dependencies
behind `conductor-client` and `lair-signer` and defaults to neither.
The example uses Lair APIs requiring **`lair-signer`**, not only the
`conductor-client` subset. Error exit code: **101**.

**Repository fix:** Explicitly declare the example in
`crates/mpc-dkg-worker/Cargo.toml` with
`required-features = ["lair-signer"]`; compile it as a dedicated **build-only**
target with `cargo check --offline --locked -p holochain-mpc-dkg-worker
--features lair-signer --example phase5c_live_writes`. This avoids
accidentally requesting an interactive example in the default workspace
check **without weakening coverage**. The dedicated compile does not connect
to a live conductor or Lair. CI workflow policy tests assert this invariant.

**Verification status:** Code and workflow changes are committed to PR #4
but must be evaluated by a **new actually executed** runner job before they
may be reported passing. The previously observed error is reproducibly
explained by the manifest/target mismatch; no claims about the corrected
Rust compilation are made before a post-change run.

## Confirmed toolchain and test evidence

Environment from run 43771920518, attempt 2:

- GitHub runner `ubuntu-24.04` (Ubuntu 24.04.5 LTS), runner v2.338.2.
- `nix develop --no-write-lock-file`, using checked-in `flake.lock`;
  Holonix branch `main-0.7`, locked rev
  `b483c5f0f75e287f1396d0b40496321bc82649e9`.
- `rustc 1.95.0`, `cargo 1.95.0`, `holochain_cli 0.7.1`,
  Node `v24.18.0`; Holochain HDK and HDI in root manifest: `=0.7.1`
  and `=0.8.1`.
- `cargo fetch --locked`: **PASS**. Native workspace check:
  **FAIL** on the example above. Thus `npm run test:native`,
  worker `conductor-client` tests, and SDK tests **did not execute**.
- Static job **PASS**, `Ran 23 tests in 1.191s ... OK`;
  includes `scripts/tests/test_ci_workflow.py` (four original tests),
  release-check and artifact-inventory unit tests. This result predates the
  new manifest regression test.
- The root `Cargo.lock` and `flake.lock` remain source-controlled,
  checked-in inputs. The runner image and action major-version tags are
  not bit-identical host pinning.

A passing SDK outcome **cannot** be derived from PR #4, where
`crates/holochain-dkg-sdk` is absent. The SDK draft is in PR #1
(`agent4/sdk-foundation-stage2c`). After Agent 6's combined integration
branch is published, the native job must execute **both** default SDK tests
and `--features native-holochain` tests there, and the exact SHA/run
results must be recorded. Source-only or policy-only checks are insufficient.

## Operator-only checks if zero-step failures recur

1. Inspect the failed run summary, job check details, and any red banner for
   a scheduling message; capture exact text and timestamp. Current accessible
   API responses do not include this reason.
2. Under **Repository Settings > Actions > General**, confirm Actions are
   enabled and required third-party actions are permitted. Read-only token
   permissions are sufficient for the existing workflow.
3. Review account billing/Actions usage and budgets **only if** GitHub
   reports a usage or payment problem; do not assume one.
4. Check GitHub's Actions service status for the relevant time. If a
   new job still fails in seconds without any assigned runner or steps,
   escalate both run IDs/attempts to GitHub Support for scheduler diagnosis.
5. Once the SDK is integrated, configure branch protection or rulesets to
   require **Inventory, versions and validator tests** and
   **Rust and native protocol checks**. The latter contains SDK tests
   whenever the SDK crate exists. Keep slow `Ephemeral Holochain Sweettests`
   separate, and keep `Read-only release artifact validation
   (operator-gated)` manual-only. Required checks must never be switched
   to a synthetic success to unblock a merge.

The available GitHub connection cannot change billing/account-level Actions
settings or branch protection. An operator must inspect/change those settings,
if warranted by evidence. Do not loosen release approvals.

## Reproducibility / security

Use the exact reviewed integrated commit and the commands in
[TESTING.md](TESTING.md#equivalent-local-validation-no-github-hosted-runner).
Use disposable local Holochain Sweettest conductors and temporary sockets.
Never use persistent operator sandboxes, real Lair credentials, funded
signing keys, or automatic release hash/inventory recording. Treat newly
introduced SDK package/dependency inventory mismatches as intentional
review gates, not artifacts to auto-correct.
