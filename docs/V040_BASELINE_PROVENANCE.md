# v0.4.0 Stage 1 — baseline provenance

27 October 2026 (Europe/London). Written by the Stage 1 integration
coordinator (coding assistant). **Integration evidence, not production
custody, not an independent audit.** Every statement below comes from a
read-only command run on 27 October 2026. The original working tree, its
index, HEAD and refs were not modified.

## Result

The authoritative v0.4 development baseline is **checkpoint commit
`b96ffdffd70fba065d3951ada416d4b39d17d73a`**
(`refs/checkpoints/security-review-20261022`). It is extended by one
untracked, docs-only directory, `docs/agent-briefs/`, with 8 files. That
directory is not in any commit.

- The live working tree matches `b96ffdf` byte for byte for every tracked
  source file. The only other difference is a `scripts/__pycache__/`
  bytecode file, which is not source.
- The three baselines the agents kept (Agents 2, 4 and 5) are byte-identical
  to that state. The copies of Agents 1, 3 and 6 differ from it only by
  their own work.
- `ecc08a6` is **not** the baseline. It is not an ancestor of `b96ffdf`.

## Baseline identity

| Item | Value |
|---|---|
| Repository | `/mnt/holochain/offloaded/sf/Downloads/holochain-mpc-core-v0.3.3-dkg-source/holochain-mpc-core` (`~/Downloads/...` resolves here) |
| Git remote `origin` | `https://github.com/ConorTttttt/holochain-mpc-core.git`. The `holochain-threshold-cryptography` URL serves identical refs; it is presumably a rename redirect |
| Branch checked out | `feature/v0.4.0-phase5c-live-writes` |
| HEAD | `544270fb1e50a38ef53d08ca71686be02a2eba7f` (tag `v0.3.8`) |
| Working tree vs HEAD | Dirty: 13 tracked files modified, 62 untracked paths (`git status --porcelain=v1`, 75 lines) |
| Authoritative commit | `b96ffdffd70fba065d3951ada416d4b39d17d73a`, "checkpoint: v0.4.0 security review remediation (R1-R5), 22 Oct 2026" |
| Commit parents | `0af1d2d` (Phase 8 checkpoint) and `544270f` (HEAD) |
| Extra source state | `docs/agent-briefs/` (8 files, untracked, 26 Oct 20:36) |
| Files in baseline | 129 (121 tracked in `b96ffdf` plus 8 briefs) |
| `git archive b96ffdf` tar SHA-256 | `a9af8f47137749fb419216b9904011c8a122f0c56aabb311dcb27eef83c02787` |
| Baseline manifest | `dkg-v040-integration/evidence/baseline-manifest.sha256` (129 lines) |
| Baseline manifest SHA-256 | `2803c864a48861730f11694e027cd24ea56bbab20362ffa907c9803f08d92419` |
| Pristine copy | `dkg-v040-integration/baseline/` (read-only) |

### Key file hashes (SHA-256, baseline)

| File | SHA-256 |
|---|---|
| `Cargo.toml` | `cbe25f413dff3d571221a54fd2fb36483e5179418a760630a62312b18e69b041` |
| `Cargo.lock` | `fafeff7914869eff12fc4efbf0ee112c31b2f774f99f146100d225e42746a866` |
| `package.json` | `6e877814ab27309911585337c78555a60e12b53713f5b96297d3db17d22fdd2d` |
| `crates/mpc-dkg-worker/Cargo.toml` | `cfdb4bd1eb22205466b65bc57d5d1651f83e23930fc7e48f65ca024d4ccbdeb6` |
| `crates/mpc-dkg-worker/src/signing.rs` | `dd48aa8880869d943ef9db3a2fcff15f1f49bc41e24c5ee698cd9b6928f14d60` |
| `crates/mpc-dkg-worker/src/sign_main.rs` | `18fa24ca928b8aa4c247f9f8a33268b70ec6274776cb05819f318e08b7a6ad58` |
| `crates/mpc-runtime/Cargo.toml` | `429f366ed0ec16daef3170a1c8940f46dfbf9ad17497c519814274d177f54285` |
| `crates/mpc-runtime/src/lib.rs` | `7e744634c5aa008a200b4f3989bdb9ec3ff11082d918c3adc12ce370955ffa10` |
| `dnas/mpc/zomes/integrity/mpc_integrity/src/lib.rs` | `8a753e5ab24f459e192ece62080f44d0fe12e8fa406cc829b2e852df9b1e7f32` |
| `dnas/mpc/zomes/coordinator/mpc/src/lib.rs` | `ba81cd223ddc60490926cb749c175af524042fa8524d4c9e7ba3ad7cb8f1700c` |
| `scripts/phase6_rehearsal.py` | `4c610119d13b0a318d6b40c74cdcaf21c6ec10c8ecebabb3a1fd3cc26adc7ec1` |
| `docs/V040_PHASE8_SIGNING.md` | `372189b5cf7d48119b9a8073e88385043231841fb4fec4b135ed7238e9ef7ab4` |
| `docs/V040_SECURITY_REVIEW_2026-10-22.md` | `9787efb6af27e945d2ec6a553ea3bca45eda5764bd7e7d0f68c0977a82a5b07d` |
| `docs/agent-briefs/00-COMMON-RULES.md` | `90f3789a470859ded54679d72c581799a8c4c107b6912db241ab235033d94364` |

Reference build artifacts from 22 October (main tree, not rebuilt by this
stage's baseline step):

| Artifact | SHA-256 |
|---|---|
| `dnas/mpc/workdir/mpc.dna` (22 Oct 06:18) | `7f77af71ba633536139f77702de1d8e74b77b8f437f33bf9328ec3856d7f7452` |
| `workdir/holochain-mpc-core.happ` | `38efb4a9bcc3accd2eff2da0fbf451c8f1d981b366819d00c1eac52655bac1e5` |
| DNA hash (deployed, per handover and `release_hashes.json`) | `uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu` |

## How the baseline was identified

1. `git log --all` and `git for-each-ref refs/checkpoints`. They show five
   local-only checkpoint commits.

   | Ref | Commit | Parent(s) | Date |
   |---|---|---|---|
   | `phase5cc-security-review-20261018` | `ecc08a6` | `544270f` | 18 Oct |
   | `gate0-b1b2-20261022` | `4b1b166` | `544270f` | 22 Oct 05:15 |
   | `phase6-7-20261022` | `f0a78aa` | `4b1b166` | 22 Oct 06:35 |
   | `phase8-20261022` | `0af1d2d` | `f0a78aa` | 22 Oct 07:10 |
   | `security-review-20261022` | `b96ffdf` | `0af1d2d`, `544270f` | 22 Oct 14:10 |

2. `git archive b96ffdf | tar -x` into a scratch directory. Then
   `diff -rq` against the live working tree, excluding `.git`, `target`,
   `workdir` and `node_modules`. Result: identical, apart from
   `docs/agent-briefs/` and `scripts/__pycache__/`. `workdir/happ.yaml` and
   `dnas/mpc/workdir/dna.yaml` were compared separately and are identical.
3. Each agent's preserved `baseline/` directory (Agents 2, 4 and 5) was
   compared with the `b96ffdf` export the same way. All three are
   identical, and their `docs/agent-briefs/` are identical to the main
   tree's.
4. The copies of Agents 1 and 3, which kept no baseline, were compared with
   the export. They differ only by new files the agents created. Agent 6's
   copy holds only `ui/` and `docs/V040_VAULT_UI.md`, and its patch
   headers say `empty-base`.
5. The handover (Claude Docs, rev 32) gives the evidence cut-off as
   22 October and names `b96ffdf` as the latest checkpoint (risk R6).

Package versions and branch names were not used as evidence. The branch
name `phase5c-live-writes` and the folder name `v0.3.3` are both
historical.

## Relationship to `ecc08a6`

- `ecc08a6` ("Phase 5C-C offline source and security review (NO-GO)",
  18 Oct) has parent `544270f`.
- `git merge-base --is-ancestor ecc08a6 b96ffdf` is **false**. The
  22 October chain starts from `544270f` again (`4b1b166`'s parent is
  `544270f`). It is a later, independent snapshot of the same working
  tree, not a descendant.
- `ecc08a6` → `b96ffdf`: 41 files changed (13 added, 28 modified;
  +3,828/−144 lines). These are the Gate 0, Phase 6, 7 and 8 work and the
  22 October review fixes.
- Conclusion: `ecc08a6` is the 18 October NO-GO archive. It is the right
  base for none of the agent patches. The handover's advice to "review the
  full diff against `ecc08a6`" is stale. Review against `b96ffdf`, or
  against `544270f` for the whole v0.4 delta.

## Relationship to GitHub

`git ls-remote` (read-only, 27 October, 11:3x UTC) shows the following.

| GitHub ref | Commit |
|---|---|
| `main`, `feature/v0.3.4-distributed-dkg` | `8dec22361b484f79c309c10f7dbbbe26e4ab47d5` (tag v0.3.3) |
| `feature/v0.3.5`…`v0.3.7` | `f0661f4f725616b715f9da874ad524b323b0a3aa` |
| `feature/v0.3.8`…`v0.4.0-*` (10 branches) | `544270fb1e50a38ef53d08ca71686be02a2eba7f` (v0.3.8) |

- No `refs/checkpoints/*` exist on GitHub, and no commit after `544270f`.
- GitHub `main` → `544270f`: 33 files changed. `544270f` → `b96ffdf`:
  73 files changed (60 added, 13 modified; +14,787/−52 lines). Name list:
  `evidence/github-544270f-to-b96ffdf.name-status`.
- All Phase 3–8 code, including `scripts/phase6_rehearsal.py`,
  `mpc-sign`, `signing.rs`, `signing_signer.rs` and every `docs/V040_*`
  file, exists only locally: in `b96ffdf` and the working tree.
- The `feature/v0.4.0-*` branch names on GitHub all point at v0.3.8 code.
  They contain no v0.4 work.

## Uncommitted state preserved

The baseline contains work that is in no commit. `docs/agent-briefs/` is
the agent instructions. It was copied explicitly into
`dkg-v040-integration/baseline/` and into the integration tree. Its file
hashes are in the baseline manifest.

Excluded on purpose: `target/` (build output), the main tree's
`workdir/*.happ` and `dnas/mpc/workdir/mpc.dna` (build output, hashed above
for reference), and `scripts/__pycache__/` (bytecode written 27 Oct 07:14,
probably by Agent 5's rehearsal importing `phase6_rehearsal.py`). No
runtime state, keystore, token or secret is part of the source tree.

## Unresolved provenance ambiguity

- **None for source.** Content equality was shown three independent ways:
  the live tree, a commit export, and the agents' own baselines.
- The operator's copy has a `.git/index` that was last written on
  22 October 13:53, before the `b96ffdf` commit (14:10). The checkpoint was
  made through a temporary index, as recorded. `git status` shows no staged
  entries (every line is ` M` or `??`), so the index describes HEAD
  (`544270f`), not `b96ffdf`. This is expected.
- Toolchain split, resolved. The `holochain` and `hc` on `PATH`
  (`~/.cargo/bin`) report 0.7.0. The rehearsal and fault harnesses
  (`tool_path()`) prefer `/nix/store/fx8695w5…-holochain-0.7.1` (reports
  `holochain 0.7.1`) and `/nix/store/r29yxqcd…-lair-keystore-0.7.1`.
  `npm run build:happ` packs with the `PATH` `hc` 0.7.0. The rebuild's
  byte-identity check (integration report) shows whether that matters.
- The original working tree's index SHA-256 was `29ff115d…e21cf` and HEAD
  was `ref: refs/heads/feature/v0.4.0-phase5c-live-writes` at the start of
  this stage. Both are re-checked at the end (see the integration report).
