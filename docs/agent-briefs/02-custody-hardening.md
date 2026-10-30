# Agent 2: Share custody hardening (R3, Phase 7 remainder)

Read `00-COMMON-RULES.md` first, then `docs/V040_PHASE7_SHARE_CUSTODY.md`.

## Goal

Close the open Phase 7 items so custody is credible for a controlled test
deployment: anti-rollback evidence, key-ownership separation, backup/restore,
and an operator-controlled lifecycle. No live keys.

## Background

Shares are sealed write-once (XChaCha20-Poly1305, AAD-bound) by
`RuntimeStore::seal_share` and reopened by `recover_completed_share`. Today one
UID runs everything, master keys sit beside the encrypted databases, and SQLite
has no anti-rollback protection (R3, N2). Signing journals record reserved and
burned nonces; a rolled-back database could let a nonce be reused.

## Scope

You own: `crates/mpc-runtime/**`, `crates/mpc-security/src/sealed.rs`, custody
parts of `crates/mpc-dkg-worker/src/{node_service,signing}.rs` only where needed,
`crates/mpc-dkg-worker/tests/share_custody.rs`, and new files under `scripts/custody_*`
and `docs/V040_PHASE7_*`. Read-only: zomes, relay, Lair signer.

## Tasks

1. Anti-rollback: design and implement a monotonic evidence mechanism (for
   example a counter or hash chain anchored somewhere a database restore cannot
   silently rewind, plus a startup check). A restored older database must be
   detected and the signer must refuse to sign. Test: snapshot, burn a nonce,
   restore the snapshot, expect refusal.
2. Nonce safety: show a reserved or burned nonce can never be re-issued after a
   crash at every journal step (extend `test:signing-session`, `test:share-custody`).
3. Key-ownership separation: define the target layout (dedicated OS users for
   the node, signer and Lair; protected master keys with file modes and an
   external key source option). Implement checks that refuse to start on unsafe
   modes or ownership. Provide `scripts/custody_check.sh` that audits a state
   directory read-only.
4. Backup and restore: an operator command that exports sealed shares and
   journals (encrypted) and restores them, with a test that a restored node
   produces a valid 2-of-3 signature and refuses any state older than the
   anti-rollback evidence.
5. Lifecycle: operator-controlled retention, deletion (secure erase is best
   effort; say so) and epoch rotation hooks. Rotation here means marking an old
   epoch retired, not resharing.
6. Write `docs/V040_PHASE7_CUSTODY_HARDENING.md` with a threat table: what each
   control stops and what it does not (same-UID attacker, root, disk snapshot).

## Done when

`npm run test:share-custody`, `test:signing-session`, `test:runtime`,
`test:security` and `test:native` pass with the new tests, the rollback test
fails before your change and passes after, and the doc states plainly that this
is still not production custody and needs the independent review (Agent 7).
