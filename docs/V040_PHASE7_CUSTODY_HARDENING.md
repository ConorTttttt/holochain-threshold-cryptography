# v0.4.0 Phase 7 hardening — anti-rollback, key separation, backup and lifecycle

26 October 2026 (Europe/London). Implemented offline by the coding assistant
from the Agent 2 brief (risk R3, the Phase 7 remainder). **Development
evidence, not production custody, not an independent audit.** This is still
not production key custody. It needs the independent review (Agent 7) before
any valuable use. No conductor, Lair, credential, persistent sandbox or live
key was touched. All keys in the tests are synthetic.

## Result

A journal restored from an older copy, or a stale backup, is now refused
before any nonce is reserved:

- An authenticated custody chain inside the journal is anchored to an
  append-only file outside the state directory.
- `mpc-node serve`, `recover_share` (and so `mpc-sign` and `activate-group`)
  and `SigningSession::begin` check it.

Custody also refuses unsafe ownership, modes and key placement. Encrypted
backup and restore, epoch retirement, best-effort erasure and retention are
operator commands (`mpc-custody`). The new rollback test fails against the
pre-change sources and passes after. `npm run test:native` passes 130 of 130.
The live three-node rehearsal could not be rerun on this host (see Limits).

## What changed

### 1. Anti-rollback evidence (task 1)

Before this change, restoring an older `journal.sqlite` silently removed
operation deadlines, nonce reservations and burns made after the copy. FROST
nonces are random and never stored, so a rollback could not replay a nonce or
leak the key. It could, however, reopen an operation slot, so the group could
sign an already-signed operation again with fresh nonces.

- **Custody chain.** Every committed journal write (DKG admission and replies,
  share sealing, deadlines, nonce reservation, commitment burn, abort, expiry,
  activation, retirement, erasure) appends one event to `custody_log` and
  advances `custody_head` in the same SQLite transaction. The chain value is
  `H(previous ‖ seq ‖ label ‖ event digest ‖ random salt)`. The head carries an
  XChaCha20-Poly1305 tag under the node master key, so it cannot be moved
  without the key. The salt means that replaying the same writes after a
  restore still yields a different chain.
- **External anchor.** After the commit, and before the write call returns,
  the head `(seq, chain)` is appended to an anchor file as an authenticated
  record (`flock`ed, fsynced). The anchor lives outside the state directory:
  by default `<state-dir>.custody-anchor` beside it, created by
  `mpc-node provision`. Records must strictly increase, so an old record
  appended again is refused rather than read as the latest.
- **Startup and post-commit check** (`RuntimeStore::open_anchored`,
  `check_anchor`). The journal is refused (`anti-rollback check failed: ...`)
  when its authenticated head is:
  - behind the last anchor record (a restored older journal);
  - at the same position with a different chain;
  - ahead but not an extension of it (a restore followed by new writes);
  - bound to a different anchor;
  - or when the anchor is missing, malformed or fails authentication.

  A journal ahead of its anchor is normal after a crash between commit and
  append. Its logged events must lead exactly from the anchored record to the
  head, and the anchor then catches up.
- **Where it is enforced.**
  - `mpc-node serve` checks before any DKG state is touched, and anchors the
    DKG's writes when its single connection ends.
  - `recover_share`, used by `mpc-sign` and `activate-group`, returns an
    anchored store, so every nonce reservation and burn is anchored before it
    returns.
  - `SigningSession::begin` re-checks right before the deadline is
    registered.
  - A restored older journal therefore never reaches nonce reservation.

The anchor is only as strong as its placement (see the threat table). The
development default, beside the state directory under the same user, stops a
restore of the journal or the state directory, not a restore of the whole disk
or an attacker running as that user.

### 2. Nonce safety across crashes (task 2)

Each signing step is one SQLite transaction, followed by an anchor append.
A crash leaves the journal in exactly one of these states. The new tests kill
the signer with `SIGABRT` (no destructor, flush or rollback runs) right after
each step:

| Crash after | Nonce row | Lifecycle | A restart of the operation |
|---|---|---|---|
| `start_deadline` | none | `open` | refused (deadline already registered) |
| `reserve_nonce` | `reserved` | `open` | refused; the slot cannot be reserved again |
| `authorize_commitment` (commitment burnt before release) | `published` | `open` | refused |
| signature share computed, not sent | `published` | `open` | refused; the in-memory nonce died with the process |
| `record_abort` | `burned` | `aborted` | refused |
| deadline expiry | `burned` | `aborted` | refused |

A crash between a commit and its anchor append leaves the journal one or more
events ahead of the anchor. That is accepted and caught up, because the
logged events extend the anchored history; a crash is not a rollback. A fresh
operation still signs after every crash.

### 3. Key-ownership separation (task 3)

`custody.json` (mode 0600 in the state directory) records the anchor path, the
master-key source and the layout. `Custody::load` runs before `serve`,
`recover_share` and every `mpc-custody` command, and refuses to start when:

- the process runs as root;
- the state directory is not owned by this user with mode 0700, or any
  ancestor (lexical or resolved) is owned by another non-root user, writable
  by others (a root-owned sticky `/tmp` is accepted), or group-writable by
  any group other than this user's own primary group. That exception covers
  umask-0002 user-private-group setups such as this host, and
  `custody_check.sh` still warns about it;
- `custody.json`, `node.json`, `storage.key` or `journal.sqlite` is a
  symlink, has more than one link, is not owned by this user, or has any
  group or other permission bit set. The journal's `-wal` and `-shm` files
  must not be writable by group or others. `serve` now creates the journal
  0600 so SQLite's side files inherit that mode;
- the anchor is missing, inside the state directory, a symlink, hard-linked,
  not owned by this user, or writable by group or others;
- the key source is unsafe:
  - **`state_directory`** (`storage.key`; what `provision` writes) is accepted
    only in the development layout;
  - **`file`**: an absolute path outside the state directory. The file must be
    owned by this user with mode 0400/0600, or owned by root with mode 0440
    and this user's group, and its ancestors must be safe. A leftover
    `storage.key` beside the journal is refused;
  - **`systemd_credential`**: `$CREDENTIALS_DIRECTORY/<name>`, provided by
    `LoadCredentialEncrypted=` (sealed to TPM2 or the host key) or
    `LoadCredential=`. It must be private to this user;
- in the **separated** layout, also: the key is not in the state directory,
  the anchor's directory belongs to another user (root) and is not writable by
  the custody user, and every `separate_from` path (the Lair keystore root,
  the conductor data root) belongs to a different user.

**Target layout.**

| Role | OS user | Holds | Can reach |
|---|---|---|---|
| Node: Holochain conductor and its data | `mpc-holochain` | conductor DB, app token | app websocket on localhost |
| Lair: keystore and `mpc-lair-signer` | `mpc-lair` | Lair root (0700), passphrase prompt | its signer socket |
| Custody signer: `mpc-node serve`, `mpc-sign`, `mpc-custody` | `mpc-custody` | state directory (0700), journal, sealed share | its own files; the master key via the key source |
| Anchor directory | root, mode 0755 | `<node>.custody-anchor`, owned by `mpc-custody`, `chattr +a` | appended by `mpc-custody` only |
| Master key | root / systemd | `LoadCredentialEncrypted=mpc-storage-key:...` | readable only inside the `mpc-custody` units |

Example `custody.json` for that layout:

```json
{
  "schema": 1,
  "anchor": "/var/lib/mpc-anchor/node-1.custody-anchor",
  "master_key": { "kind": "systemd_credential", "name": "mpc-storage-key" },
  "layout": "separated",
  "separate_from": ["/var/lib/mpc-lair/node-1", "/var/lib/holochain/node-1"],
  "retired_share_retention_days": 30
}
```

**Not yet runnable end to end.** Code outside this brief's scope still
requires one user for several roles, so the full separated layout cannot run
today:

- `socket_signer.rs` and `lair_signer_main.rs` accept a signer-socket peer
  only with the same UID (`SO_PEERCRED`), and `lair_signer.rs` requires the
  Lair root to be owned by that UID. Lair and the custody signer therefore
  share a user.
- The relay reads `ipc.key` from the 0700 state directory
  (`node_service::bridge_credentials`) and connects to `controller.sock`
  inside it, so the relay shares the custody user.
- Only the conductor can run as a separate user today (it is reached over
  the websocket with a token file).

These are follow-ups (see Limits). The custody checks are ready for them.

`scripts/custody_check.sh <state-dir> [--lair-root DIR] [--conductor-root DIR]`
audits a state directory without writing anything and without the key. It
prints PASS, WARN and FAIL lines and exits 1 on any FAIL. Its journal/anchor
comparison is unauthenticated. `mpc-custody verify` authenticates both.

### 4. Backup and restore (task 4)

- `mpc-custody backup <state-dir> --out <file>` first anchors any lagging
  commits and refuses a journal that is already behind. It then writes one
  file, encrypted with XChaCha20-Poly1305 under the master key. The file
  holds a consistent `VACUUM INTO` copy of the journal (sealed shares, nonce
  and operation journal, custody chain), plus `custody.json`, `node.json` and
  `group-descriptor.json`. The header (sequence number, anchor id, key
  source) is authenticated as associated data.
  - **Not included:** the master key (keep it in a separate, offline backup),
    `ipc.key` (needed only by a DKG, which never resumes) and
    `transport.sqlite`.
- `mpc-custody restore --bundle <file> --state-dir <new-dir>
  --master-key-file <file> --confirm-restore` restores into a directory that
  does not exist yet. It is refused when:
  - the bundle does not decrypt;
  - the anchor named in the backup is missing or belongs to another journal;
  - the backup is older than the anchor.

  The files are staged in a hidden 0700 sibling and checked with the full
  anchored open. Only then is the directory renamed into place. Nothing is
  left behind on refusal.
- **Freshness rule.** A backup is stale after the node's next journal write
  (any DKG step, signature, retirement or erasure), and a stale backup is
  refused. Take a backup after each signing session, while the signer is
  stopped.
- **Disaster limit.** If the anchor is lost together with the node, restore is
  refused by design. 2-of-3 tolerates losing that node. Resharing is not
  implemented. An override that re-anchors a backup is deliberately not
  provided (operator decision below).

### 5. Lifecycle: retention, deletion, rotation (task 5)

- `mpc-custody retire-epoch <dir> --proposal-hex .. --epoch N --reason ..
  --confirm-retire` is the rotation hook. It marks the epoch retired and does
  not reshare. In the same transaction it aborts this node's open operations
  in that epoch and burns their nonce slots. From then on the epoch refuses
  nonce reservation, share opening (so `recover_share`, `mpc-sign` and
  `activate-group` refuse) and sealing.
- `mpc-custody erase-share ... --confirm-erase` erases a retired epoch's
  share. `mpc-custody apply-retention <dir> --confirm-erase` erases every share
  retired longer ago than `retired_share_retention_days`. Both are one-way.
- Both transitions are logged in the custody chain, so restoring an older
  journal or backup to undo a retirement or to recover an erased share is
  refused as a rollback.
- **Secure erase is best effort.** `secure_delete` (now on for every journal)
  zeroes the deleted row in the main file, and a TRUNCATE checkpoint empties
  the WAL. Copies can still survive in backups, VM or disk snapshots,
  filesystem journals and flash wear-levelling. The share remains ciphertext
  under the master key. When no epoch under a key is needed any more,
  destroying that key (crypto-shredding) is the stronger step, and old
  backups must be destroyed too.

### Operator commands (`mpc-custody`, built with the runtime crate)

```text
mpc-custody verify <state-dir>
mpc-custody init <state-dir> --anchor <abs-file> [--key-file <abs-file> | --key-credential <name>]
            [--separated --separate-from <abs-path>...] [--retention-days <n>]
mpc-custody backup <state-dir> --out <abs-file>
mpc-custody restore --bundle <abs-file> --state-dir <abs-new-dir> --master-key-file <abs-file> --confirm-restore
mpc-custody retire-epoch <state-dir> --proposal-hex <78-hex> --epoch <n> --reason <text> --confirm-retire
mpc-custody erase-share <state-dir> --proposal-hex <78-hex> --epoch <n> --confirm-erase
mpc-custody apply-retention <state-dir> --confirm-erase
```

Run it as the custody user, never as root, and stop the signer before
`restore`. Nothing prints key material.

### Migration of existing state directories

Directories provisioned before this change have no `custody.json`, and
`mpc-node serve`, `recover_share` (and so `mpc-sign` and `activate-group`)
refuse them. Transport-key commands keep working. `mpc-custody init <dir>
--anchor <path>` adopts such a directory **on trust**: a rollback that
happened before adoption cannot be detected. The persistent 5B/5C sandboxes
were not touched; adopting them is an operator step.

## Threat table

| Threat | Control | Stops | Does not stop |
|---|---|---|---|
| An operator or backup tool restores an older `journal.sqlite` or state directory (file-level) | Custody chain + external anchor; checks in `serve`, `recover_share`, `begin` | The restored journal is refused before any nonce, share or signing step | A restore that also rewinds the anchor |
| A stale encrypted backup is restored | Header and journal checked against the anchor in `restore`, then again at the next open | The restore is refused; nothing is written | Nothing extra; same limits as the anchor |
| Journal rows or the head are edited without the master key (backup operator, another user with disk access) | Authenticated head; salted chain; recomputation on extension | Detected (wrong tag, history not extending the anchor) | Anyone holding the master key |
| A crash at any signing step | One transaction per step; the anchor is caught up only if the history extends it | No reserved or burned slot is reissued; no false rollback alarm | Liveness: the interrupted operation is lost, a new plan is needed |
| **Same-UID attacker** (code running as the custody user) | Only partially: the separated layout with a root-owned anchor directory and `chattr +a` stops replacing or truncating the anchor | Rewriting the anchor file in the hardened layout | Reading the master key (from `storage.key`, or from the credential inside the unit) and decrypting the share; signing anything outside the approval flow; deleting the journal (fail-closed denial of service) |
| **Root** | None | Nothing | Everything: clearing `chattr +a`, reading keys, rewriting journal and anchor together, attaching to processes |
| **Disk or VM snapshot restore** (journal and anchor rewound together) | Anchor placement only | Detected only if the anchor lives on storage the snapshot does not cover | Snapshot of a single volume holding both: an operation can be signed again. The FROST nonces are fresh, so the key itself is not exposed |
| Offline theft of the disk image | `systemd_credential` sealed to TPM2 (`LoadCredentialEncrypted=`) | Shares cannot be decrypted away from the machine's TPM | Development layout: `storage.key` is on the same disk, so the share is exposed |
| Other local, non-root users | 0700 directory, 0600 files, ancestor, symlink and hard-link checks, not-root rule | Reading custody files; swapping paths under the custody user | Kernel or root compromise |
| Lair or conductor compromise | Separated layout (target); approval and activation gates (Phase 8) | The conductor user cannot read custody files today. Lair isolation needs the follow-ups below | A compromised conductor can still deny service or inject frames, which abort the operation |
| Anchor deleted or substituted | Missing, foreign, tampered or replayed anchor is refused | Silent bypass | Denial of service (the node refuses to sign until the operator acts) |
| Erased share recovered from old copies | `secure_delete`, WAL truncation, chain-logged erasure | Restoring an older journal to undo erasure (refused) | Recovery from backups, snapshots or disk blocks while the master key exists (best effort only) |
| System clock moved back | None new | — | Deadline extension; slots are insert-once, so no nonce reuse |

## Tests

New tests. All are offline, with synthetic agents and keys and temporary
directories.

| Suite | Test | Shows |
|---|---|---|
| `test:runtime` (`durable.rs`) | `restored_journal_snapshot_is_refused_by_its_anchor` | A restored journal copy is refused ("older than"). Without the anchor, the same restored file hands the burned slot out again. Writing past the anchor's position does not launder the restore ("does not extend") |
| | `a_journal_ahead_of_its_anchor_catches_up_but_a_fork_is_refused` | Crash-window lag is accepted and caught up; a restore followed by more writes is refused |
| | `missing_foreign_or_tampered_anchors_fail_closed` | Wrong key, missing, foreign, flipped-tag and replayed-record anchors are refused; a torn final line is skipped |
| | `retired_epochs_refuse_signing_and_erasure_is_one_way` | Retirement aborts in-flight work and blocks reserve, open and seal. Erasure removes the ciphertext from the main file and the WAL. Restoring the pre-erasure journal is refused |
| | `custody_layout_refuses_unsafe_modes_and_misplaced_keys` | Loose key, directory or journal modes, symlinked or hard-linked keys, a key or anchor inside the directory, a leftover `storage.key`, separated-layout rules, a missing systemd credential and an ancestor writable by others are each refused; an external key file works |
| | `backup_restores_only_when_not_older_than_the_anchor` | The bundle is encrypted and never overwritten. A wrong key or a tampered bundle is refused. Restore works and reopens the share. A stale bundle is refused and leaves nothing behind |
| | `retention_erases_only_shares_retired_long_enough` | No policy means no erasure; erasure happens exactly at the retention boundary |
| | `mpc_custody_cli_verifies_and_refuses_a_rolled_back_journal` | `mpc-custody verify` passes, then fails after a restore; writes need `--confirm-*` |
| `test:share-custody` | `restored_journal_snapshot_is_refused_after_a_nonce_was_burned` | Real `mpc-node serve` DKG, then a 2-of-3 signing through `recover_share` and `run_signing`. Node 1's journal is restored from before the signing, and the signer refuses ("anti-rollback") |
| | `nonce_is_never_reissued_after_a_crash_at_any_journal_step` | SIGABRT after each of the six steps in section 2. The node reopens, the journal state is as tabled, `SigningSession::begin` and a direct `reserve_nonce` are refused, and a new operation still signs |
| | `serve_refuses_unsafe_custody_and_custody_check_reports_it` | `mpc-node serve` refuses a 0644 key and a missing anchor before creating any DKG state. `custody_check.sh` passes with warnings, then FAILs, and changes nothing |
| | `restored_backup_signs_two_of_three_and_a_stale_backup_is_refused` | Node 1 lost and restored from a bundle signs 2-of-3 with node 3. The same bundle is then refused |
| | `retired_epoch_stops_one_node_and_erasure_survives_a_restore_attempt` | A retired node refuses; nodes 1 and 3 still sign; erasure cannot be undone by restoring an older bundle |
| `test:signing-session` | `begin_refuses_every_prior_journal_state_of_the_operation` | After each prior journal state, the operation never restarts, and a fresh one signs |

`zz_crash_child_for_journal_steps` is the child half of the crash test and
does nothing on its own.

**Before and after.** `restored_journal_snapshot_is_refused_after_a_nonce_was_burned`
uses only the pre-hardening API. Run against the baseline sources (the
`security-review-20261022` checkpoint) in the same work tree, it **fails**:
"the restored journal was accepted; a second signing session for the burned
operation was started". With this change it passes.

**Commands run on the development host** (rustc 1.99, `--offline --locked`,
unchanged `Cargo.lock`):

- `npm run test:native`: 18 groups, **130 passed, 0 failed** (115 before; 15
  new). Among them:
  - `test:share-custody` 10/10;
  - `test:signing-session` 9/9;
  - `test:runtime` 12/12;
  - `test:security` 14/14;
  - `test:dkg-durable` 4/4;
  - `test:node-service` 1/1;
  - `test:worker-unit` 34/34.
- Feature-gated suites that use `node_service`:
  - `npm run test:transport-probe` 1/1 and 21/21;
  - `test:signing-signer` 2/2;
  - `test:phase5c-b-unit` 12/12 and 6/6.
- Sweettests with three in-process conductors: `conductor_bridge` 1/1
  (provision and `mpc-node serve`) and `three_processes` 1/1. They ran against
  the existing `mpc.dna`; the zomes are unchanged, so the hApp was not rebuilt.
- `check_release.py` and `check:holochain-versions`: PASS.
  `check:wasm-imports` was not meaningful in the work tree (no WASM build
  products were copied there, and no zome changed).

## Limits — still NOT production custody

- **Independent review required.** This design and code need the independent
  review (Agent 7) before any valuable use.
- **Same-UID and root.** See the threat table: a process running as the
  custody user can read the master key and decrypt the share. Only a hardware
  boundary (HSM, TPM-bound key use, or an enclave) changes that.
- **Software anti-rollback only.** There is no TPM NV counter or remote
  witness. An anchor on the same volume as the journal does not survive a
  whole-volume snapshot restore. Placing it on separate storage, or anchoring
  it with peers or on the DHT, is future work and needs a zome change.
- **Separated layout not exercised end to end.** It needs:
  - `socket_signer.rs` and `lair_signer_main.rs` to accept a pinned peer UID
    instead of their own;
  - `lair_signer.rs` to accept a Lair root owned by the Lair user;
  - the relay to stop reading `ipc.key` from the custody directory (for
    example a separate bridge credential or a group-accessible socket).

  Those files are outside this brief.
- **No re-anchoring.** A node whose anchor is lost cannot be restored from
  backup. Resharing is not implemented.
- **Backups go stale** after every journal write and must be refreshed by the
  operator. There is no automatic schedule.
- **Rehearsal.** Not rerun. Since 23 October `~/mpc-phase6-rehearsal` has been a symlink to
`/mnt/holochain/offloaded/sf/mpc-phase6-rehearsal`. Lair records the resolved
socket path, and `lair_signer.rs:248` compares it lexically with the symlinked
root, so the harness's first write (`propose`) fails before any custody code
runs (run `run-20261026T213814Z`, `logs/propose.log`). The fix belongs in
`lair_signer.rs` (canonicalise the root) or in the harness
(`Path.home().resolve()`), both outside this brief. The live
`mpc-sign` + Lair + conductor path is therefore not re-proven with this
change. The sweettests and the served-node tests above cover provision,
serve, `recover_share` and `run_signing`.
