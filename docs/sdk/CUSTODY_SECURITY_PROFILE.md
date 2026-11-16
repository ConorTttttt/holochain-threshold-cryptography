# S1-H01 — Native custody security profiles (Sprint 1 / Agent 8)

**Status: HARDENED CANDIDATE ONLY; PRODUCTION REFUSED; S1-H01 OPEN / HIGH.**
**Date:** 16 November 2026. **Base:** Sprint 1 integration branch
`sprint1/agent6-stage2c-integration-20261116` at
`899e433d057a4d1a0533e2304a2493edb75ad82f`.

This profile describes *local, enforceable configuration checks*, not production
key custody, certified external rollback, or a successful privileged-process
deployment. Never use it with real funds or live valuable shares. Development
provisioning is intentionally unchanged.

## Existing controls retained (not reinvented)

- `crates/mpc-runtime/src/custody.rs`: `KeySource::StateDirectory`
  (`storage.key`, development only), `KeySource::File` (outside the journal
  directory), `KeySource::SystemdCredential` (`$CREDENTIALS_DIRECTORY/<name>`);
  `Layout::Development` and `Layout::Separated`; owner/mode, directory
  ancestor, symlink/hard-link, leftover-key, role-path, and anchor-path checks.
- `crates/mpc-runtime/src/chain.rs` and `RuntimeStore::open_anchored`:
  authenticated, salted journal chain and authenticated append-only-format
  software anchor; detects a stale journal **when the anchor is not rewound**;
  uses fsync and refuses missing, altered or non-extending history.
- `mpc-custody backup/restore`: authenticated encrypted snapshots excluding
  `storage.key` and `ipc.key`. Restore refuses old backups if its anchor
  survived and advanced. `retire-epoch` and `erase-share` are irreversible
  at the journal layer. See `docs/V040_PHASE7_CUSTODY_HARDENING.md` and
  `docs/V040_PHASE7_SHARE_CUSTODY.md`.

The default `mpc-node provision` still generates both `ipc.key` and
`storage.key` in the private state directory and an adjacent software anchor.
Its `0600` permissions are **not** offline-disk protection, same-UID
containment or whole-VM snapshot protection.

## Profile contract

| Layout in `custody.json` | What the build enforces | Claim |
|---|---|---|
| `development` | Existing 0700/0600 checks, locally stored key permitted, software anchor outside the state directory | **Development only**; unchanged |
| `separated` | Existing non-state-directory key, external anchor in a directory not writable by the custody user, distinct ownership for configured `separate_from` paths | **Partially isolated; not production** |
| `hardened` | Exactly three ordered role roots, systemd credential source only, private **distinct non-root owner UID** for every role directory, root-owned non-group-writable anchor parent, and all separated checks; leftover `storage.key` and a credential resolved inside the state directory refused | **Software-checked candidate, NOT production** |
| `production` | **Always refuses** in `CustodyConfig::validate`, including `SystemdCredential` and external `File`. `StateDirectory` receives a specific rejection. No operator override. | **NOT VERIFIED / unavailable** |

The new fail-closed `production` variant is deliberate. Without a measured,
protected key source *and* a trusted witness that cannot be rewound by the
journal's snapshot administrator, accepting production would be a false
security claim. `LoadCredential=` is not proof of encryption; even
`LoadCredentialEncrypted=` can be host-key (not TPM) sealed. Configuration
strings and filesystem device numbers do not prove hardware custody or snapshot
isolation. A root-owned directory or `chattr +a` does **not** survive a VM
snapshot that includes it.

Example *shape only* for a future hardened-candidate installation; the current
relay and Lair IPC path cannot yet run all these roles under separate UIDs:

```json
{
  "schema": 1,
  "anchor": "/var/lib/mpc-anchor/node-1.custody-anchor",
  "master_key": {"kind": "systemd_credential", "name": "mpc-storage-key"},
  "layout": "hardened",
  "separate_from": [
    "/var/lib/mpc-relay/node-1",
    "/var/lib/mpc-lair/node-1",
    "/var/lib/holochain/node-1"
  ],
  "retired_share_retention_days": 30
}
```

Ordering of `separate_from` in *hardened* is **relay, Lair signer,
conductor**; each directory must be a non-symlinked `0700` directory owned
by a distinct non-root UID different from the custody UID. Runtime checks
also require the anchor file to be owned by the custody user, with one link and
no group/other write permission, and the anchor parent to be root-owned, not
group/other-writable and not symlinked. The custody process must not run as
root. This verifies static directory identities, **not who is actually
running each daemon**. The systemd credential path must resolve outside
the journal's state directory.

To prepare a candidate on an isolated test system, use a separately
provisioned credential and `mpc-custody init <legacy-state-dir> --anchor
<root-protected-anchor> --key-credential mpc-storage-key --hardened
--separate-from <relay-root> --separate-from <lair-root>
--separate-from <conductor-root>` *only for a state directory without
`custody.json`*. `init` is **trust-on-first-use** and cannot verify previous
rollbacks. It is not an upgrade tool for an already-provisioned development
`custody.json`, and it does not configure Linux services or mount boundaries.
Do not move a secret or delete `storage.key` before safely completing a
separately documented operator migration. `--production` cannot initialise.

## Required process / operating-system separation

| Role | Intended UID | Privileged material | Mandatory boundary / current gap |
|---|---|---|---|
| Custody worker + native FROST signer | `mpc-custody` | encrypted share journal and *in-process* key | 0700 state directory, private key/credential, authenticated nonce and approval checks |
| Bridge / relay | `mpc-relay` | its own narrowly scoped IPC credential | **GAP:** `bridge_credentials` reads `ipc.key` inside custody's 0700 directory; `controller.sock` there is 0600 |
| Lair signing service | `mpc-lair` | Lair root, Lair key material | **GAP:** `socket_signer.rs` / `lair_signer_main.rs` enforce same-UID peers; `lair_signer.rs` requires its keystore root under that UID |
| Holochain conductor | `mpc-holochain` | conductor data, app token | Separate process UID and explicit signed-call policy; no custody path or master-key access |
| Anchor administrator / independent witness | root / separate operator | anchor directory / future witness signing authority | Root-controlled anchor directory helps against ordinary file replacement, **not** root or snapshot administrator; no external witness connector exists |

A directory owner check is not process isolation. Real service units must
pin `User=`, `Group=`, supplementary groups, `NoNewPrivileges=`, restrictive
`UMask=`, filesystem namespaces / `ProtectSystem=`, private mounts,
capability drops, and narrow socket peer credentials. Do not grant conductor,
relay or Lair the custody UID or access to its journal/credential. The
bridge and Lair UID gaps above must be corrected, tested with real process
credentials, and independently reviewed **before** advertising end-to-end
separation. The worker currently remains both custody and cryptographic signer;
protecting against compromise of *that same UID* requires a stronger key-use
boundary (HSM/TPM-backed operation or equivalent).

## Snapshot and witness acceptance gate

A future production implementation must accept **fresh monotonic evidence**
from an independently administered source *outside the snapshot/rollback
domain* and bind it to the exact journal identity and authenticated chain
head. It must check the witness **before** loading shares, DKG work, nonce
reservation, or signing; record evidence durably **before** declaring each
journal mutation complete; permit only authenticated extension after a crash
and refuse stale, missing, wrong-node, unreachable and forked evidence.
Rewinding the state **and local anchor** while keeping the witness advanced
must refuse restart before nonce publication. A local second file is not a
witness. No such provider or hardware environment was available here, so
**none of this is claimed implemented or verified**.

An operator cannot “fix” a rollback refusal by deleting/replacing the anchor,
re-creating `custody.json`, or resetting a group epoch. Re-key/re-propose with
disposable identities; there is no safe re-anchor or reshare override.

## Backup, restore, restart and rollback procedure (disposable only)

Stop the worker/signing process, ensure no open operations, and retain a key
backup in a *different administrative and snapshot boundary*. On a development
fixture, take `mpc-custody backup <state-dir> --out <absolute-file>`, copy the
encrypted bundle away, and confirm `mpc-custody verify <state-dir>` checks
the current anchor. Never include unencrypted `storage.key` or a live IPC key
in the journal backup. Restore into a **new, nonexistent absolute directory**
with `mpc-custody restore --bundle <file> --state-dir <new-dir>
--master-key-file <separately protected 32-byte-key-file> --confirm-restore`;
the current CLI loads that separate key file transiently. This does **not**
satisfy hardened/production physical custody. Verify it again before
restarting; replay the same proposal only if the journal and anchor are
current and lifecycle allows it. A backup taken before subsequent signing
or retirement must fail and must leave no restored state behind. Test a
crash/restart during an operation with disposable shares; never reissue the
nonce/operation. If the anchor is lost, restoration fails by design.

### Tests and evidence

```sh
cargo test --locked -p holochain-mpc-runtime --test custody_security_profile
cargo test --locked -p holochain-mpc-runtime --test durable
cargo test --locked -p holochain-mpc-dkg-worker --test share_custody
# Root ONLY, isolated disposable Linux fixture; intentionally ignored by default:
cargo test --locked -p holochain-mpc-runtime --test custody_security_profile \
  test_separated_uids_cannot_read_custody -- --ignored --exact
```

| Required test | Scope | Current status |
|---|---|---|
| `test_production_layout_rejects_state_directory_key` | Rejects local key and **all** unverified production sources | **SOURCE ADDED; NOT RUN** |
| `test_separated_uids_cannot_read_custody` | Privileged Linux fixture checks other UIDs cannot open 0700/0600 paths | **IGNORED / NOT VERIFIED**; does not prove live IPC separation |
| `test_whole_state_snapshot_rewind_refused` | Demonstrates that coordinated *software* journal+anchor rewind is otherwise accepted; asserts production configuration refuses startup | **SOURCE ADDED; NOT RUN**. **EXTERNAL-WITNESS ACCEPTANCE NOT VERIFIED** |
| `test_development_backup_restore_restart_with_disposable_share` | Encrypted share backup, successful current restore/reopen, stale restore refused | **SOURCE ADDED; NOT RUN** |
| Existing Phase 7 `durable.rs` / `share_custody.rs` | Partial-journal rollback, restart, signature/nonce and retention regressions | **NOT RERUN HERE** |

No Rust/Cargo/Nix tools or privileged multi-UID environment are available in
this agent's execution container; a GitHub source-only commit does **not**
establish compile or runtime correctness. CI and an independent custodian
must execute the tests. A green local `test_whole_state_snapshot_rewind_refused`
does **not** close the requirement for an independent rollback witness.

## Residual attacks and deployment decision

**Out of scope / not prevented:** root, kernel, hypervisor or privileged host
administrator compromise; malicious code under the custody UID reading the
credential and decrypting a share; a captured unlocked systemd credential;
key exfiltration by in-process signer code; side channels; rollback of *all*
software evidence together; Lair/conductor process compromise and DoS; power
loss or clock manipulation; lost anchors or credentials; snapshot recovery of
erased ciphertext from backups or flash media. Compromise of one share is not
by itself a threshold group-signature forgery. No mechanism in this profile
provides authenticated remote witness, hardware non-exportability, or
privileged-host defenses.

**Gate:** S1-H01 remains **OPEN / HIGH / RELEASE BLOCKING**. A verified,
separately protected key source, independently operated monotonic rollback
witness, process-UID integration, backup/restore rehearsal, and independent
security approval are required before a production claim. Do not change
release hashes or release inventories to make a draft green.
