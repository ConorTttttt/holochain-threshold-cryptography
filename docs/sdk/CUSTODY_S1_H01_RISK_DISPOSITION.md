# Agent 8 — S1-H01 custody risk disposition

**Date:** 16 November 2026  
**Severity:** HIGH  
**Finding:** S1-H01 from `docs/sdk/SPRINT1_SECURITY_REVIEW.md`  
**Decision:** **OPEN — CHANGES REQUIRED — PRODUCTION RELEASE BLOCKED**  
**Scope:** Separate draft branch based on Sprint 1 integration, not on stale `main`.

## Source-level disposition

| Condition | Before | After this branch | Verification |
|---|---|---|---|
| Default `mpc-node provision` stores `storage.key` beside encrypted journal | Present, development-only | **Unchanged by design** | Source-inspected only |
| External file / systemd credential key source | Implemented in Phase 7 | Reused; hardened candidate demands systemd credential | Source-inspected only |
| `separated` layout | Present with ownership checks | Preserved | Existing tests NOT RERUN |
| Production label accepts local key / anchor | No enforceable production profile | `Layout::Production` explicitly rejects `StateDirectory`, and rejects all other sources until verified backing exists | Added test; NOT RUN |
| Hardened candidate | No distinct profile | `Layout::Hardened` demands systemd credential, three distinct role-root UIDs, root-owned anchor parent, no state-key leftover or in-state credential resolution | Added tests; NOT RUN |
| Rollback of journal only | Detected when anchor stays advanced | Unchanged | Existing Phase 7 tests; NOT RERUN |
| Rollback of journal **and software anchor** | Not detected | **Still not detected by software anchor**; production startup refuses instead of claiming protection | New negative exposure test; independent witness NOT VERIFIED |
| Privileged / same-UID memory and credential access | Unprotected | **Still unprotected** | OUT OF SCOPE |
| Native relay, Lair and signer UIDs isolated and interoperable | Blocked by same-UID IPC and key location | **Not implemented**; static role-root ownership only | NOT VERIFIED |
| Full real backup/restore with independently hosted master key and witness | Not evidenced | **Not evidenced** | NOT VERIFIED |
| Release inventory / hashes | Operator-controlled | **Untouched** | Source diff to be reviewed |

## Acceptance criteria and evidence limits

1. **`test_production_layout_rejects_state_directory_key`:**
   source added; asserts all production configurations refuse. **NOT RUN**.
2. **`test_separated_uids_cannot_read_custody`:**
   intentionally ignored test requires a privileged, isolated Linux host.
   It checks kernel DAC inability to open a disposable custody directory,
   key and journal as three distinct other UIDs. This is not proof of
   process-to-process signer/relay communication. **NOT VERIFIED**.
3. **`test_whole_state_snapshot_rewind_refused`:**
   source added and deliberately demonstrates the local software-anchor
   weakness: coordinated state + anchor rewind can still open.
   `Layout::Production` is refused *before* reaching signing, which keeps
   the production claim fail-closed. A passing version of this negative
   test is **NOT** proof that an independent witness rejects a rewind.
   The original stronger acceptance test requires keeping an **external**
   witness advanced while rewinding *both* local artifacts. **NOT VERIFIED**.

An independent witness that is outside the journal snapshot domain must
be implemented and attested before any production profile can run.
The future test must fail a reinstated old journal before a nonce reservation
or any signature-share generation, and verify honest post-crash catch-up
against the witness with disposable shares. A local duplicate file, inode
owner, separate pathname or same-host append flag is insufficient.

## Remaining work for independent reviewers

- Prove a hardware / OS protected key that is not independently obtainable
  from the state snapshot (including how the systemd credential is sealed and
  unsealed); verify provisioning, backup, revocation and restore policies.
- Design/implement an independently administered monotonic witness and
  fail-closed pre-sign, post-commit and restart integration. Provide
  threat-model evidence for snapshot independence and unavailable witness.
- Split `ipc.key` from the custody directory, authenticate pinned peer UIDs
  across relay and FROST signer sockets, and adapt Lair root ownership so
  relay, Lair, conductor and custody can *actually run under distinct UIDs*.
- Run the ignored multi-UID test under root **only in an isolated test
  sandbox**, followed by a real multi-process check under those UIDs.
- Execute pinned Cargo tests, complete DKG + sealed share sign + restart,
  snapshot/backup/restore fault injection and external-witness rollback
  tests with recorded exit codes. No Rust/Cargo toolchain is present in this
  agent's container; tests and builds are **NOT RUN**.
- Request independent security review and operator approval; keep the
  Sprint 1 branch and PR draft and do not re-record release hashes or
  manifests to bypass gates.

**Residual impact:** offline disk compromise of development `storage.key`
and ciphertext; same-UID/key theft; root/hypervisor compromise; full-disk
snapshot rollback; stored ciphertext on old backups; denial of service by
lost anchor; process separation not end-to-end. See
`docs/sdk/CUSTODY_SECURITY_PROFILE.md` for controls and limits.

**Final disposition:** **S1-H01 OPEN / HIGH / RELEASE BLOCKER.**
