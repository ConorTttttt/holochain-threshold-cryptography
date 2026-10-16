# v0.3.7 — Encrypted DKG journal and fail-closed restart

## Scope and threat model

This release adds **write-ahead, encrypted DKG checkpoint metadata** to the
native worker. It does **not** persist or restore the FROST Round-1 secret
package, Round-2 secret packages, the final FROST `KeyPackage`, or any
signing nonces. A restarted worker can **never resume the same DKG proposal**.
Crash safety means permanent refusal to reuse its cryptographic ceremony,
not transparent continuation. Starting a new DKG requires **a new on-chain
proposal action** and fresh randomness, with explicit application consent.

This is necessary because there is no reviewed/verified serialization or
restart-proof replay design for intermediate FROST secret packages in this
prototype. Writing their raw contents to SQLite would be inappropriate.

## Protocol integration

The existing `--test-authenticated-stdio` bootstrap optionally accepts an
independent, randomly generated `master_key` and a per-worker database path.
This provisioner is **trusted**. Do not deploy the test bootstrap as a
production RPC interface.

`AuthenticatedController::new_durable` checks the encrypted database for a
prior `(proposal_action, worker_agent)` record. Every prior state, including
`running`, `completed` or `aborted`, refuses restart. Bad keys, tampering and
session rebinding also refuse restart.

After verifying an authenticated `Init` command and exact ceremony identity,
`dkg_begin` creates a SQLite durable record **before** FROST produces secrets
or announces Round 1. Before emitting each authenticated outward reply, the
worker stores a fresh XChaCha20-Poly1305 encrypted checkpoint with a strictly
increasing revision and a SHA-256 domain-separated digest of the outward
public/ciphertext-only reply. `Finalize` transitions the marker to `completed`;
any controller rejection records `aborted` and destroys volatile secrets.

The journal is opened with WAL and SQLite `synchronous=FULL` through the
existing native runtime. Each transition is protected by SQLite transactions,
unique constraints, and authenticated encryption associated data bound to
proposal/owner/session/state/revision. Public and ciphertext reply digests are
recorded; **plaintext FROST secret packages never enter this journal**.

## Security properties and limits

- **Proven by intended tests, subject to compilation:** a terminated worker
  cannot re-init the same proposal, independent of channel rekeying; tampered
  encrypted metadata, wrong key and conflicting state revisions fail closed;
  failed authentication creates a durable abort tombstone.
- **Does not guarantee:** anti-rollback if an attacker restores an earlier
  database snapshot, OS-level permissions against privileged local actors,
  secure key provisioning, disaster recovery of completed FROST keys, or
  liveness under a malicious participant.
- **Operational requirement:** database and key must be protected separately.
  A lost encryption key makes the journal unreadable. **Never delete the
  journal to "recover" a failed ceremony**: doing so removes anti-reuse
  evidence. Rotate to a fresh proposal using an independently verified
  authorisation workflow.
- **DoS trade-off:** deliberately fail-closed rejection can tombstone a
  proposal after a single unauthorised IPC attempt. Limit endpoint access.

For production use, a trusted OS/Lair-backed key manager and rollback-resistant
lifecycle storage are still necessary. Integration with conductor provenance
must be independently authenticated, not asserted only by the test harness.

## Tests

```bash
npm run test:dkg-durable
npm run test:worker-restart
npm run test:worker-unit
npm run test:dkg-process
npm run test:native
npm run test:sweettest
```

The new tests are designed to verify encrypted persistent checkpoints,
replay/restart rejection, concurrent start, key mismatch, SQL tampering, and
real process termination. They are **not verified to compile or pass** until
executed in Holonix with the Holochain 0.7.1 dependencies.

Next: provision master keys from OS/Lair or another trusted keystore, add
rollback-evident externally authenticated epochs, then design independently
reviewed encrypted final-KeyPackage storage before claiming recoverable groups.
