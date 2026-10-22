# Phase 5C-C offline implementation report

> Security review status: **NO-GO for live deployment writes.** The subsequent
> [readiness review](V040_PHASE5C_C_SECURITY_REVIEW.md) identifies inherited
> controller/signer boundary gaps. Passing offline tests are not deployment
> approval. Use the [public read-only checklist](V040_PHASE5C_C_READ_ONLY_PREFLIGHT.md)
> only under its stated scope; it has not been executed.
> **22 October 2026:** B1/B2 are remediated in source with refusal tests (see
> the review's *Remediation* section). Live writes still need the read-only
> preflight and step-specific approval.

Date: 18 October 2026 (Europe/London). Scope: authorized source-only
implementation and synthetic offline tests. Live encrypted A → B delivery
remains a separate, unperformed milestone.

## Source preservation

The pre-implementation checkpoint is retained outside the Git repository at:

```text
../source-checkpoints/phase5cc-before-implementation-j70nwlvp/source.tar.gz
../source-checkpoints/phase5cc-before-implementation-j70nwlvp/manifest.json
archive SHA-256: 2a493bb4186b773cf2a0dd44bec40473cebc18c2b7a9f620dcd50d1bdf329baf
```

It contains 99 allowlisted project files: 61 tracked and 38 untracked,
including the pre-existing uncommitted modifications. Archive and manifest
are `0600`; containing checkpoint directory is `0700`. Every archive member
was checked against its manifest hash, and all original paths remain present.
No keystores, tokens, capability records, signer policies, persistent node
state, build artifacts or Git internals were included. No Git cleanup,
reset, branch switch, commit or staging operation was performed.

Diff review used this checkpoint as well as Git: much of the existing
implementation is untracked, so `git diff` alone cannot show its changes.
Both zome source files, the FROST provider, encrypted DKG journal, existing
security encryption implementation, controller implementation from `Active`
onward, and node `serve` path match the checkpoint exactly. The original
FROST signer authorization is unchanged except an explicit refusal branch
for the probe-only session-status enum variant. RuntimeStore's existing
implementation differs only by exporting the new probe module. Cargo.lock
adds development dependency edges for mocked-host compatibility tests; its
package/version inventory is unchanged from the checkpoint.

## Implementation delivered

- `transport_probe.rs`: separate protocol/spec builder, strict public plan,
  independent approved action/author/key pins, retained native identity,
  authenticated inner domain/DNA/ceremony/evidence/message identity, payload
  digest/limits, durable send admission and recipient replay checks.
- `probe_signer.rs`: separate opt-in policy schema with exact ceremony,
  key, direction and bounds; separate purpose/proposal/grant-bound credential;
  registration/read-only mode until a complete approved plan is installed.
- `transport_probe_main.rs`: bounded operator commands (`keys`, `register-key`,
  `inspect`, `send`, `receive`) with specific confirmation flags, no automatic
  provisioning, no retries, exclusive fsynced registration markers and no
  plaintext/secret output.
- Runtime `probe.rs`: lazy transactionally committed attempt and receipt
  tables. `pending` and `uncertain` attempts are terminal, including across
  restarts and changed plans. Conflicting ciphertext cannot reuse a receipt.
- Existing signed transport: typed, proposal-pinned `get_session_status` read
  for probe preflight. Existing FROST signer does not authorize that operation.
- `mpc-lair-signer --probe-profile`: selects the separate policy explicitly;
  its default FROST path remains unchanged.
- `mpc-phase5c-provision propose-probe`: distinct source-only operator path
  and confirmation flag. Original `propose` remains FROST-only. Neither path
  was executed against a conductor during development.
- Design/runbook, README, signer and provisioning documentation updated;
  historical deployment evidence retained with a dated handover addendum.

The existing coordinator and integrity accept the separate probe protocol
under their current generic SessionSpec/envelope validation. Tests call the
actual functions against mocked host calls; these mocks return synthetic
records/actions and perform NO real source-chain operations. This is stronger
than a reimplementation of the predicates, but does not verify deployed WASM.

## Commands and evidence

All dependency resolution/build/test commands were offline. The lockfile was
updated offline once for development-only dependency edges; subsequent
commands used `--locked`. No dependency versions changed.

| Command/suite | Result |
|---|---|
| Worker default-feature library | 34/34 passed |
| Worker `lair-signer` library | 51/51 passed |
| Probe integration, final run | 18/18 passed |
| Probe CLI gates | 1/1 passed |
| Provisioning CLI and isolated proposal builder | 6/6 passed |
| Worker restart regression | 2/2 passed |
| Authenticated IPC process regression | 2/2 passed |
| Independent node-service regression | 1/1 passed |
| Mock relay regression | 3/3 passed |
| Runtime retained transport-key unit tests | 5/5 passed |
| Runtime durable ledger/nonce/share tests | 4/4 passed |
| Runtime DKG journal tests | 4/4 passed |
| Security protocol tests | 14/14 passed |
| Group activation/signing-approval tests | 3/3 passed |
| Worker binaries, `lair-signer` | Build passed |
| Worker binaries, `conductor-client` | Build passed |
| Version, release inventory, preflight self-test | Passed |

Representative reproducible commands:

```sh
cargo test --offline --locked -p holochain-mpc-dkg-worker --lib
cargo test --offline --locked -p holochain-mpc-dkg-worker --features lair-signer \
  --lib --test transport_probe --test dkg_restart --test node_service \
  --test ipc_process --test relay_simulation \
  --bin mpc-transport-probe --bin mpc-phase5c-provision
cargo test --offline --locked -p holochain-mpc-runtime --lib --test durable --test dkg_journal
cargo test --offline --locked -p holochain-mpc-security --test security_protocol --test group_activation
cargo build --offline --locked -p holochain-mpc-dkg-worker --features lair-signer --bins
cargo build --offline --locked -p holochain-mpc-dkg-worker --features conductor-client --bins
python3 -I scripts/check_holochain_versions.py
python3 -I scripts/check_release.py
python3 -I scripts/phase5b_preflight.py --self-test
git diff --check
```

Unix-socket process regressions ran outside the restrictive execution sandbox
with authorization limited to synthetic fixtures and temporary state. They did
not contact persistent nodes, Lair stores or credentials. Ordinary probe tests
run inside the sandbox. Raw local development logs are in
`/tmp/mpc-phase5cc-regressions.log`, `/tmp/mpc-phase5cc-probe-final.log` and
`/tmp/mpc-phase5cc-build.log`; these temporary paths are not durable artifacts.
The source-only checkpoint comparison diff is
`/tmp/mpc-phase5cc-implementation.diff`.

Probe coverage includes separate-process identity recovery; crash/cancellation
and uncertain delivery; exact signed-call bytes with deliberately fake mock
signatures; native AEAD and all inner bindings; public pin mismatch; duplicate
and conflicting ciphertext; concurrent admission/receipts; strict file/schema
and confirmation gates; independent signer profiles; payload limits; and
actual unchanged zome functions with mocked host provenance/acceptance.
The subprocess test helper is also a test entry point and is exercised through
parent-driven subprocess invocations. Existing FROST regression fixtures may
exercise synthetic DKG; the probe itself never initializes or resumes DKG.

Development fixes before final acceptance included correcting ExternIO's Debug
requirements using a redacted send formatter, using Holochain 0.7.1's actual
CapAccess variant in the mock, and accounting for nested JSON byte-array
expansion. The final packet limit is 48 KiB, under the 64 KiB core envelope
payload bound, while clear application data remains capped at 128 bytes.
Rust reports an upstream `proc-macro-error2` future-compatibility warning.

## Security assessment and limits

The implemented probe is separated by protocol, immutable proposal/session,
full spec, native key binding, opt-in signer policy and independent approved
registration evidence. It fails closed before replay admission for malformed,
cross-protocol, cross-ceremony or unauthenticated ciphertext. Outbound
admission precedes signing/network IO and cannot be reset through its API.
Invalid or lost acknowledgements never authorize retry. A remote storage
receipt is not reported as proof of native recipient decryption.

These guarantees assume trusted local code/conductor and intact local storage.
A compromised same-UID process can access development state or call a signer;
master keys remain files on the same host as encrypted databases. SQLite and
file permissions are not anti-rollback protection. The standalone signer
socket is not a durable one-shot service; trusted callers must use the native
admission path. Capability purpose/proposal labels are trusted operator
configuration: actual Holochain grants remain function/caller-scoped. Fresh
probe credential provenance requires independent operator verification; the
code neither loads existing FROST policy secrets nor proves fresh issuance.
Plaintext limits/inner digest are checked by native endpoints; the signer
checks ciphertext structure and outer limits without decryption authority.

No real Lair signature validation, websocket/conductor interoperability,
Holochain capability enforcement, source-to-deployed-WASM provenance or
persistent-network delivery was demonstrated here. No production-grade key
custody is claimed. No existing persistent directory, token, private key,
passphrase, capability secret or signer policy was accessed.

The proposed live procedure and each operator-approval checkpoint are in
`V040_PHASE5C_C_TRANSPORT_PROBE.md`. It has not been executed. A successful
live milestone still needs B's own conductor inbox and native authenticated
decryption using its retained key, followed by approved restart/replay checks.

## Final verification

The final focused run passed 18/18 integration test entry points and 1/1 CLI
gate test. Its real 30-second send-deadline test passed; an admitted attempt
became terminal uncertain with no resubmission. Its abrupt-process-death test
killed a synthetic child with an open SQLite connection and recovered the
same native key/admission through the WAL, refusing retry. Recipient recovery
and replay checks also passed. Both binary feature builds passed.

Version pins, release inventory (including all new files), preflight self-test,
new-file rustfmt checks and `git diff --check` pass. The verified checkpoint
remains intact; the protected existing implementations listed above still
match it. All changes remain uncommitted for operator review.
