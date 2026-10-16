# v0.3.5 — Three process-isolated FROST DKG controllers (experimental)

## What this actually implements

- Adds a separate native **`mpc-dkg-worker`** executable in a new workspace
  package. A worker owns its **own** `DkgParty`, X25519 private key, and
  `EchoBroadcast` state. The parent test process cannot read the KeyPackage
  from the worker protocol; it receives only public key bindings, public
  announcements, echo/attest messages, encrypted Round-2 envelopes, and the
  public group descriptor.
- Adds **`three_process_frost_dkg_over_three_conductors`** Sweettest: three
  independent OS child processes, three actual Holochain conductors, a real
  ActionHash-bound proposal, actual consent and private-inbox network delivery,
  unanimous transcript echo/attestation, encrypted DKG share delivery, local
  DKG completion and independently authored activation attestations.
- Uses the existing Holochain 0.7.1 coordinator/integrity zomes unchanged,
  respecting the project's integrity/coordinator split.
- If any worker command fails, its controller is permanently poisoned, the
  binary emits a failure and exits. A crash or restart **aborts the ceremony**:
  no DKG secret state is checkpointed, and a new session proposal is required.

## Trust and isolation boundaries

The experimental executable accepts `--unsafe-test-stdio` intentionally:
**stdio does NOT authenticate the caller.** The test harness is trusted to
obtain envelope provenance from the recipient's own conductor-validated
private inbox and to check each encryption binding's `author` and `action`.
The worker cannot verify raw caller-supplied `authenticated_sender` bytes by
itself. A compromised parent can impersonate participants to its child. This
is **not** a production transport, distributed process identity proof, or
portable signed receipt.

Stdio is not a secure key-provisioning channel. Child processes are colocated
under one test harness and may share the same OS user. OS process isolation
keeps accidental in-process access separate, but does not protect against a
compromised parent OS user or kernel. Conductor instances are separate test
instances, not three independent machines.

The native `KeyPackage` is not yet persisted, unlocked, or signed with.
OS/Lair-backed encrypted key provisioning, rollback-resistant persistence,
authenticated sidecar↔conductor channels, secure capability distribution,
true fail-stop recovery, crash-injection tests and signing from separate
processes remain future work. Run with **TEST-ONLY** keys and never use for
funds or production credentials.

## Run in Holonix

```sh
npm run check:holochain-versions
python3 scripts/check_release.py
npm run test:native
npm run test:dkg-process
npm run test:sweettest
```

`test:dkg-process` first builds and packages the same Holochain zomes, then
runs the new native-process integration test. `test:sweettest` runs the existing
coordination and v0.3.4 live-DKG scenarios **plus** the process-isolation case.
It may take several minutes due to Holochain conductor setup and consistency.

## Deliberate non-goals

No new Holochain entry types, protocol wire formats or DNA schema versions;
no production service; no key recovery/replay after power loss; no FROST
signing from process workers; no guarantee of asynchronous Byzantine liveness.
