# Phase 5C-C security and deployment-readiness review

18 October 2026 (Europe/London). Recommendation: **NO-GO for staged live
mutation/deployment. Read-only public preflight may be considered separately.**
No live preflight was executed. No conductor, Lair, credential, native-node or
source-chain state was accessed or changed. No DKG was initialized in this
review. This is a separate evidence-driven review by the coding assistant,
not an external independent security certification.

> **22 October 2026 update:** B1 and B2 are remediated in source with refusal
> tests (see *Remediation* at the end). That satisfies re-entry criteria 1–2
> offline only. Criteria 3–4 (read-only preflight, step-specific approval for
> every live action) still stand, so live writes remain unapproved.

## Decision and blocking findings

The dedicated probe path has sound separation and durability mechanisms, but
its passing tests do not establish the requested isolation across ALL existing
FROST entry points. Two inherited boundary weaknesses remain blocking under
that acceptance criterion. They were present before the probe implementation;
preserving their source bytes also preserved these weaknesses. This review
adds reproductions and documentation, not functional remediation.

### B1 — FROST binding validation is bypassable at controller/provider entry

`crates/mpc-frost-ed25519/src/lib.rs:78` defines Binding with public fields and
derived Deserialize. Its `new` constructor rejects the probe protocol, but
construction/deserialization need not call `new`. The review reproduction
successfully deserializes the exact probe SessionSpec into a FROST Binding
and resolves a participant identifier from it.

Source call-path review:

- `crates/mpc-dkg-worker/src/lib.rs:127`: Controller Init checks local membership,
  then passes Binding to DkgParty::begin without reconstructing/validating it.
- `crates/mpc-dkg-worker/src/lib.rs:321`: AuthenticatedController checks local
  agent, proposal and session against IPC context, not protocol/full spec.
  Its durable path records DKG admission before dispatching the inner command.
- `crates/mpc-frost-ed25519/src/lib.rs:320`: DkgParty::begin resolves the ID,
  then calls FROST part1 without revalidating Binding.

Thus an authorized local controller caller or accidental use of the legacy
worker with a probe node is not stopped at the protocol boundary before
secret generation/admission. This review did NOT invoke those Init/begin
operations: the deserialization bypass is tested; the remaining call path is
established by source inspection. ConductorBridge::connect revalidates and
the probe CLI never invokes a controller, so the normal dedicated CLI is not
shown to leak into an existing FROST ceremony. Nevertheless the broader
"FROST rejects probe before initialization" claim is unproven and the raw
entry path lacks the guard.

Required remediation: validate full Binding at controller/provider boundaries
before durable DKG admission or FROST randomness generation; reject probe and
other unsupported protocols. Preserve existing restart/tombstone rules. Tests
must cover public-field/deserialized inputs and prove refusal before any
admission/key-generation side effect. Request separate approval for changing
the protected FROST implementation; no DNA change should be necessary.

### B2 — legacy signer trusts a protocol label absent from signed SendMessage

`crates/mpc-dkg-worker/src/lair_signer.rs:99` pins app/DNA/agent/proposal/session,
but its legacy policy contains no independently approved full SessionSpec.
The FROST protocol check at line 130 trusts the request envelope label.
`SendMessage` omits protocol and session; the coordinator at
`dnas/mpc/zomes/coordinator/mpc/src/lib.rs:235` derives these from the actual
proposal. The signed-byte comparison cannot recover the missing protocol
from its arguments alone.

The reproduction deliberately constructs a synthetic LEGACY policy pointing
at a probe proposal. It rejects the honest probe label. Changing only the
unsigned label to frost-ed25519 makes authorization succeed; reconstructing
the coordinator envelope from the signed payload and actual proposal gives
the original probe envelope. No Lair signing, network call or live secret is
used. An existing FROST policy pinned to a DIFFERENT original proposal is
still protected by that proposal pin; this is not a demonstrated bypass of
an unchanged deployed policy or of agent signatures.

This is blocking for the required fail-closed opt-in/profile boundary under
misconfiguration. The existing tests checked the honest probe label, and the
legacy test policy had no recipient capability; they did not cover this case.

Required remediation: independently pin and verify the full immutable proposal
spec/protocol for legacy signer policies as well, without trusting a client
label. Choose a fail-closed policy compatibility/migration design; do not
silently add permission to old policies. Verify actual protocol against the
pinned proposal before authorizing a send. This needs approval before changing
legacy policy architecture. Existing DNA/SendMessage need not change if the
native signer binds trusted proposal evidence; wire/DNA changes require a
separate design approval if chosen.

## Other findings and mandatory deployment gates

| ID | Classification | Finding / required treatment |
|---|---|---|
| N1 | Nonblocking code limitation; mandatory credential gate before signing/sending | ProbeCapability validates action syntax and purpose/proposal/grantor/grantee labels, not issuance or secret-to-action association. A nonexistent syntactically valid action plus another nonzero secret is accepted by the constructor. Independently verify a fresh assigned grant and authenticated sealed-offer/import provenance before assembling the private policy. Do not copy or relabel FROST credentials. No verification was performed against live grants. |
| N2 | Nonblocking for a non-sensitive trusted-host development probe; production blocker | Same-UID file custody and ordinary SQLite do not prevent malicious local code, database rollback or use of a signer outside the admission API. Prohibit rollback and use non-sensitive test data; no production custody claim. |
| N3 | Nonblocking operational hazard | The existing coordinator error text suggests retrying the same round/sequence. That is incompatible with the probe's terminal admission rule. Probe CLI hides raw conductor errors; the runbook's no-retry rule must override that message. Never switch to a lower-level call tool to retry. |
| N4 | Pending live evidence gate | Native/mock compatibility does not establish installed WASM provenance, real Lair/WebSocket interoperability, current token validity or live capability enforcement. Public metadata preflight must precede separately approved authenticated reads/writes. A storage receipt does not prove native decryption. |
| N5 | Nonblocking resource/availability limitation | Session/key/inbox reads use existing RPC timeout behavior; registration has no encompassing CLI deadline. A stalled call can require termination. An existing registration-attempt marker remains terminal; termination never grants retry permission. |

A test-only defect was corrected: inner-binding tamper tests previously set a
random commitment byte to 255, which could leave it unchanged. They now XOR
that byte with one, guaranteeing mutation. No product code was changed.

## Positive findings and transaction audit

- The probe CLI uses only ProbeEndpoint and SignedAppTransport, not
  Controller, AuthenticatedController, DkgParty or RelayEngine. It verifies
  the actual typed session status before opening retained local state.
- ProbePlan pins the full spec, DNA/proposal/session, direction, payload
  digest/limit and an independently supplied exact registration roster.
  Observations are compared with approved pins, never promoted to approval.
  Local public-key evidence must equal the retained secret-derived identity.
- Both the sealed wrapper and inner ProbeBody authenticate ceremony/header
  bindings. Inner values also bind domain, DNA, exact registration commitment,
  plan, explicit message ID and payload digest. Sender identity additionally
  depends on trusted conductor provenance; SalsaBox is not transferable proof
  of exclusive authorship. No cryptographic identity bypass was found in the
  supported CLI path under its trusted-host assumptions.
- The two-member probe proposal has its own session/protocol namespace and
  `max_round=1`. Its transport key AAD pins DNA/agent/proposal/session. Its
  replay/admission tables are distinct from DKG checkpoints and nonce tables.
  Changing the plan cannot reset the `(proposal,sender)` outbound slot.
- Outbound SQLite admission commits before any signing/network output.
  `pending` survives cancellation/process death; both pending and uncertain
  refuse resubmission. A failed/ambiguous local acknowledgement commit does
  not release another attempt. Registration separately fsyncs an exclusive
  marker and its parent before making the signed call.
- Recipient verifies envelope, approved key evidence, AEAD and every inner
  binding before entering a BEGIN IMMEDIATE transaction. Its only application
  effect is the committed receipt marker. Exact duplicates do not create
  another effect; conflicting ciphertext fails. Console output is not an
  exactly-once external effect. No probe transaction-boundary defect found.

## DNA and original-ceremony assessment

Neither zome nor DNA/hApp manifest changed relative to the preserved
pre-implementation checkpoint. Existing integrity/coordinator functions accept
this generic protocol without a schema migration, as exercised with mocked
host calls. The proposed procedure adds a separate proposal/session and probe
state; it does not replace DNA or modify the original FROST proposal.

This establishes source compatibility, NOT the currently installed binary
identity. The baseline already included the earlier integrity revocation fix;
Git HEAD is older. Never infer deployed DNA from Git HEAD or rebuild/install a
hApp as part of this native probe. Verify public installed hashes first. No
conductor restart, app update, coordinator replacement or DNA migration is
part of this review or the proposed preflight.

## Evidence and scope of diff review

Baseline: `../source-checkpoints/phase5cc-before-implementation-j70nwlvp/`.
Its archive SHA-256 remains
`2a493bb4186b773cf2a0dd44bec40473cebc18c2b7a9f620dcd50d1bdf329baf`.
All 99 original source paths remain. The original implementation delta was
27 files (7 new), including untracked files invisible to ordinary git diff.
This review adds these two documents, three reproduction tests and the
one-byte test-mutation correction; README/runbook/offline report gain review
status pointers. The final reviewed snapshot contains 108 allowlisted files
and differs from the preserved checkpoint in 29 files (9 new).
Full source snapshot/diffs are prepared from explicit public
source paths; no private state is traversed or included.

The reviewed delta covers all changed native/runtime modules, signed-call and
signer dispatch, key/node recovery helper, proposal builder/CLI, dev dependency
edges, integration tests, release inventory, npm scripts and documentation.
No lockfile package versions changed. Source checks still find unchanged
zomes, FROST provider, journal, controller body and node serve path. This is an
implementation/deployment review, not a complete audit of all historical code.

Offline review reproductions (3/3 PASS = gaps reproduced):

```sh
cargo test --offline --locked -p holochain-mpc-dkg-worker \
  --features lair-signer --test transport_probe review_reproduction
```

The completed focused review run passed 21/21 integration entries, 1/1 probe
CLI gate test and 6/6 provisioning tests. Runtime retained-key tests passed
5/5, durable-state tests 4/4 and journal tests 4/4. Version/inventory checks,
new test formatting and git diff whitespace checks pass. These runs invoked
no DKG initialization. Raw synthetic logs are retained temporarily at
`/tmp/mpc-phase5cc-review-tests.log` and
`/tmp/mpc-phase5cc-security-reproductions.log`.
The three passing reproduction tests must not be mistaken for fixes
or a GO decision. No Init/begin, source-chain operation or live API was called
by those reproductions. Previously reported broader regressions remain
historical evidence, with their limits explained in the offline report.

## Source-only Git checkpoint

The review snapshot is prepared under
`refs/checkpoints/phase5cc-security-review-20261018`. It is an archival
checkpoint with known blockers, not deployment approval. A temporary index
and Git plumbing preserve the working branch, HEAD and real index. The tree
contains only explicitly allowlisted public source/docs/manifests/lockfiles;
no private state, credentials, build products or original archive are added.
The snapshot has the original HEAD as parent so the complete accumulated
source diff is inspectable. No hooks, branch switch, reset or push is used.
A separate manifest and bundle retain the commit identity and file hashes.

## Re-entry criteria

1. Approve and implement native B1/B2 boundary hardening; retain all restart,
   nonce and FROST restrictions and prove rejection before side effects.
2. Rerun focused security/restart/signer regressions and review the resulting
   complete diff. The existing reproductions should become refusal tests.
3. Complete the separate read-only public preflight checklist. Mismatches
   require investigation, not repair or credential issuance during preflight.
4. Obtain explicit, step-specific approval for each later setup, independent
   credential, registration and message operation. Verify N1/N4 at the
   appropriate stage. No current approval covers any such live action.

## Remediation — 22 October 2026

Source-only work by the coding assistant at the operator's request. No
conductor, Lair, credential, token, native-node or source-chain state was
accessed. No zome, DNA or hApp source changed, so deployed DNA identity is
unaffected. This is not an independent audit.

### B1 — FROST binding revalidated at every entry point

- `Binding::validate()` holds the checks formerly inside `new`: FROST v1
  protocol, threshold and roster of at least two, `max_round >= 6`, 39-byte
  proposal action, plus `SessionSpec::validate`.
- `Binding` deserializes through `#[serde(try_from)]`, so a deserialized probe
  or other non-FROST spec is rejected. The wire format is unchanged.
- Public fields still allow a struct literal, so `DkgParty::begin`,
  `Signer::new` (and through it `ControlledSigner::new`) and
  `AuthenticatedShareCollector::new` call `validate()` before any FROST
  randomness.
- `Controller` Init validates before membership checks. `AuthenticatedController`
  validates during its Init identity check, before `dkg_begin` writes the
  durable admission marker. A refused Init keeps the existing fail-closed
  tombstone (`aborted`, revision 0) and never leaves a `running` marker.
- Refusal test `review_b1_frost_rejects_probe_binding_before_admission`
  replaces the deserialization reproduction. It covers deserialization, the
  struct literal, `DkgParty::begin`, `Controller` Init and a durable
  `AuthenticatedController` Init with its journal inspected afterwards.

### B2 — legacy signer pins the full proposal spec

- `SignerPolicyFile` gains `spec`, the full `SessionSpec` from the
  conductor-verified ceremony record. It must form a valid FROST `Binding`
  with the pinned proposal, match the pinned session and contain the signer's
  agent. Every capability recipient must be a member.
- A send is authorised only if the envelope equals the one
  `Envelope::new(spec, agent, recipient, round, sequence, payload)` rebuilds,
  the same derivation the coordinator applies from the on-chain proposal. The
  unsigned envelope label is no longer trusted.
- Fail-closed compatibility: a policy without `spec` is read-only. It may not
  carry recipient capabilities, and key registration and sends are refused.
  Old policies gain no permission. Policies written before this fix that carry
  capabilities, including the 17 October 5C-B policies, are refused at load
  and must be regenerated to a new path with `mpc-phase5c-provision
  write-policy`. That is a local file operation, not a chain write.
- `assemble_policy` (`write-policy`) now writes the record's spec. The 5B
  bootstrap read-only policy (`recipients: []`, no spec) still loads.
- Refusal tests: `review_b2_frost_signer_refuses_misbound_probe_ceremony`
  replaces the relabelling reproduction. Signer unit tests
  `b2_capabilities_require_pinned_frost_spec` and
  `b2_send_must_equal_envelope_rebuilt_from_pinned_spec` cover the rest.

### Verification (rustc 1.99.0, `--locked`, locked dependencies fetched once)

| Suite | Result |
|---|---|
| core, security, runtime, FROST crates (`cargo test -p …`) | all pass; FROST `three_agents` 5/5 |
| worker `--features lair-signer --lib` | 53/53 (51 before + 2 B2 tests) |
| `transport_probe` integration | 21/21, including both new refusal tests |
| `dkg_restart`, `ipc_process`, `node_service`, `relay_simulation` | 2/2, 2/2, 1/1, 3/3 |
| `mpc-transport-probe`, `mpc-phase5c-provision`, `mpc-phase5b-bootstrap` bin tests | 1/1, 6/6, 5/5 |
| `npm run test:native` (15 suites) | 101 passed, 0 failed across 16 result groups |
| Sweettests: `mpc_network`, `dkg_live`, `revoke_cap_grant`, `three_processes`, `conductor_bridge`, `capability_provisioning` (lair-signer) | 6/6 pass |
| `npm run build:happ` from this tree | `mpc.dna`, `.happ` and both zome WASMs byte-identical to the 17 October build; DNA hash `uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu` = the deployed 5C hash |
| `check_wasm_imports.py` (new) | both zomes import only Holochain 0.7.1 host functions (48 and 11) |
| `check_release.py`, `check_holochain_versions.py` | pass |

The remaining reproduction, `review_reproduction_capability_action_is_an_operator_assertion`
(N1), still passes by design: N1 is an operator verification gate, not a code
fix. N2–N5 are unchanged.
