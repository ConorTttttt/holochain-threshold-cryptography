# Sprint 1.7 Agent 23 — Signing Slot / Quota Handoff

**Created:** 2026-11-16 UTC. **Agent:** 23. **Target branch:** sprint1/agent6-stage2c-integration-20261116. **Starting immutable commit:** 899e433d057a4d1a0533e2304a2493edb75ad82f. **Review branch:** agents/sprint17-agent23-signing-slot-quota-20261116. **Pull request:** #13 (DRAFT). **Disposition:** CHANGES REQUIRED.

## Baseline check

At inspection the target branch pointed to 899e433d057a4d1a0533e2304a2493edb75ad82f. Alternative agents/ci-recovery-integrated-sdk-20261116 was at 2f3b4c3d708db6d48954d1341fdaa1ba246a9ef1; GitHub comparison with the starting commit returned diverged, ahead 1 / behind 3, and no combined passing statuses were reported. It is **not** a newer validated Sprint 1.6 integration candidate. No replacement baseline used. Main and deployed cells were untouched.

The required Fable documents are historical evidence tied to 8dec223; current code (signing.rs, coordinator lib.rs, FROST frame validation, current Sprint 1.5 review on review/sprint15-independent-security-20261116, API_CONTRACT and THREAT_MODEL) was inspected separately. No historical absence was promoted to a current finding without current-source checks.

## Test matrix (test sources authored; none executed)

| Test | Source location | Claimed coverage | Observed status |
| --- | --- | --- | --- |
| distinct_operation_ids_can_collide_on_legacy_sequence | worker tests/signing_session.rs | Construct same-first-eight-byte plans; same sequence, different full intent | NOT RUN (E1 only) |
| colliding_operations_never_cross_authorize | same | Selected-signer approvals isolated by full operation ID | NOT RUN (E1 only) |
| colliding_operations_cannot_cross_aggregate | same | Real FROST native signing for first operation in simulated network; second collided operation must abort, no new artifact | NOT RUN (E1 only) |
| per_sender_quota_is_isolated | same | Coordinator partition helper isolates sender 1 quota from sender 3 | NOT RUN (E1 only) |
| honest_sender_quota_exhaustion_is_detected | same | 2,049th inbound record withheld in 3-member quota | NOT RUN (E1 only) |
| group_renewal_uses_fresh_proposal | same | New proposal descriptor not activated by prior attestation; synthetic evidence, **not** a new DKG | NOT RUN (E1 only) |
| old_exhausted_group_is_not_silently_reactivated | same | Future durable expired-group admission policy | **IGNORED / KNOWN-RED**, NOT RUN; protection currently missing |

### Exact execution diagnostics from this session

The sandbox does not contain a local checkout. Commands and observed exit statuses:

~~~text
command -v cargo       exit=1
command -v rustc       exit=1
command -v rustfmt     exit=1
command -v nix         exit=1
command -v hc          exit=1
command -v holochain   exit=1
git ls-remote https://github.com/ConorTttttt/holochain-threshold-cryptography.git refs/heads/sprint1/agent6-stage2c-integration-20261116
exit=128; fatal: unable to access ... Could not resolve host: github.com
~~~

GitHub connector access was available for source inspection and isolated PR creation but does **not** run Rust tests. The baseline Sprint 1.5 report documents the prior exact-head workspace E0433 due to an unconditional holochain_zome_types import with an optional dependency; the existing integration owner must resolve and validate the combined workspace before this branch can claim compilation. Do not confuse historic or CI-recovery branch observations with test evidence for this PR.

### Required executable gate on the final integrated commit

~~~sh
git rev-parse HEAD
rustc --version
cargo --version
cargo check --locked --workspace --all-targets
cargo test --locked -p holochain-mpc-dkg-worker --test signing_session -- --nocapture
cargo test --locked -p mpc --lib inbox_tests -- --nocapture
cargo test --locked -p holochain-dkg-sdk --all-targets
cargo test --locked -p holochain-dkg-sdk --features native-holochain --all-targets
npm run build:happ
npm run test:sweettest
~~~

For each command record **exact commit, complete command, exit status and redacted relevant log**. Execute conductor adversarial tests on disposable cells for same-slot write races, over-quota at the real receiving zome, full operation-ID rejection and rekey. Execute real FROST negative tests for non-cross-approval and cross-operation share rejection. A native simulated-transport pass does not constitute E5 or E6.

## Evidence levels at handoff

- **E1:** YES — source and documentation are present on Agent 23 branch.
- **E2:** NOT RUN — no compiler on this runner. Prior CI failures on the base are not newly verified.
- **E3:** NOT RUN — no native Rust tests executed for this branch.
- **E4:** NOT RUN — no WASM or hApp packaging.
- **E5:** NOT RUN — no real Holochain conductors.
- **E6:** NOT RUN — no native cryptography driven across conductors.
- **E7:** NOT RUN — source-level adversarial regressions drafted only.
- **E8:** NOT RUN — independent security review of this exact PR or combined candidate not completed.

## Open security obligations for integrating Agent 18 / integration owner

**S1-L01 remains OPEN** for collision-free long-lived transport; the v1 native identity check is a fail-closed containment property, not a collision-free namespace. Decide between documented deterministic rejection and an explicitly versioned full operation namespace before any compatibility-sensitive change.

**S1-M03 remains OPEN** for durable expiry and quota preflight, including unknown/stale/concurrent remaining counts and group-wide retirement. The ignored test must stay ignored/red until the real guard is integrated and executed. Do not claim successful prevention of old exhausted group reactivation on this branch. The conservative limit, 128-record reserve and renewal steps are design recommendations, not deployed defaults.

**S1-H01 custody and S1-M02 cross-application transport replay remain independent open blockers.** This PR has no fix for either and cannot promote the project to reusable SDK or production-safe deployment. No real keys/funds/persistent credentials, release-hash writes, migrations, group resurrection or deployed-cell changes are permitted.

**Milestone:** source-only contribution to a DEVELOPMENT DKG/SIGNING IMPLEMENTATION, pending compilation and execution. Not an EXPERIMENTAL READ-ONLY SDK verification, not a FULL REUSABLE MULTI-APPLICATION SDK, and not PRODUCTION-SECURE DEPLOYMENT.
