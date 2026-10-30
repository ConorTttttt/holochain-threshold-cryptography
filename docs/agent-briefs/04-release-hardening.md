# Agent 4: Release hardening and documentation

Read `00-COMMON-RULES.md` first, then `docs/SECURITY.md`,
`docs/SECURITY_PROTOCOL.md`, `docs/V040_SECURITY_REVIEW_2026-10-22.md` and
`docs/security-profile.yaml`.

## Goal

Finish the release-hardening checklist items that do not need an operator or an
external auditor.

## Scope

You own: `docs/**` except files named in other briefs, `scripts/check_*`,
`scripts/release_*` (new), and `SECURITY.md`/`README.md` warnings. For R7 you may
edit the app-interface configuration in `crates/mpc-dkg-worker/src/conductor_client.rs`
and related provisioning code only. Do not touch the lockfile except as in task 4.

## Tasks

1. Threat model: write `docs/THREAT_MODEL.md` (assets, trust boundaries, actors,
   attacks, controls, residual risk) from the existing docs and the 22 October
   review. Map each row to the risk IDs R1 to R11 and L1 to L4. No new claims
   that the code does not support.
2. Reproducible offline test scripts: one script, `scripts/release_check.py`,
   that runs the offline-capable checks in order (`check:holochain-versions`,
   `check:wasm-imports`, `test:native`, WASM and `.dna`/`.happ` rebuild with a
   byte-identity comparison to the recorded hashes) with `--offline --locked`,
   prints a pass/fail table, and exits non-zero on any failure. Add
   `"check:release"` to `package.json`.
3. Exhaustive import and protocol validation: audit every external input parser
   (IPC frames, relay frames, signing plans, descriptors, inbox envelopes) for
   size bounds, version fields and unknown-field handling. Add missing tests;
   report anything you cannot test.
4. Supply chain (R9): re-run `cargo audit` offline if an advisory DB is present.
   Record which advisories are in shipped binaries versus test-only. Do not bump
   versions. If a patch bump of a direct non-Holochain dependency looks safe,
   propose it in the report only. Add a short toolchain-provenance note.
5. R7: replace `allowed_origins: "*"` and `installed_app_id: null` with
   per-app values for provisioned app interfaces. Test the refusal of a wrong
   origin if the conductor test harness allows; otherwise document the manual
   check for the operator.
6. Non-production warnings: ensure `README.md`, `SECURITY.md` and each binary's
   `--help` carry the explicit non-production wording until custody and audit
   criteria are independently met.

## Done when

`npm run check:release` passes from a clean state, the threat model is complete,
and the report lists each remaining gap by risk ID.
