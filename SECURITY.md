# Security status

**NOT PRODUCTION SOFTWARE. EXPERIMENTAL, UNAUDITED DEVELOPMENT SOURCE.**
Do not use it with real keys, funds, identities or secret shares.

This repository implements dealerless 2-of-3 FROST Ed25519 key generation and
operator-approved threshold signing between independent Holochain 0.7.1
agents. It is development evidence from a single host and a disposable
three-node rehearsal. Its only review so far is the coding assistant's own
code review of 22 October 2026 (see below). That is **not an independent
audit**, formal verification or side-channel assessment.

## Why it is not production ready

- **Custody is development-grade.** The master key, the sealed share journal,
  the signers and the services share one OS user and one disk. There is no
  HSM or OS keyring, no anti-rollback protection and no tested backup and
  restore (risk R3).
- **No independent audit** of the cryptographic integration, the zomes or the
  tools.
- **Availability is not provided against a malicious member.** Any member can
  force a ceremony to abort (limitation L1), and one can block another node's
  inbox for a proposal (R11).
- **Deployment evidence is incomplete** for the persistent cells (R4, R10).
- **Open dependency advisories** remain in the Holochain crate tree (R9).
- App interfaces created with `hc sandbox` or `hc client call add-app-ws`
  default to any origin and no app binding (R7).

## Criteria before this warning may be removed (proposed, operator to confirm)

1. An independent security audit of the cryptographic integration, the zomes
   and the native tools, with every High finding fixed or accepted in writing.
2. Production custody: per-role OS users or a hardware-backed key, a monotonic
   counter or external append-only evidence against rollback, and a tested
   backup and restore procedure (R3).
3. Separate-machine, partition and kill testing, with the abort paths of
   limitation L1 exercised.
4. Deployment evidence for the cells in use: a recorded read-only audit, the
   installed WASM matching the hashes recorded by `scripts/release_check.py`, and a decision on the
   pending coordinator update (R4, R10).
5. A stated availability target and the coordinator change for R11, or a
   written acceptance of the risk.
6. Per-app origin and app binding on every app interface in use (R7), and no
   unresolved advisory in a shipped binary (R9).

Until a criterion is met and confirmed by someone other than the author, keep
the warnings in `README.md`, this file and every binary's `--help`.

## Where to read more

- Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- Security properties and limits: [`docs/SECURITY.md`](docs/SECURITY.md),
  [`docs/SECURITY_PROTOCOL.md`](docs/SECURITY_PROTOCOL.md)
- Latest review: [`docs/V040_SECURITY_REVIEW_2026-10-22.md`](docs/V040_SECURITY_REVIEW_2026-10-22.md)
- Release checks and evidence: [`docs/V040_RELEASE_HARDENING.md`](docs/V040_RELEASE_HARDENING.md)
  (`npm run check:release`)

This repository has no security contact or disclosure process yet.
