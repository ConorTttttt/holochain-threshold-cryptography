# Agent 7: Independent reviewer (read-only)

Read `00-COMMON-RULES.md` first. You must not be the agent that wrote the code
under review. Start after Agents 1, 2 and 5 have returned patches.

## Goal

Find defects, missed attack paths and false claims in the patches from Agent 1
(coordinator), Agent 2 (custody) and Agent 5 (vault app core). Treat their
reports as claims to check, not facts.

## Scope

Read-only on the project. You may write ONLY
`docs/review/REVIEW_<agent>_<date>.md`. Do not fix code. Do not run anything
against persistent sandboxes. Running tests and building in a scratch copy is
fine.

## Method

- Apply the project's security review profile (`docs/security-profile.yaml`) and
  the format of `docs/V040_SECURITY_REVIEW_2026-10-22.md`: severity, location,
  failure scenario, reproduction, fix suggestion.
- For each patch, review the full diff, not the report. Check that every new
  refusal path has a test and that the test fails without the fix.
- Agent 1: can a malicious member still block an inbox? Is the quota bypassable
  with many identities? Is the DNA hash really unchanged (rebuild and compare)?
- Agent 2: can a rollback be disguised (partial restore, clock change, copying
  the evidence file too)? Is every nonce path crash-safe? Do error messages or
  logs leak share or key material? Are file mode checks racy?
- Agent 5: can bytes shown differ from bytes signed? Can a non-selected or
  outsider approve? Replay, double broadcast, token leakage, localhost
  exposure, injection into CLI arguments, size limits.
- Confirm each report's "not done" list is complete and each claim is evidenced
  by a command output you reproduced.

## Report

Findings ranked most severe first, each marked CONFIRMED (you reproduced it) or
PLAUSIBLE. Then a list of claims you could not verify. No praise padding. End
with a go / no-go for merging each patch into the operator's tree.
