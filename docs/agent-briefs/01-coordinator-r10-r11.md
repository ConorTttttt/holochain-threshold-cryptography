# Agent 1: Coordinator inbox availability (R10 offline half, R11)

Read `00-COMMON-RULES.md` first.

## Goal

A malicious or racing member must not be able to block another node's inbox for a
whole proposal. Fix this in the coordinator zome only.

## Background

- R10: the persistent 5C cells run the 17 October coordinator, which writes inbox
  entries with strict ordering. Concurrent delivery fails with HeadMoved and the
  error kind is hidden. The current tree already uses relaxed ordering for
  `InboxEvent`.
- R11 (security review finding R6, `docs/V040_SECURITY_REVIEW_2026-10-22.md`):
  with relaxed ordering, one concurrent conflicting delivery pair makes
  `get_inbox` fail, and the 16,384-message capacity has no per-sender share. The
  victim then cannot sign for that group again.

## Scope

You own: `dnas/mpc/zomes/coordinator/**` and its sweettest tests.
Read-only: `dnas/mpc/zomes/integrity/**`, everything else.

## Tasks

1. Reproduce R11 with a failing test: a conflicting pair for one slot makes
   `get_inbox` fail for the whole inbox.
2. Candidate fix (confirm or improve it in the report):
   - `get_inbox` returns conflicting envelopes as data, so only the consumer of
     that one slot aborts. Other slots stay readable.
   - A per-sender quota inside the 16,384 capacity so one sender cannot fill it.
   - Make delivery errors keep their kind (no retry advice for non-idempotent
     calls; see N3 and R2: never suggest retrying `prepare_inbox_grant`).
3. Tests: honest delivery unchanged; conflicting pair; quota exhaustion by one
   sender leaves room for others; HeadMoved under concurrent honest delivery.
4. Prove the DNA hash is unchanged: `npm run build:happ` twice, compare the
   integrity WASM and the DNA hash with the 22 October build, and run
   `npm run check:wasm-imports` and `npm run check:holochain-versions`.
5. Write `docs/V040_COORDINATOR_INBOX_HARDENING.md` including the exact steps
   the operator would take for `update_coordinators` (do not run them), and what
   must be verified on the persistent cells afterwards.

## Done when

New tests pass, `npm run test:sweettest` and `npm run test:native` pass, the
integrity WASM and DNA hash are byte-identical, and the report states the
availability target the fix actually meets (and what it does not, for example a
member who stays silent still aborts DKG under L1).

## Decision to flag

The quota size and whether a sender over quota is rejected or ignored need an
operator decision. Propose a default.
