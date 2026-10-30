# Agent 3: Fault injection on the disposable rehearsal (Phase 6/8 remainder)

Read `00-COMMON-RULES.md` first, then `docs/V040_PHASE6_REHEARSAL.md` and
`docs/V040_PHASE8_SIGNING.md`.

## Goal

Test failure, partition and process-kill behaviour during DKG and during
signing on a single host, with repeatable scripts.

## Background

The disposable rehearsal (`scripts/phase6_rehearsal.py`) passes 2 of 2 runs for
DKG, group activation and 2-of-3 signing verified by OpenSSL. What is untested:
what happens when a node dies, stalls or is partitioned mid-protocol (limitation
L1: unanimous fail-closed echo, any offline member forces an abort; the DHT gives
no finality).

## Scope

You own: new files `scripts/phase6_faults.py` (and helpers `scripts/faults_*`),
and `docs/V040_PHASE6_FAULT_TESTS.md`. Do not modify
`scripts/phase6_rehearsal.py`; import or copy from it. Everything runs under
`~/mpc-phase6-rehearsal` style disposable directories with throwaway passphrases.

## Scenarios (each scripted, repeatable, with an expected outcome stated first)

DKG:
1. SIGKILL one worker in rounds 1, 2 and 3. Expect a clean abort journaled by
   every surviving node, no sealed share on an aborted run, and no half-complete
   group descriptor.
2. SIGSTOP a node past the deadline, then SIGCONT. Expect abort, no late
   acceptance.
3. Partition one node (network namespace or by stopping its relay and conductor
   link; document which tool you used and whether it needs root, and skip with a
   clear message if it does). Expect abort.
4. Kill during seal: after share sealed but before completion journaled, and
   after both. Restart. Expect recovery only for a completed journal (see
   `recover_completed_share`).
5. A restarted node must not re-run an aborted DKG under the old context.

Signing:
6. Kill a selected signer after nonce reservation, after commitment publish,
   after share publish, and after aggregate. Expect: the restarted signer never
   reuses the nonce, a repeated operation is refused ("deadline already
   registered"), and the surviving signer does not produce a signature without
   the second share.
7. Kill the unselected node at any point. Expect no effect and no nonce reserved.
8. Partition between the two selected signers. Expect timeout and abort.

## Done when

`python3 -I scripts/phase6_faults.py --list` shows all scenarios, each runs
alone and as a suite, two consecutive full runs pass, and the doc reports every
scenario's observed outcome, including any that differ from the expectation
(file those as findings with logs; do not patch product code, that is another
agent's job).

## Do not

Touch persistent sandboxes, or add product code changes. A real bug found goes
into the report with a reproduction.
