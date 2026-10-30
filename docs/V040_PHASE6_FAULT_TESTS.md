# v0.4.0 Phase 6/8 — fault injection on the disposable rehearsal

26 October 2026 (Europe/London). Run by the coding assistant (agent 3) on the
development host against the disposable three-conductor rehearsal.
**Single-host development evidence, not a multi-machine deployment, production
custody or an independent audit.** The persistent `~/mpc-phase5b-sandbox` and
`~/mpc-phase5c-sandbox` deployments and `~/.local/state/mpc-phase5c` were not
touched. No product code was changed; the binaries under `target/debug` were used
as built on 22 October (checksums at the end).

## Result

Eighteen repeatable scenarios (the brief's eight as fifteen runs, plus three contrast
runs) and a harness control kill, freeze and partition nodes during the DKG and
during 2-of-3 signing. **Two consecutive full-suite runs passed
(suites A and B in the run records).** Every fail-closed expectation held: no sealed share
or descriptor appears on an aborted DKG, a restarted node never re-enters an old
ceremony, a killed signer never reuses its nonce and is refused with "deadline
already registered", and a surviving signer never signs without the second share.

The runs also produced **two findings against the brief's expectations** (F1, F2)
and two environment findings (E1, E2). The most important: a surviving node that
abandons a DKG leaves its journal in `running`, not `aborted` (F1), and killing a
member in round 3 can leave one node with a *completed* share of a group that will
never activate (F2). Both are fail-closed in effect; neither is patched here.

## How to rerun

```bash
python3 -I scripts/phase6_faults.py --list          # every scenario, with its expected outcome
python3 -I scripts/phase6_faults.py --self-check    # tools, binaries, network-namespace support
python3 -I scripts/phase6_faults.py --scenario dkg-kill-r2 [--scenario ...]
python3 -I scripts/phase6_faults.py --suite --jobs 4   # all scenarios, 4 environments at a time (~9 min)
```

No `cargo build` is run: the harness uses the existing `target/debug` binaries and
`workdir/holochain-mpc-core.happ`. Each run directory is
`~/mpc-phase6-rehearsal/f<HHMMSS>-<id>-<pid>/` with `RESULT-<id>.json`, `logs/` and
`harness.log`; the conductor databases are deleted after a pass (`--keep` retains
them). A suite writes `faults-suite-<UTC>/SUMMARY.json`. Exit status 0 means every
scenario ended `PASS`, `FINDING` or `SKIP`.

Status words: **PASS** — every expectation held. **FINDING** — everything held except
checks recorded with `differs(...)`, which assert the *observed* deviation from the
brief, so the scenario fails if that behaviour changes. **FAIL** — an unexpected
observation. **HARNESS-ERROR** — the environment could not be built; says nothing about
the product.

## Method

Scripts: `scripts/phase6_faults.py` (CLI), `faults_env.py` (environment),
`faults_signing.py` (activation, plans, approvals, `mpc-sign`) and
`faults_scenarios.py` (the scenarios). `scripts/phase6_rehearsal.py` is imported
for `Run`/`Proc`/tool lookup and is unmodified. The provisioning sequence is the
rehearsal's, with these differences:

- **One `hc sandbox generate -n 1` per node** instead of one `-n 3` process, so a node
  can be frozen, killed or moved into its own network namespace alone.
- **Signer proxy.** Every relay and every `mpc-sign` reaches its Lair signer through
  a unix-socket forwarder in the harness. It parses only the request's operation name
  and round (never payloads) and can *drop* a named request and run an action first.
  This makes protocol-level kill points exact: "the victim's relay asked to send its
  second round-3 message" is a fact, not a timing guess.
- **Journal gate.** `journal.sqlite` keeps its state and row counts in plaintext
  columns. The harness reads those, and for commit-level kill points it holds
  SQLite's write lock (`BEGIN IMMEDIATE`) while evaluating a predicate, so the node
  cannot commit another write between the check and the `SIGKILL`. That is how
  "sealed but not yet journaled complete" and "nonce reserved but commitment not yet
  authorised" are hit deterministically.
- **Rootless network namespaces** for the partition scenarios. *Changed in Stage 2A
  (27 Oct), see [V040_STAGE2A_PARTITION_HARNESS_FIX.md](V040_STAGE2A_PARTITION_HARNESS_FIX.md):*
  a hub user + network namespace maps only this user (`unshare --map-current-user -n`),
  each node's **conductor** runs in its own network namespace joined to the hub by a
  veth pair (as this user, no capabilities), and the bootstrap/relay server sits in the
  hub. The custody stack (worker, relay, signers, `mpc-sign`, provisioning) stays in the
  host namespaces as this user and reaches its conductor's ports through a local bridge.
  Before Stage 2A the whole child ran under `unshare -Urmn` as namespace root, which the
  custody root refusal correctly rejects (I-5). `ip`, `nsenter`, `unshare` and `nft` are
  used; **no root is needed and the host network is untouched**. A node is cut off with `ip link set down`; a pair is cut
  with nft drop rules for their direct traffic *and* for both nodes' traffic to the
  relay port (the conductors fall back to the relay when the direct path is dropped).
  If the kernel refused unprivileged namespaces the scenario would be `SKIP`ped with
  the reason; here it is available (`--self-check`).
- **Budgets.** Relays and signers use `--poll-ms 1000 --max-polls 60` (the rehearsal
  uses 900), so an abandoned ceremony times out in about a minute. Fixed product
  deadlines stay: 15 s per signer RPC, 20 s per relay poll.
- **Paths are resolved.** `~/mpc-phase6-rehearsal` is a symlink on this host (E1).
  Run paths are short because Lair and signer sockets must fit in `SUN_LEN`.

Scenarios of one group (`signing`) share a single provisioned environment and
DKG, each with its own plan and operation id; every other scenario provisions its
own, because a DKG consumes its ceremony. Every scenario also runs alone.

## Scenarios

Expected outcome first (from the brief), then what was observed. "Journal" is the
node's `journal.sqlite`.

### DKG

**1. `dkg-kill-r1`, `dkg-kill-r2`, `dkg-kill-r3` — SIGKILL one worker in round 1, 2, 3.**
The victim's relay asks its signer for its first message of that round; the harness
SIGKILLs the victim's `mpc-node` and drops the request, so nothing of that round
leaves the victim.
*Expected:* both survivors abort cleanly; no sealed share anywhere; no group
descriptor; every surviving node's journal records the abort.
*Observed:* survivors' relays exit 1 after the poll budget with the documented
`FAIL: relay service terminated: DKG did not complete within bounded poll budget; do
not restart proposal`; the victim's relay exits 1; no node has a sealed share or a
descriptor; no journal is `completed`. **Differs:** the survivors' journals are
`running`, not `aborted` (**F1**). Journal revisions when the DKG stalled:
survivors 3 / 9 / 12, victim 1 / 8 / 11 for rounds 1 / 2 / 3.

**1+. `dkg-kill-r3-partial` — SIGKILL a worker in round 3 after one peer got its share** *(extra)*.
*Expected (scenario 1 would predict):* no node completes. *Observed:* **one node
completes** (relay exit 0, `completed`, one sealed share, descriptor written); the
other survivor aborts and the victim has nothing. The group stays inactive:
the completing node's `activate-group` succeeds (`1/3 members attested so far`) and
`signing-status` then reports `activated=false` with the other two members `pending`.
**F2.**

**2. `dkg-stop` — SIGSTOP a whole node past the deadline, then SIGCONT.**
At the victim's first round-2 send the harness freezes *every* process of that node
(relay, worker, signer, conductor, Lair) and waits for both survivors to abort, then
resumes it.
*Expected:* abort, no late acceptance.
*Observed:* both survivors had exited 1 before the resume; the resumed relay exited 1
(`signer RPC deadline exceeded`: its own 15 s deadline had long passed); no sealed
share, descriptor or `completed` journal anywhere; the survivors' journals are
byte-for-byte identical (state and revision) before and after the resume. Journals are
`running` (**F1**).
*Contrast `dkg-stop-short`:* a freeze of 8 s (inside every deadline) is tolerated and
all three nodes complete.

**3. `dkg-partition` — partition one node during round 2.**
Tool: rootless user+network namespaces, `ip link set down` on the node's hub-side
veth. No root. Since Stage 2A only the conductors are in the namespaces; the scenario
also checks the custody processes' euid, capabilities and namespaces at the cut, a
namespace-root control refusal, and TCP reachability of the cut and uncut paths.
*Expected:* abort.
*Observed:* all three relays exit 1 with `DKG polling deadline exceeded; do not retry
RPC` (the 20 s poll deadline: a publish to the cut node never returns); no sealed
share or descriptor. After the partition heals and 30 s pass no journal changes: the
aborted ceremony is not revived. Journals are `running` (**F1**).

**4. `dkg-seal-kill-before`, `dkg-seal-kill-after` — SIGKILL during the seal.**
The gate holds the victim's journal lock and kills the worker (a) when the sealed
share exists but the state is still `running`, (b) when it exists and the state is
`completed`.
*Expected:* restart; recovery only for a completed journal.
*Observed (a):* revision 13, `running`, one sealed share; the survivors complete; the
victim's relay exits 1, it has no descriptor. Restarting its worker is refused
(`invalid, altered or previously started DKG state`). Feeding a survivor's public
descriptor to `recover_share` (via the `mpc-sign` preflight, which stops at the signer
check before any nonce) is **refused**: `DKG did not complete; no share is
recoverable`. `activate-group` for the victim is refused (no descriptor). So the sealed
ciphertext is stranded (orphan, no wipe path) and the victim can never attest.
*Observed (b):* revision 14, `completed`, one sealed share. Worker restart is still
refused, but recovery with the peer-supplied descriptor is **accepted** (the preflight
passes recovery and stops at the missing signer socket). The probe reserved no nonce
and registered no deadline in either case. In (b) the outcome of the victim's *relay* is a race
with the kill and is not asserted: in both final suites the kill beat the
`Completed` reply (relay exit 1, no `group-descriptor.json`, yet journal `completed`
and recovery accepted with the peer's public descriptor); in earlier runs the relay
finished first (exit 0, descriptor written).

**5. `dkg-restart-refused` — restart after an aborted DKG.**
Round-2 worker kill, then, on every node: `mpc-node serve`, `mpc-node provision`
(with the node's real pinned identity) and `mpc-relay-service`.
*Expected:* nothing re-runs under the old context.
*Observed:* every `serve` is refused (`previously started DKG state`), every
re-provision is refused (`File exists`), every relay restart fails closed (no worker
socket); no journal changed (state and revision identical) and no request reached any
signer during the attempts.

### Signing

All use the same DKG, an activated group and a fresh plan (operation id) per
scenario; nodes 1 and 3 are the selected signers, node 2 is not. The victim is node 1;
its restart is a second `mpc-sign` with the same plan.

**6. `sign-kill-reserved` / `-commit` / `-share` / `-aggregate`.** Kill points:
nonce slot `reserved` (gate on the journal, before `authorize_commitment`); the
signer's next request after its round-4 commitment publish; after its round-6 share
publish; and as it asks to publish the result (aggregated and verified in memory).
*Expected:* the restarted signer never reuses the nonce; a repeated operation is
refused ("deadline already registered"); the surviving signer does not produce a
signature without the second share.
*Observed:* in all four the victim's journal holds exactly one nonce slot for the
operation (`reserved` for the first kill point, `published` for the others) and one
`open` lifecycle; the restart exits 1 with `persistent conflict: deadline already
registered; cannot extend or revive`, adds no nonce row, leaves the first untouched
and writes no files. For `reserved` and `commit` the survivor produced **no
signature** (exit 1, abort journaled `signature not reached within the poll budget`,
its nonce `burned`). For `share` and `aggregate` the victim's share had already
reached the survivor, so the survivor **completes** (exit 0) with a signature OpenSSL
verifies; the brief's "no signature without the second share" holds because the
second share exists. The victim writes no output in any case.
*Contrast `sign-recover-new-op`:* after the kills, a new plan with a new operation id
signs normally with the same two nodes; the earlier slots stay used.

**7. `sign-unselected-early`, `sign-unselected-mid` — SIGKILL the unselected node's
whole stack (conductor, Lair, worker, relay, signer).** Before signing starts, and
right after the first commitment publish.
*Expected:* no effect, no nonce reserved.
*Observed:* both selected signers exit 0, OpenSSL verifies the signature, and node 2's
journal has no nonce and no lifecycle row.

**8. `sign-partition` — partition the two selected signers from each other.**
nft drops node-1 <-> node-3 traffic and both nodes' traffic to the relay (rootless
namespaces; node 2 stays reachable from both). Triggered at node 1's round-4 send.
Since Stage 2A the drop rules carry counters; the scenario checks that they dropped real
conductor traffic, plus the isolation checks of scenario 3.
*Expected:* timeout and abort.
*Observed:* neither signer produced a signature or a file. Node 1's abort is journaled
as `signed MPC RPC failed: Timeout`, node 3's as `signature not reached within the poll
budget`; both nonces `burned`. After healing, repeating the operation is refused
(`deadline already registered`).

## Findings

Severity is the assistant's rating for triage, not an audit rating.

**F1 — A surviving node's abandoned DKG is never journaled as `aborted` (Low).**
Seen in `dkg-kill-r1/r2/r3`, `dkg-stop`, `dkg-partition` (survivors). The journal stays
`running`. `dkg_abort` is only called when the authenticated controller *returns an
error* (`crates/mpc-dkg-worker/src/lib.rs:351`). When the relay gives up (poll budget,
RPC deadline, signer failure), `relay_service_main.rs:113` exits; the worker's
`serve_connection` reads EOF and returns `Ok` (`node_service.rs:248`), so the worker
exits with the checkpoint untouched. Effect: still fail-closed, since any checkpoint
including `running` blocks `mpc-node serve` (`dkg-restart-refused`) and recovery
accepts only `completed`; but the journal cannot tell an abandoned ceremony from one in
progress, and the brief's "abort journaled by every surviving node" does not hold.
Reproduce: `python3 -I scripts/phase6_faults.py --scenario dkg-kill-r2 --keep`, then
`sqlite3 <run>/ops/node-1/node/journal.sqlite 'select state,revision from
dkg_checkpoints'` prints `running|9`. Suggested direction (another agent's change):
journal `dkg_abort` when the worker sees EOF in `running`, or have the relay send an
explicit abort before it exits.

**F2 — Round-3 delivery is not atomic; DKG completion is local (Medium; the known
L1 "no finality").** Seen in `dkg-kill-r3-partial`. A member killed after sending its
share to only one peer yields one node with a `completed` journal, a sealed share and
a descriptor, while the other survivor aborted and the killed member has nothing. The
group cannot be used (activation needs all three attestations; observed
`activated=false`), and no code path wipes the stranded completed share. Operators must
treat any DKG in which a member aborted as dead even if some node reports success.
Reproduce: `--scenario dkg-kill-r3-partial`.

**E1 — `scripts/phase6_rehearsal.py` fails at `propose` on this host (environment).**
`~/mpc-phase6-rehearsal` was moved to `/mnt/holochain/offloaded/sf/mpc-phase6-rehearsal`
and replaced by a symlink (23 October). Lair records the resolved socket path, and
`mpc-phase5c-provision` refuses a `--lair-root` spelled through the symlink
(`Lair socket is not inside the given Lair root`). The rehearsal builds `Run.root`
from `HOME/...` unresolved. This was reproduced with the harness using the same path
construction (the rehearsal itself starts with `cargo build`, which this work must not
run in the operator's target directory). The harness resolves the path; the fix for the
rehearsal is `.resolve()` on its base directory.

**E2 — Relays can start before their worker's socket exists (environment).** One run
lost this race under load (`FAIL: relay service terminated: No such file or directory`,
node never admitted the DKG). The rehearsal starts workers, signers and relays in the
same order, so it shares the race. The harness now waits for `controller.sock` and
refuses to treat an abort as evidence unless all three nodes journaled admission.

**Observations (no action implied).**
- A completed signature leaves the signer's lifecycle `open` and its nonce `published`;
  there is no terminal "done" state. A killed signer leaves `open` and
  `reserved`/`published`. Those rows are what make a repeat of the operation
  permanently refused.
- A restarted `mpc-sign` for a dead operation still makes the signed *read* calls
  (activation and approval polls) before the deadline conflict stops it; it writes
  nothing and reserves nothing.
- After `SIGKILL` the worker's `controller.sock` is left behind; harmless, because the
  journal check refuses the restart first.
- A frozen node's own deadlines (15 s signer RPC) abort it on resume, so a stall longer
  than a deadline cannot silently rejoin.

## What this does not show

- **Process kills are not power loss.** `SIGKILL` stops a process between syscalls;
  fsync ordering, torn pages and disk-full are untested.
- **Single host, one UID.** No separate machines, real latency or loss; the namespaces
  model total drops, not slow links.
- **No Byzantine members**, equivocation, clock jumps or database rollback.
- **No kill of a selected signer's conductor mid-signing**, and no freeze inside the
  relay's idle sleep (the freeze lands in an RPC, so the resumed node aborts on its
  own deadline rather than rejoining a dead ceremony).
- **Persistent 5C deployment** untouched: its cells still run the 17 October
  coordinator.

## Run records

| Run | Where | Result |
|---|---|---|
| Suite A (first of two consecutive) | `faults-suite-20261026T222021Z`, 22:20–22:29, 8 min 38 s | 18 of 18 completed as documented: 12 PASS, 6 FINDING (`dkg-kill-r1/r2/r3`, `dkg-kill-r3-partial`, `dkg-stop`, `dkg-partition`), 0 FAIL |
| Suite B (immediately after) | `faults-suite-20261026T222901Z`, 22:29–22:37, 8 min 14 s | identical statuses; journal states and revisions identical to suite A (for example survivors 3 / 9 / 12 and victim 1 / 8 / 11 for the three kill rounds) |
| Alone: `sign-kill-reserved`, `-share`, `-aggregate` | `faults-suite-20261026T223726Z` | 3 of 3 PASS |
| Alone: `control`, `sign-recover-new-op`, `sign-kill-commit`, `sign-unselected-mid` | `faults-suite-20261026T224002Z` | 4 of 4 PASS (`control`: DKG, activation and one OpenSSL-verified signature through the harness, 101 s) |

Each suite directory holds `SUMMARY.json` (every check with its detail, the journal
snapshots and the signer-proxy request traces); the run directories hold the logs.
Development runs before the final code are not counted. One of them, a suite run just
before the last harness fixes, failed `dkg-kill-r1` because of E2; the fix was made and
both consecutive suites above ran on the fixed code, unchanged since (script checksums
below).

Checksums of what was run (binaries built 22 October; harness files):

```
9dcf7679bca578d7aeac99969eb347fb…  mpc-conductor-call
b8e5862c411b5fa4566770ba6a9725d5…  mpc-conductor-connect
75c89c65576426e327711a285c4d2a23…  mpc-dkg-worker
6bfd908639eb3bbe7ffa6561a7369752…  mpc-lair-live-probe
0f67e4eecc50125434b5a31f633275f4…  mpc-lair-signer
587f827c5ce74128e91a8de44520b44b…  mpc-node
5d4b4b5a4013acf3c305b29b7f8ae6de…  mpc-phase5b-bootstrap
68c5c8f0db667103a7e6fda397e0cfa3…  mpc-phase5c-provision
21bea4a9192e6417da0e06d34eeb1e37…  mpc-relay-service
f4dab59f000e8f39ada768981dcd1ea1…  mpc-sign
4546b1510ed52394a7a115b5aee1f4e1…  mpc-transport-probe
38efb4a9bcc3accd2eff2da0fbf451c8…  workdir/holochain-mpc-core.happ
ac59112e1bbedefdf427d1fae17084b3…  scripts/phase6_faults.py
ab544e4a2c8b84c4a0dfcd3e99eecad2…  scripts/faults_env.py
e24f74b8e906a08cda9656e37f42a1ed…  scripts/faults_scenarios.py
f2ff9209717d8951578196e9010fd16e…  scripts/faults_signing.py
(first 32 hex digits of each SHA-256)
```
