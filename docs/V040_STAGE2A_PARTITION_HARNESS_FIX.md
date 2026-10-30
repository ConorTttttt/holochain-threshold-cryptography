# v0.4.0 Stage 2A — partition fault tests restored under the custody root refusal (I-5)

27 October 2026 (Europe/London). Done by the coding assistant as the Stage 2
integration engineer. **Single-host development evidence, not production custody,
not an independent audit.** No product code was changed. No persistent conductor,
sandbox, Lair, credential, nonce journal or live key was touched. No commit, ref,
branch or push was made.

## Result

**COMPLETE.** Both partition scenarios now run against the integrated Stage 1
binaries, with custody at a nonzero euid. The custody root refusal is unchanged and
was shown to be still in force.

- `dkg-partition` ends **FINDING (F1)**, as it did on the 22 October binaries.
- `sign-partition` ends **PASS**.
- Two consecutive full suites (`--suite --with-control --jobs 4`) each attempted all 19
  scenarios: **13 PASS, 6 FINDING (F1 ×5, F2 ×1), 0 FAIL, 0 HARNESS-ERROR, 0 SKIP**.
  The two suites have identical statuses, check names, check results and finding tags.

The fix is in the test harness only: three scripts edited, one new script. It moves
the custody stack *out* of the user namespace. Only the conductors stay in the
private network.

## Root cause

Agent 3's harness re-executed each partition scenario under `unshare -Urmn`. Every
process of the scenario then ran in one rootless user namespace with the mapping
`0 1000 1`, and that included `mpc-node`, the relays, the signers and `mpc-sign`.
Inside, they all had euid 0 and a full capability set. Agent 2's
`check_location` (`crates/mpc-runtime/src/custody.rs:176`) correctly refuses euid 0,
so `mpc-node provision` failed before any fault was injected (`node-provision-1.log`:
`unsafe custody layout: custody must not run as root`).

Changing the `unshare` flags alone cannot fix this. The probe
(`evidence/ns_probe.sh`, log `logs/ns-probe-1.log`) ran `mpc-node provision` in each
mapping:

| Mapping | euid inside | CapEff | veth / nft | `/` and `/mnt` seen as | `mpc-node provision` |
|---|---|---|---|---|---|
| host (no namespace) | 1000 | 0 | refused (as intended) | 0:0 | **accepted** |
| `unshare -Urmn` (Stage 1) | 0 | `000001ffffffffff` | ok | 65534:65534 | refused: *must not run as root* |
| `unshare --map-current-user -mn` | 1000 | 0 | **refused** (caps dropped on exec) | 65534:65534 | refused: *`/mnt` is owned by another user* |
| `… --map-current-user --keep-caps -mn` | 1000 | full, ambient | ok | 65534:65534 | refused: *`/mnt` is owned by another user* |

Two facts follow:

1. In an unprivileged user namespace, only namespace root (or a process with
   ambient capabilities) can build the network. Custody must have neither.
2. `check_location` walks every ancestor up to `/` and accepts only the owners root
   and euid. An unprivileged namespace cannot map real root, so `/` and `/mnt` appear
   as the overflow uid 65534. No process inside **any** rootless user namespace can
   pass the check, whatever its uid. Making it pass would need a weaker custody check
   or a fake root filesystem. Both were ruled out.

`newuidmap` is not installed, so multi-uid mappings (`--map-users`, `--map-auto`)
were not available. They would not help in any case, because of fact 2.

## Which processes need what

| Process | Needs a private network? | Needs capabilities? | Runs as (after) |
|---|---|---|---|
| `holochain` conductor + its `lair-keystore` (`hc sandbox`) | **yes**, it is what gets partitioned | no | euid 1000, CapEff 0, own node netns, hub user namespace |
| `kitsune2-bootstrap-srv` (bootstrap + relay) | yes, it sits in the hub | no | euid 1000, CapEff 0, hub netns |
| `ip`, `nft`, the `ip_forward` sysctl, namespace holders | yes | **yes**, inside the hub user namespace only | euid 1000 + caps in the hub user namespace (`nsenter --keep-caps`) |
| `mpc-node` (worker), `mpc-relay-service`, `mpc-lair-signer` (DKG and signing profiles), `mpc-sign`, `mpc-phase5c-provision`, `mpc-phase5b-bootstrap`, `hc client` | no; they only talk to their own conductor and Lair | no | **host namespaces**, euid 1000, CapEff 0, as in every other scenario and in production |

## The fix (harness only)

Topology, built by `Net` in `scripts/faults_env.py`:

```
host user + net namespace (uid 1000, no caps)
 ├─ custody stack per node ──TCP 127.0.0.1:{admin,app}──> bridge-host-N ──┐
 │                                                                         │ unix socket
 │   run/fw/<port>.sock (dir 0700, this user)  <───────────────────────────┘
 └─ hub user namespace, uid_map "1000 1000 1"  (unshare --map-current-user -n)
     ├─ hub netns: 10.77.0.1  kitsune2-bootstrap-srv,  nft table inet faults
     ├─ node-1 netns 10.77.1.2 <-veth vh1/vn1-> hub   conductor-1 (+Lair), bridge-ns-1
     ├─ node-2 netns 10.77.2.2 <-veth vh2/vn2-> hub   conductor-2 (+Lair), bridge-ns-2
     └─ node-3 netns 10.77.3.2 <-veth vh3/vn3-> hub   conductor-3 (+Lair), bridge-ns-3
```

- **Hub.** `unshare --map-current-user -n sleep infinity` keeps the hub user and
  network namespace alive. Each node holder is
  `nsenter -t <hub> -U -n --preserve-credentials --keep-caps -- unshare -n sleep infinity`.
  The holders get `PR_SET_PDEATHSIG=SIGKILL`, and the harness keeps their PIDs.
- **Plumbing** (`ip`, `nft`, the sysctl) runs through `nsenter … --keep-caps`. This is
  the only place where capabilities exist, and they are capabilities in the hub user
  namespace, which owns nothing on the host.
- **Conductors and bootstrap server** run through
  `nsenter -t <holder> -U -n --preserve-credentials --`. That gives euid 1000, no
  capabilities, and the node's network namespace.
- **Custody stack.** `Env.argv()` no longer adds any namespace prefix. The worker,
  relays, signers, `mpc-sign` and the provisioning tools run exactly as they do in
  the non-partition scenarios.
- **Port bridge** (`scripts/faults_portfwd.py`, stdlib only). Each node's conductor
  admin and app ports are bridged to the *same* port numbers on the host loopback:
  host TCP, then a unix socket in a 0700 run directory, then TCP in the node netns.
  It copies bytes only. No custody argument (`--app-socket`, `--origin`, ports)
  changed.
- **Partition.** This is unchanged:
  - `dkg-partition` downs the node's hub-side veth.
  - `sign-partition` adds nft drop rules in the hub, both for the direct pair and for
    each node's traffic to the relay port.
  - The drop rules now also carry `counter`, which does not change what they drop.
  - The bridge is the node's local link to its own conductor. The partition never
    cut it before either: it was the loopback inside the node netns.
- **Re-exec removed.** `phase6_faults.py spawn()` no longer wraps children in
  `unshare -Urmn --kill-child`, and the `MPC_FAULTS_NETNS` variable is gone.
- **Teardown.** Holders and the hub are killed by PID and waited for. The harness
  then scans `/proc` for any process still in the recorded namespaces and writes
  `NETNS-TEARDOWN.json` to the run directory. Bridges and conductors are `rh.Proc`
  process groups that `stop_all()` stops, as before.

New checks in the two partition scenarios. Existing checks, `differs("F1")` and
the scenario names are unchanged.

- At the moment of the cut, every custody process is euid = this user ≠ 0, has
  CapEff 0 and is in the host user and network namespaces. Each conductor is euid =
  this user, has CapEff 0 and is in its own node netns.
- Control: the same `mpc-node` under `unshare --map-root-user` is refused with
  *custody must not run as root* and writes nothing.
- The partition is real, checked while it is still in place:
  - TCP probes from inside the node namespaces, as this user without capabilities,
    get no answer on every cut path (*timeout* or *unreachable*). On every uncut
    path they connect or are actively refused.
  - `dkg-partition`: the hub-side veth state is `DOWN`.
  - `sign-partition`: the nft counters show that real conductor traffic was
    dropped.

One harness defect was found and fixed during this work. A node holder starts in the
host netns, joins the hub, then runs `unshare -n`. The first version waited only for
"not the hub's netns", which the host netns already satisfies. Under suite load the
veth peer was then created before `unshare -n` and went into the hub instead of the
node. Pre-fix suite `faults-suite-20261027T140122Z` therefore ended 18/19, with
`sign-partition` HARNESS-ERROR `Cannot find device "vn1"`. The wait now excludes both
the host and the hub netns. A stress test (`evidence/net_stress.py`, 4 parallel
processes × 15 setups) failed 6/60 with the old wait (`logs/net-stress-old-wait.log`)
and 0/60 with the fix (`logs/net-stress.log`). No host interface was created in either
case: the misplaced peer could only land in the hub, which is destroyed at teardown.
That suite was produced by pre-fix code and is not counted below.

## UID/GID and namespace mapping, before and after

| | Before (Stage 1) | After (Stage 2A) |
|---|---|---|
| Harness child | in `unshare -Urmn`, uid 0, CapEff full | host namespaces, uid 1000, CapEff 0 |
| Custody processes | user ns `0 1000 1`, euid 0 / egid 0, CapEff `000001ffffffffff`, setgroups deny, supplementary groups → 65534 | initial user ns (`0 0 4294967295`), euid 1000 / egid 1000, CapEff 0, host netns (`user:[4026531837]`, `net:[4026531833]` in the runs) |
| Conductors + Lair | same namespace as custody, euid 0, full caps | hub user ns `1000 1000 1`, euid 1000, CapEff 0, one netns per node |
| Network plumbing | the harness itself (euid 0 in the namespace) | `nsenter --keep-caps`: euid 1000 with caps **in the hub user ns only** |
| File ownership on disk | uid 1000 (namespace 0 maps to 1000) | uid 1000 for everything; no namespace-root ownership |
| Ancestors as custody sees them | `/`, `/mnt` → 65534 | `/`, `/mnt` → 0 (real root), the rest → 1000, as in production |

Every partition run records the per-process values in `RESULT-*.json`
(`identities_at_cut`, `namespaces`) and in its check details.

## Why production custody security is unchanged

- **No product file changed.** `diff -rq` between the integration tree and the
  Stage 2A copy (excluding `target/` and `__pycache__`) lists only:
  - `scripts/faults_env.py`, `scripts/faults_scenarios.py` and `scripts/phase6_faults.py`;
  - the new `scripts/faults_portfwd.py`;
  - `docs/V040_PHASE6_FAULT_TESTS.md`.

  `custody.rs`, signing, DKG, cryptographic code, the DNA and the lockfile are
  untouched.
- **Same binaries.** No binary was rebuilt. The scenarios used the integrated Stage 1
  binaries, copied and verified by SHA-256 (`evidence/integrated-binaries.sha256`,
  13 binaries plus the `.happ`).
- **No new bypass.** There is no `--allow-root`, no environment variable, no
  world-writable directory and no change to any persistent directory. The bridge
  sockets live in a 0700 directory of the disposable run.
- **Still enforced, from the outside.** These ran as namespace root
  (`logs/root-refusal-integrated-binaries.log`):
  - The integrated `mpc-node provision`, `mpc-node serve` and `mpc-custody verify`
    are refused with *custody must not run as root*. The refused provision creates no
    directory, and the refused serve creates no socket.
  - The same `mpc-node provision` as the ordinary user succeeds.
- **Still enforced, in the scenario.** Each partition run repeats the namespace-root
  control and passes it.
- **Still enforced, in the source.** `cargo test -p holochain-mpc-runtime` passes 21/21.
  The same `durable` test binary run under `unshare --map-root-user` fails exactly the
  4 custody-layout tests with `Unsafe("custody must not run as root…")`.
- **Closer to production than before.** Custody in the partition scenarios now runs
  exactly as in production: as an ordinary user, in the host namespaces, with real
  directory ownership. Before, it was namespace root with every capability.

## Commands executed

All commands ran in `dkg-v040-stage2a/holochain-mpc-core` with `TMPDIR=/tmp/v040s2`,
except where a different directory is named.

| Command | Result |
|---|---|
| `sha256sum -c ../evidence/integration-manifest.sha256` (integration tree, start and end) | OK both times; manifest hashes equal the handover's |
| `python3 -I scripts/phase6_faults.py --scenario dkg-partition --keep` (unmodified harness) | **reproduced I-5**: HARNESS-ERROR at `node-provision-1`, *must not run as root* (`faults-suite-20261027T134639Z`) |
| `bash ../evidence/ns_probe.sh …` | table above (`logs/ns-probe-1.log`) |
| `bash ../evidence/topo_probe.sh` | rootless hub/node topology works: plumbing has caps, the workload is uid 1000 with CapEff 0 and cannot change links, link-down cuts, heal restores, PIDs cleaned (`logs/topology-probe.log`) |
| `cargo test --offline --locked -p holochain-mpc-runtime` (`CARGO_TARGET_DIR=../target-tests`) | **21 passed**, 0 failed (5 lib + 4 `dkg_journal` + 12 `durable`) |
| `unshare --map-root-user …/durable-4fa9fecff1710057 --test-threads 1` | 8 passed, **4 failed with the root refusal** (expected) |
| `bash ../evidence/root_refusal_check.sh …` | integrated binaries refuse namespace root (above) |
| `python3 -I scripts/phase6_faults.py --list` | exit 0, 19 scenarios, 2 marked `ns` |
| `python3 -I scripts/phase6_faults.py --self-check` | exit 0; *rootless user namespace mapping only uid 1000 … custody stays in the host namespaces* |
| `python3 -I ../evidence/net_stress.py scripts 15` ×4 parallel | 0/60 bad (old wait: 6/60 bad) |
| `--scenario dkg-partition` (final code) | **FINDING (F1)**, exit 0 (`faults-suite-20261027T141105Z`) |
| `--scenario sign-partition` (final code) | **PASS**, exit 0 (`faults-suite-20261027T141313Z`) |
| `--suite --with-control --jobs 4`, suite 1 | exit 0, 19/19 as documented (`faults-suite-20261027T141553Z`, 14:15:53–14:25:33 UTC) |
| `--suite --with-control --jobs 4`, suite 2 (immediately after) | exit 0, 19/19 as documented (`faults-suite-20261027T142533Z`, 14:25:33–14:36:19 UTC) |

Earlier development runs (`…T135647Z`, `…T135845Z`: the two scenarios alone, before
the race fix) and the pre-fix suite (`…T140122Z`) are kept but not counted. Harness
checksums for the counted runs are in `evidence/harness-as-run.sha256`.

## Results of the two full runs

| Scenario | Suite 1 | Suite 2 |
|---|---|---|
| control | PASS | PASS |
| dkg-kill-r1, -r2, -r3, dkg-stop | FINDING (F1) | FINDING (F1) |
| dkg-kill-r3-partial | FINDING (F2) | FINDING (F2) |
| **dkg-partition** | **FINDING (F1)** | **FINDING (F1)** |
| dkg-stop-short, dkg-seal-kill-before, dkg-seal-kill-after, dkg-restart-refused | PASS | PASS |
| sign-kill-reserved, -commit, -share, -aggregate, sign-recover-new-op, sign-unselected-mid, -early | PASS | PASS |
| **sign-partition** | **PASS** | **PASS** |
| Totals | 13 PASS, 6 FINDING, 0 FAIL, 0 HARNESS-ERROR, 0 SKIP | identical |

Partition evidence from the two suites:

- **`dkg-partition`.**
  - The fault fired at node 2's first round-2 send.
  - All three relays exited 1 with `DKG polling deadline exceeded; do not retry RPC`.
  - No node has a sealed share, a descriptor or a `completed` journal.
  - After healing and 30 s, no journal changed.
  - The survivors' journals are `running` (F1, unchanged).
  - Probes: node 2 to the hub, and nodes 1 and 3 to node 2, were *unreachable*.
    Nodes 1 and 3 to the hub *connected*, and node 1 to node 3 was *refused* (path up).
  - The veth was `DOWN`.
- **`sign-partition`.**
  - Neither signer produced a signature or a file.
  - Both journaled `aborted` with nonce `burned`. Node 1's reason is `signed MPC RPC
    failed: Timeout`. Node 3's is either that or `signature not reached within the
    poll budget`, depending on timing; both satisfy the unchanged check.
  - After healing, the repeat was refused (`deadline already registered`).
  - The nft counters dropped 169 and 197 packets.
  - Probes: node 1 to node 3, node 3 to node 1, and both to the relay port *timed
    out*. Node 2 to the relay *connected*, and node 1 to node 2 and node 2 to node 3
    were *refused* (paths up).
  - No forbidden nonce reuse: each signer holds exactly one, burned, nonce slot for
    the operation, and the repeat added none.
- **Cleanup.** `NETNS-TEARDOWN.json` reports `released: true` and no process left in
  the namespaces, for all four counted partition runs. After the runs, no harness
  process (`sleep` holder, bridge, conductor, Lair, bootstrap, `mpc-*`) was left for
  this user.

## Remaining failures and limitations

- **F1 and F2 are open product findings.** They are reproduced exactly as before,
  and nothing here changes them.
- **Rootless namespaces and nft.** The partition scenarios need unprivileged user
  namespaces, util-linux ≥ 2.39 (`--map-current-user`, `--keep-caps`), `ip` and
  `nft`. This host has `kernel.apparmor_restrict_unprivileged_userns=1`, but the
  probes work. A host that refuses them gets SKIP with the reason, and a SKIP is not
  counted as partition coverage.
- **Coverage.** The partition cuts conductor-to-conductor and conductor-to-relay
  traffic, as before. It does not cut a node's link to its *own* conductor, which is
  local in production. Total drops only, no latency or loss. Single host, one UID
  (custody and conductor are the same user, which is not the separated layout).
- **Ports.** The bridge binds the conductor's port numbers on the host loopback. They
  are chosen by `free_port()` as in the other scenarios, so a rare collision with
  another local process would give HARNESS-ERROR, not a false result.
- **Not run.** `npm run test:share-custody` (worker crate, needs a large build; the
  root refusal lives in `mpc-runtime`, which was tested), the persistent sandboxes
  (forbidden), and any separate-machine run.
- **Host event during suite 2.** At 14:35:36 the kernel logged a USB hub disconnect
  (buses 1-7 and 2-1), which removed the USB NIC `enx6c6e07423c0c`. It was hardware
  or hub related, not the harness: the harness has no capability in the host
  namespace. The host's other interfaces are unchanged, and no veth, `vh*`/`vn*` or
  nft table was ever created in the host namespace.

## Evidence that originals were not touched

- **Stage 1 integration tree.** `integration-manifest.sha256` verifies before and
  after. These hashes are unchanged and equal the handover's:
  - `c5ef3aef…`, `3c4bc3c6…` and `2803c864…`;
  - `STAGE2_HANDOVER.md` (`69617c31…`), `PATCH_APPLICATION_RECORD.md` (`1be61b68…`)
    and `run_tests.sh` (`a0c87300…`).

  `find -newer` (excluding the build cache) lists nothing. The integrated binaries
  verify against `evidence/integrated-binaries.sha256`. No `run_tests.sh` step ran,
  so `logs/test-results.tsv` is untouched.
- **Original repo.**
  - `git --no-optional-locks status --short | wc -l` is still 75, and HEAD is still
    `544270f`.
  - The five `refs/checkpoints/*` are unchanged; `security-review-20261022` is still
    `b96ffdf`.
  - `find -newer` outside `target/` lists nothing.
- **Persistent sandboxes.** `~/mpc-phase5b-sandbox`, `~/mpc-phase5c-sandbox` and
  `~/.local/state/mpc-phase5c` were never named in any command. The harness still
  refuses them (`FORBIDDEN`). Every run directory is under
  `/mnt/holochain/offloaded/sf/mpc-phase6-rehearsal/`.
- **GitHub.** Nothing was pushed or fetched.

## Handover

- Patch: `dkg-v040-stage2a/stage2a-partition-harness.patch`. Apply it with
  `patch -p1` in the integration tree.
- New files: `scripts/faults_portfwd.py` and this document.
- Edited files: `scripts/faults_env.py`, `scripts/faults_scenarios.py`,
  `scripts/phase6_faults.py` and `docs/V040_PHASE6_FAULT_TESTS.md`.
- After applying, regenerate `evidence/integration-manifest.sha256`.
- Proposed handover edits:
  - Close I-5 as resolved in the harness, and rerun the suite after merging.
  - Note that the partition evidence now runs on the integrated binaries.
  - Keep F1 and F2 open.
