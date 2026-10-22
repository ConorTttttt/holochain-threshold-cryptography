# Phase 5C-C read-only live preflight checklist

Prepared 18 October 2026. **NOT EXECUTED.** Current review recommendation is
NO-GO for deployment writes (see `V040_PHASE5C_C_SECURITY_REVIEW.md`). This
checklist authorizes nothing by itself. It prepares public/metadata-only
checks of the existing conductors; it is not a probe setup script.

## Scope and stop rules

- Use existing running services. No restarts, installs, DNA/coordinator updates,
  new sandboxes, DKG workers, relay daemons, signers or writable DB opens.
- No proposals, acceptances, grants, registrations, messages, revocations,
  credential issuance, transport-key creation, local-state provisioning or
  changes to permissions. No repair commands on failed checks.
- Do not read/cat/copy/hash tokens, private keys, capability records, policies,
  keystore databases or native databases. Do not dump environment, process
  arguments, shell history or unfiltered logs/state. Do not enable debug traces.
- `mpc-node transport-key-public` performs secret recovery and may write SQLite;
  it is NOT read-only. Probe `inspect` also opens writable local state and
  authenticates; neither belongs in this preflight.
- Existing `phase5b_preflight.py` can read configs and call dump-state. Do not
  run its broad live modes as a substitute for this restricted checklist.
- A failure/missing/expired credential means STOP, not implicit permission to
  renew, unlock Lair, recreate files, initialize cells or rerun prior writes.
- Record only public identifiers, settings, version strings, metadata and
  PASS/FAIL/UNVERIFIED. Review outputs before sharing. Never attach raw private
  files or a live sandbox/native-state backup to source-control artifacts.

## 1. Source and review gate

- [ ] B1/B2 remain unresolved until separately approved hardening is reviewed.
      A passing reproduction is evidence of a gap, not a fix.
- [ ] Resolve and record the source-only checkpoint commit and tree. Confirm
      source manifest hashes and offline results. Preserve the original
      source archive. No Git reset/clean/checkout is needed.
- [ ] Confirm only native binaries will be used later. Do NOT run `build:happ`,
      sandbox generation, app install/update or network-seed modification.
- [ ] Record locally available `holochain --version` and `hc --version`.
      Compare with the pinned 0.7.1 source family. A mismatch is a stop gate.
      These version commands do not contact a conductor.

## 2. Public conductor identity and app-interface metadata

Get the CURRENT admin ports from existing operator-held public startup records.
Ports from the historical report (34835 and 35169) may have changed; do not
assume them or restart anything to recover them. Set only public port variables.
Then, if separately authorized to execute public administrative reads:

```sh
hc client call --port "$ADMIN_A" list-apps
hc client call --port "$ADMIN_B" list-apps
hc client call --port "$ADMIN_A" list-app-ws
hc client call --port "$ADMIN_B" list-app-ws
```

- [ ] Each existing `mpc-phase5c` app is enabled, with exactly the expected
      provisioned `mpc` role/cell; no clone substitutes for the pinned cell.
- [ ] Both report the same independently approved DNA hash and distinct,
      correct agent keys. Compare complete identifiers, not short prefixes.
- [ ] Historically recorded expected values (not freshly verified here):

```text
DNA: uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu
A: uhCAkwfXPxtzM7lKfMBc1BS8TZkPpcBPav6RoxhpA2YfrhGjo0BQo
B: uhCAkU0m8gBCkoSRobThBSYh47kC-DiAhCR1AJKmxUB1uf-Oi6vtb
App ports last reported: A 8891, B 8892
```

- [ ] Record actual app ports, allowed origins and installed_app_id binding.
      Future probe CLI sockets must be numeric loopback addresses. Origins
      must match its accepted `http://localhost[:port]` form and interface
      settings. Wildcard origins/unbound interfaces are development limitations;
      record them without changing settings during preflight.
- [ ] An installed hash match proves identity to the pinned public value, not
      the source-to-WASM build provenance. Any missing provenance stays
      UNVERIFIED. Do not rebuild/reinstall to make a mismatch disappear.

## 3. Public network observations

Optional separately authorized metadata reads:

```sh
hc client call --port "$ADMIN_A" list-agents
hc client call --port "$ADMIN_B" list-agents
hc client call --port "$ADMIN_A" dump-network-stats
hc client call --port "$ADMIN_B" dump-network-stats
```

- [ ] Record expected space/peer metadata and observed connectivity. Null
      remote agent fields or traffic counters do not prove authenticated
      application delivery, decryption, acceptance or DKG completion.
- [ ] No send/ping zome invocation or source-chain write is needed. A network
      observation is not finality. A failure leads to investigation only.

## 4. Preserve original ceremony and private-state boundaries

- [ ] Retain the original FROST proposal/session identifiers from approved
      PUBLIC records. Historical proposal:
      `uhCkk5YMJyNLP2DXnLnuvXIyY66dMl0mwYqx4tgT0ucDPDgxyIhmD`;
      session `e26c6855fd54ab228c5c386196754eaf4cfab16d0377deae0f9b0c7df2684371`.
      No reacceptance, key replacement or grant rotation is implied.
- [ ] Plan distinct probe proposal/session, node directories, signer socket
      and policy paths. Check proposed destination existence by metadata
      only; an existing path is a stop for investigation, not reuse/removal.
      Do not create paths during preflight.
- [ ] If separately authorized, inspect permissions/ownership/file-kind/link
      counts using `stat`/`lstat` only. Contents of existing private state and
      credentials remain out of scope. Do not recursively enumerate keystores.
- [ ] Existing app tokens are NOT assumed valid from their presence/mode.
      Token validity is UNVERIFIED in this public-only checklist. Do not issue
      a token, unlock Lair or start a signer to test it.
- [ ] Fresh signed session/status reads require separate authorization for
      credential use. Native commands using existing Lair/token state are not
      included here. Existing consent/grant evidence is historical until that
      later approved read; public metadata alone cannot reverify it.

## 5. Approval gates for later stages — no execution here

- [ ] A future probe uses `mpc-transport-probe` v1, two exact participants,
      threshold two and max_round one, under a NEW proposal/session. Never
      invoke the default FROST `propose` path for diagnostics.
- [ ] Separate approval is needed for proposal/acceptance writes, new private
      node/key state and any token issuance. Existing FROST state stays intact.
- [ ] Before any probe signer/send: independently verify a NEW assigned grant
      and confidential authenticated exchange/import of its secret. Verify
      exact grant author/action, assigned peer and sole inbox function; reject
      orphaned/ambiguous grants and four-byte tag collisions. Do not print the
      secret, load an old FROST policy, or treat a label as proof of provenance.
- [ ] Before registration: verify the retained key belongs to the new probe
      state. Existing own registration or attempt marker means reconcile;
      missing local receipts or DHT links do not authorize a retry.
- [ ] Before send: approve exact author/action/public-key pins independently
      of conductor observations, full plan/direction/digest/limits, one message
      identity and a separate probe profile. Establish a no-rollback rule.
- [ ] `pending`/`uncertain` admissions never authorize another send. Recipient
      native decryption and durable receipt are separate acceptance criteria.
      Never follow the coordinator's generic same-sequence retry suggestion
      for this probe; do not use another tool to bypass the admission ledger.

## Handoff

Record each check as PASS / FAIL / UNVERIFIED with public evidence and date.
Even all PASS results here do not clear B1/B2 or authorize deployment. Proceed
only to the next explicitly approved stage after the security review is
reopened and its blocking findings are resolved.
