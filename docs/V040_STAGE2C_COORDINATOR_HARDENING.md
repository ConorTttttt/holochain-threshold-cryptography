# v0.4.0 Stage 2C — coordinator inbox hardening (R10 offline half, R11)

27 October 2026 (Europe/London). Done by the coding assistant as the
coordinator protocol security engineer. **Development evidence on one host,
not production custody, not an independent audit, not a release.** This patch
has not been reviewed by a separate agent; it must be before it reaches the
operator's tree. No persistent conductor, cell, sandbox, Lair state or
credential was touched, and `update_coordinators` was not run.

## Result

**Implemented and verified: R11 is reproduced on the Stage 2B coordinator and fixed in the coordinator only; R10's HeadMoved is reproduced on the 17 October coordinator and the delivery error kinds now survive. The new tests fail before the change and pass after it; `test:sweettest` (11/11) and `test:native` (153/153) pass. `check:release` fails only at `identity`, because the coordinator hashes legitimately changed and need an operator re-record after independent review.**

- **Conflicts are localized.** A conflicting pair for one
  (sender, round, sequence) slot no longer makes `get_inbox` fail. The slot is
  withheld, never chosen, and every variant is kept and returned by the new
  `get_inbox_slots`. Other slots stay readable.
- **Per-sender share, strict on read.** Each authenticated sender gets
  `clamp(4096 / (members − 1), 1, 4096)` slots per recipient and proposal:
  2,048 for this project's three members. Deliveries past the share are
  refused with `inbox_sender_quota`. Concurrent deliveries can still overshoot
  the write check (measured: 3–4 extra records with 64 concurrent deliveries), but `get_inbox` never serves
  more than the share, so served totals stay within the native clients' 4,096
  limit.
- **Error kinds survive.** Every inbox refusal starts with a stable code
  (`inbox_conflict`, `inbox_sender_quota`, …) and says whether a delivery was
  stored. The code survives `call_remote`, which used to hide it. The Stage 2B
  wording follows the code. Nothing advises a retry.
- **Identity.** Integrity WASM and DNA hash are byte-identical to Stage 2B.
  The coordinator WASM, `.dna` and `.happ` bytes change, as expected for a
  coordinator change.
- **Not solved:** a silent or self-equivocating member still stops a unanimous
  DKG and any signing it was selected for; Holochain gives this protocol no
  global finality; group lifetime stays bounded. See "What the fix prevents,
  and what it does not".

## Starting point (verified before any change)

| Check | Result |
|---|---|
| Stage 2B tree `dkg-v040-stage2b/holochain-mpc-core` against `evidence/stage2b-source-manifest.sha256` (SHA-256 `f2c13233…fe61`) | OK, 197/197 files, on the new copy `dkg-v040-stage2c/holochain-mpc-core` (rsync without `target/`) |
| Stage 2B patch | `c41f43dc…ffc9a`, equal to `STAGE2_HANDOVER_UPDATE.md` |
| Pristine read-only copy for the patch | `dkg-v040-stage2c/stage2b-pristine/` |
| Build cache | Stage 2B `target/{debug,release,wasm32-unknown-unknown}` copied (62 GB, 2,005 s) |
| Reference identity built in the copy before any change | equals `scripts/release_hashes.json` exactly (`evidence/reference-identity-stage2b.txt`) |
| Earlier "Agent 1" documentation | not used as evidence; `docs/V040_COORDINATOR_INBOX_HARDENING.md` does not exist in the Stage 2B tree |

Reference identity (Stage 2B, rustc 1.99.0, cargo 1.99.0, `hc` 0.7.0,
hdk =0.7.1, hdi =0.8.1):

| Artifact | SHA-256 |
|---|---|
| Integrity WASM `mpc_integrity.wasm` | `2d6aa14170e4e1d40a78fc270d89a7534e943813b18811a66a84c88c6bb4ffdb` |
| Coordinator WASM `mpc.wasm` | `432d4d7d2e0244cad46c1c747f4fd2bdb2f9b15cf510218dd4a4b6ef8ee19614` |
| `mpc.dna` | `7f77af71ba633536139f77702de1d8e74b77b8f437f33bf9328ec3856d7f7452` |
| `holochain-mpc-core.happ` | `38efb4a9bcc3accd2eff2da0fbf451c8f1d981b366819d00c1eac52655bac1e5` |
| DNA hash | `uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu` |

## Reproductions (Task A)

All in `dnas/mpc/zomes/coordinator/mpc/tests/inbox_hardening.rs`. The file
uses only extern names and its own mirror of the new response type, so the
same file compiled and ran unchanged against the Stage 2B coordinator. Four
agents on one conductor; the test calls Bob's `receive_protocol_message` with
another agent's provenance and Bob's real assigned capability secret, the same
grant and provenance checks as `call_remote` without the network. Two tests
use three conductors and `send_protocol_message`.

| Scenario | Stage 2B coordinator (`432d4d7d…`) | Log |
|---|---|---|
| Conflicting pair | Both variants committed at the **first** concurrent attempt. `get_inbox` then failed for the whole proposal: `Guest("Equivocation: conflicting messages with the same ID")`. Carol's round-1 message (before) and round-4 message (after) were unreadable | `logs/tests/test-inbox-hardening-baseline-run1.log` |
| Flood, client limit | Alice stored all **4,097** distinct slots with no refusal (983 s). Carol was still stored, and `get_inbox` served **4,098** envelopes, more than the 4,096 at which `conductor_client.rs` and the DKG relay refuse the **whole** inbox, Carol's slots included | `…-baseline-run2.log` |
| Flood, coordinator capacity | Code: one shared `recorded.len() >= 16_384` check. A full 16,384-delivery fill was started and stopped by the assistant after 81 min (each delivery rescans the inbox, so the fill is quadratic under the debug conductor, and it held the build lock). Not completed; the 4,097 result above already shows that one sender consumes other senders' capacity | `…-baseline-run1.log` (tail) |
| Concurrent quota | 64 concurrent deliveries with Alice already at 2,040: **64 stored, 0 refused**; no per-sender limit at all | `…-baseline-run1.log` |
| Error kinds, receive | Forged sender correctly refused, but as `holochain_mpc_adapter … Guest("authenticated caller does not match envelope sender")`: no kind | `…-baseline-run1.log` |
| Error kinds, send | The recipient's conflict refusal reached the sender as `Remote delivery not acknowledged: network: Other: invalid response to call_remote: ErrorRes { … Guest(\"Conflicting payload for an existing sender/round/sequence\") … }`: a "network" failure, with no stored/not-stored signal | `…-baseline-run2.log` |
| Honest fan-in (R10), Stage 2B | 32/32 local, 16/16 over the network: relaxed ordering already fixed HeadMoved | `…-baseline-run1.log` |
| Honest fan-in (R10), 17 October coordinator `c52292a` (built from git, read-only, into the copy and then removed) | **30 of 32** local deliveries failed with `CellError(WorkflowError(SourceChainError(HeadMoved([…]))))`, raised by the commit of `receive_protocol_message`. Over the network, **15 of 16** failed, and the sender saw only `Remote delivery not acknowledged; retry with the same round/sequence`: the kind was hidden and the text gave the N3 retry advice. The same build kept DNA hash `uhC0kp2j…P6Mwu` (coordinator `ab880bd1…`, `.dna` `7a7b2858…`) | `logs/tests/test-inbox-hardening-strict.log`, `evidence/c52292a-coordinator-identity.txt` |

Holochain path for the hidden kind: the recipient's `Cell::handle_call_remote`
turns any zome error or failed commit into a network error
(`holochain-0.7.1/src/conductor/cell.rs:420`, `call_zome(…).await??`), and the
caller's `call_remote` host function wraps it as
`ZomeCallResponse::NetworkError(e.to_string())` (`host_fn/call.rs:160`).

### Found on the way: receipt action hashes under relaxed ordering (new, R10-a)

With concurrent deliveries, **one of the two receipts' `storage_action` was
not on the recipient's chain** (`…-conflict.log`: "receipt actions not found
on the chain after the race: 1 of 2"). Under `ChainTopOrdering::Relaxed`, the
action `create` returns inside the zome is hashed before the commit rebases
it onto the moved chain head. This dates from the 22 October relaxed-ordering
change, not from Stage 2C, and the coordinator cannot know the final hash.
Consumers: the DKG relay and `signed_relay` check only that the hash is 39
non-zero bytes. `transport_probe.rs:319-328` journals it as acknowledgement
evidence; its single delivery is not concurrent, but an operator inspecting a
probe journal must look a delivery up by slot, not by that hash.
`get_inbox_slots` reports the real storage actions.

## Root causes (Stage 2B coordinator)

### R11, conflicting envelopes

`receive_protocol_message` checks for an existing (sender, round, sequence)
slot by reading the chain, then writes with `ChainTopOrdering::Relaxed`. Two
concurrent calls each read a chain that does not yet hold the other's write,
both pass, and both commit. `get_inbox` then met two different envelopes for
one slot and returned `Err("Equivocation: conflicting messages with the same ID")`
for the **whole proposal**. Every later read failed the same way, so the
recipient could no longer run DKG or any signing operation on that group. The
attacker needs only a delivery grant, which every member holds.

### R11, capacity

The only limit was `recorded.len() >= MAX_MESSAGES_PER_SESSION` (16,384), shared
by all senders. A member that sends 16,384 distinct slots leaves nothing for
anyone else; the next honest delivery fails with "Inbox capacity reached". The
check is also read-before-write, so concurrent deliveries pass it together.

There was a second, client-side limit that made this worse. Both native
consumers refuse a `get_inbox` response longer than 4,096 envelopes
(`conductor_client.rs`: `inbox.len() > 4096` → "inbox contains messages outside
pinned ceremony"; `relay.rs`: `MAX_INBOX = 4096`). One sender that delivers
4,097 slots therefore made the recipient's signed client refuse its whole inbox
long before the coordinator's 16,384 capacity was reached.

### R10, ordering and error kinds

The 17 October coordinator (`c52292a`, still on the persistent 5C cells) wrote
`InboxEvent` with strict ordering, so concurrent fan-in failed with
`HeadMoved`. The 22 October change to relaxed ordering fixed that and exposed the
conflict race above. Separately, Holochain 0.7.1 returns any remote zome error,
including a failed commit, to the caller of `call_remote` as
`ZomeCallResponse::NetworkError(text)` (`holochain-0.7.1/src/conductor/cell.rs:420`,
`host_fn/call.rs:160`). The coordinator printed that text after "network:", so a
conflict, a capacity refusal, a HeadMoved and a real network failure looked
alike to the sender, and the sender could not tell "not stored" from "outcome
unknown".

## Design

### Conflicts are isolated on read

Holochain gives the coordinator no atomic check-and-write on a source chain, and
strict ordering brings back R10. Conflicts therefore cannot be prevented at
write time without an integrity change. Stage 2C makes them harmless on read:

- `partition_inbox` groups every stored record by slot. A slot with two or more
  distinct envelopes goes to `conflicts` with **all** its variants and **all**
  their storage actions. It is never served, and no variant is chosen.
- `get_inbox` keeps its signature (`ActionHash → Vec<Envelope>`). It returns the
  served slots only, so every other slot stays readable.
- New `get_inbox_slots` returns `InboxSlots { envelopes, conflicts, over_quota }`.
  `envelopes` equals the `get_inbox` result.

A conflicting slot can only be one of the misbehaving sender's own slots: the
slot key contains the sender, and the sender is the authenticated caller
(`validate_received` against `call_info().provenance`). Withholding it therefore
removes exactly the messages that sender authored, which is the effect it could
already have by staying silent. It gains no new power over other senders' slots.

Why `get_inbox` withholds rather than returns both variants: `run_signing`
(`signing.rs:375-376`) deduplicates the inbox with
`seen.insert((sender, round, sequence))` **before** `ingest`, so it would
silently use whichever variant came first. Returning both through the old
response would turn a fail-closed whole-inbox error into silent selection in
the signer. Withholding keeps both consumers fail-closed without a client
change: a consumer waiting on that slot never receives it and fails at its
deadline (`run_signing`: poll budget, journaled abort; DKG relay: supervisor
deadline).

### The per-sender share is enforced on read

- `sender_quota(spec) = clamp(4096 / (participants − 1), 1, 4096)`: 2,048 for
  the project's three members, 4,096 for two, 1,024 for five, 65 for 64.
- Write side: `receive_protocol_message` counts the stored records whose sender
  is the authenticated caller, for this proposal, and refuses with
  `inbox_sender_quota` once the count reaches the share. Identical repeats
  return `AlreadyStored` first, so they never consume or hit the share.
- Read side: a single-variant slot is served only if its first record is among
  that sender's first `quota` records in chain order. Records past the share
  are reported in `over_quota` and never served.

The write check is read-before-write and **can be overrun by concurrent
deliveries** (measured below). The read rule cannot: it is computed from the
committed chain on every call, whatever order the writes landed in. That is the
strict guarantee: per recipient and proposal, at most `quota` slots from any
one sender are ever served, and the served total is at most 4,096, the native
clients' limit.

### Error kinds

Every inbox refusal is a guest error that starts with a stable code followed by
": " (`InboxFailure::code`, `InboxFailure::find`). The Stage 2B wording follows
the code unchanged, so callers that match on the old text still match.

| Code | Condition | Delivery outcome |
|---|---|---|
| `inbox_conflict` | different payload already stored for the slot | not stored |
| `inbox_sender_quota` | caller has used its share | not stored |
| `inbox_capacity` | 16,384 records in the inbox | not stored |
| `inbox_unauthorized` | caller ≠ envelope sender, sender or recipient not a member, wrong recipient, local agent not a member, session not fully accepted, capability rejected, call signature not authenticated | not stored |
| `inbox_invalid_argument` | malformed envelope (digest, round, sequence, version), other session or protocol, plaintext FROST round 2, send to self | not stored |
| `inbox_missing` | proposal not available here | not stored |
| `inbox_write_conflict` | recipient's commit lost a chain-head race (HeadMoved) | not stored |
| `inbox_stored_record_invalid` | a stored record no longer validates (read only) | — |
| `inbox_transport` | storage error; network failure; undecodable receipt; countersigning | **outcome unknown** for a delivery |

`send_protocol_message` recovers the recipient's code from the `NetworkError`
text and says "rejected by the recipient, not stored". It reports HeadMoved as
`inbox_write_conflict`. Anything else stays `inbox_transport … outcome unknown`.
No text advises a retry or a resend. The coordinator still never prints the
`Unauthorized` Debug output, which carries the capability secret.

Missing messages are not an error. A slot that has not arrived, or is
withheld, is simply absent from `get_inbox`, as before.

## Changed files

| File | Change |
|---|---|
| `dnas/mpc/zomes/coordinator/mpc/src/lib.rs` | `InboxFailure` kinds; `inbox_session`; `sender_quota`; `StoredVariant`, `WithheldSlot`, `InboxSlots`, `partition_inbox`; `receive_protocol_message` (inline `validate_received` against `call_info().provenance`, quota and conflict checks, kinded errors); `send_protocol_message` (kinded errors, `remote_failure_message`); `get_inbox` via `inbox_slots`; new `get_inbox_slots`; 7 unit tests. Relaxed ordering kept |
| `dnas/mpc/zomes/coordinator/mpc/tests/inbox_hardening.rs` | new, 7 Sweettests |
| `package.json` | `test:coordinator-unit` (in `test:native`), `test:inbox-hardening`, inbox Sweettest added to `test:sweettest` |
| `docs/V040_STAGE2C_COORDINATOR_HARDENING.md` | this report |

Not changed: the integrity zome, `dna.yaml`, `happ.yaml`, DNA properties, the
adapter, `mpc-core`, every `crates/` and `scripts/` file, every `Cargo.toml`,
`Cargo.lock`, `scripts/release_hashes.json`, `scripts/release_inventory.json`,
custody, vault and signing code. `mpc.dna` and the `.happ` are rebuilt
artifacts (see "DNA and bundle identity").

## Unit tests (deterministic)

`cargo test -p mpc --lib` (`npm run test:coordinator-unit`, now part of
`test:native`): `a_conflict_withholds_only_its_own_slot`,
`identical_copies_are_one_slot_and_keep_every_action`,
`the_share_is_counted_per_sender_in_chain_order`,
`a_variant_beyond_the_share_still_marks_a_conflict`,
`shares_never_exceed_what_clients_accept` (every size 2–64),
`kind_codes_are_distinct_and_found_in_text`,
`remote_failures_keep_their_kind_and_never_advise_resending` (uses the exact
`NetworkError` shape seen in the Stage 2B run and a HeadMoved shape). The
HeadMoved shape over the network is inferred, not observed: the 17 October
coordinator replaced the text with its generic message, and Stage 2C never
raises HeadMoved for the inbox.

## Test evidence

Commands ran through `dkg-v040-stage2c/run_tests.sh <step>` (offline,
`TMPDIR=/tmp/v040s2c`, `Cargo.lock` checked after every step), each inside
`systemd-run --user --scope -p MemoryMax=12G…14G -p MemorySwapMax=0` with
`CARGO_BUILD_JOBS=4`, one step at a time. Logs: `dkg-v040-stage2c/logs/tests/`.
Summary: `logs/test-results.tsv`.

### Red, then green (same test file)

| Test | Stage 2B coordinator | 17 Oct coordinator | Stage 2C coordinator |
|---|---|---|---|
| `r11_conflicting_pair_leaves_unrelated_slots_readable` | **FAIL**: whole inbox `Equivocation` | not run | **PASS**: 2 unrelated envelopes served; conflict reported with both variants |
| `r11_one_sender_cannot_exhaust_another_senders_allocation` | **FAIL**: Alice 4,097 stored, inbox 4,098 > client limit | not run | **PASS**: Alice refused at 2,048 (`inbox_sender_quota`), Carol stored and fills her own 2,048, inbox exactly 4,096 |
| `r11_concurrent_deliveries_cannot_overrun_the_served_quota` | **FAIL**: 64/64 stored, no refusal | not run | **PASS**: 64 concurrent with 8 places left: 12 stored / 52 refused (run 1), 11 / 53 (run 2). Write overshoot 4 and 3. Served: exactly 2,048. Overshoot listed in `over_quota` |
| `membership_and_context_binding_survive_hardening` | **FAIL** on missing kind (refusals themselves correct) | not run | **PASS** |
| `send_protocol_message_keeps_the_remote_failure_kind` | **FAIL**: conflict seen as "network" | not run | **PASS**: `inbox_conflict: … rejected by the recipient, not stored: …` |
| `r10_concurrent_honest_fan_in_is_stored` | PASS 32/32 | **FAIL** 30/32 HeadMoved | **PASS** 32/32 |
| `r10_network_fan_in_is_stored` | PASS 16/16 | **FAIL** 15/16, kind hidden, retry advice | **PASS** 16/16 |

The first Stage 2C run (`test-inbox-hardening-run1.log`) passed 6/7. The
conflict test failed on its own assumption that receipt action hashes are
stored hashes (finding R10-a above). The behavioural assertions before it had
passed. The test was corrected to take storage actions from `get_inbox_slots`
and passed (`test-inbox-hardening-conflict.log`), and the whole file passed
7/7 again inside `npm run test:sweettest`.

### Integrated suites (Stage 2C tree)

| Command | Result |
|---|---|
| `cargo test -p mpc --lib` (`test:coordinator-unit`) | PASS 7/7 |
| `npm run test:sweettest` | PASS 11/11 in 5 groups (2,097 s): `mpc_network` 1, `dkg_live` 1, `inbox_hardening` 7, `three_processes` 1, `conductor_bridge` 1 |
| `npm run test:native` | PASS 153/153 in 23 groups (Stage 2B: 146; +7 coordinator unit tests). Includes `test:input-validation`, `test:signing-session`, `test:share-custody`, `test:security`, `test:cli-notices` |
| `test:phase5c-b-sweettest` (`capability_provisioning`, matches the old `Remote delivery not acknowledged: unauthorized (capability rejected)` text) | PASS 1/1 |
| `revoke_cap_grant` Sweettest | PASS 1/1 |
| `npm run test:conductor-client` | PASS 6/6 |
| `npm run test:signing-signer` | PASS 2/2 |
| `npm run test:transport-probe` (calls `mpc::receive_protocol_message` natively) | PASS 22/22 |
| `npm run check:holochain-versions` | PASS |
| `npm run check:wasm-imports` | PASS: `mpc.wasm` 48, `mpc_integrity.wasm` 11 Holochain 0.7.1 host functions only |
| `npm run build:happ`, twice | PASS, byte-identical |
| `npm run check:release` | **FAIL (identity) — expected release-approval dependency, not a build or implementation failure.** 10 of 11 steps PASS (validator-tests 19, manifest, versions, wasm-build fresh target, wasm-imports, pack, help-notices 13 binaries, native 153, lockfile). `identity` differs only in coordinator WASM, `.dna` and `.happ`; the frozen integrity WASM and DNA hash match. `logs/tests/check-release.log`, `logs/release-check-logs/` |

Not run: `cargo audit`, clippy (not configured), the fault suite
(`scripts/phase6_faults.py`, it exercises worker processes, which this patch
does not change), `phase6_rehearsal.py`, anything on a persistent sandbox.

## DNA and bundle identity

| Artifact | Stage 2B | Stage 2C (tree build = fresh-target build in `check:release`) | |
|---|---|---|---|
| Integrity WASM | `2d6aa141…4ffdb` | `2d6aa14170e4e1d40a78fc270d89a7534e943813b18811a66a84c88c6bb4ffdb` | **identical** |
| DNA hash | `uhC0kp2j…P6Mwu` | `uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu` | **identical** |
| Coordinator WASM | `432d4d7d…19614` | `e9b46c84542112bd2a860992dfeb4b7d758dc430150d540db57b86d2bb2e8965` | changed (intended) |
| `mpc.dna` | `7f77af71…7f7452` | `e0e80b54dd9ce9336184caeb94eb6883cd595d26d2b8551ca952506a49d1f622` | changed (contains the coordinator) |
| `.happ` | `38efb4a9…bac1e5` | `41935b26b752c443b4bd2e88606733684d84e3afdddf9b23ffa25466bd76d71b` | changed (contains the `.dna`) |

Toolchain: rustc 1.99.0 (b940084d7 2026-09-28), cargo 1.99.0, `hc` 0.7.0,
hdk =0.7.1, hdi =0.8.1, unchanged from Stage 2B.

DNA identity is the hash of the integrity zomes and DNA properties; bundle
identity is the hash of the packed files, which include the coordinator. Only
the first is frozen (L2). The 17 October coordinator built for the R10
characterization is a second witness: different coordinator and `.dna` bytes,
the same DNA hash (`evidence/c52292a-coordinator-identity.txt`).

The coordinator WASM contains the change (`evidence/coordinator-wasm-change.txt`):
the only added export is `get_inbox_slots`, none removed, and the new kind
strings are present.

### Proposed artifact-hash update (operator review; not applied)

`scripts/release_hashes.json` was **not** modified. After the independent
review, the operator either runs
`python3 -I scripts/release_check.py --record --confirm-record` on the merged
tree or checks that it produces exactly this change
(`evidence/PROPOSED-release_hashes.json`, `.diff`):

```diff
-  "coordinator_wasm_sha256": "432d4d7d2e0244cad46c1c747f4fd2bdb2f9b15cf510218dd4a4b6ef8ee19614",
-  "dna_sha256": "7f77af71ba633536139f77702de1d8e74b77b8f437f33bf9328ec3856d7f7452",
-  "happ_sha256": "38efb4a9bcc3accd2eff2da0fbf451c8f1d981b366819d00c1eac52655bac1e5",
+  "coordinator_wasm_sha256": "e9b46c84542112bd2a860992dfeb4b7d758dc430150d540db57b86d2bb2e8965",
+  "dna_sha256": "e0e80b54dd9ce9336184caeb94eb6883cd595d26d2b8551ca952506a49d1f622",
+  "happ_sha256": "41935b26b752c443b4bd2e88606733684d84e3afdddf9b23ffa25466bd76d71b",
```

`integrity_wasm_sha256`, `dna_hash`, `rustc`, `cargo` and `hc` stay as they
are. `scripts/release_inventory.json` needs no change: no manifest, lockfile
or binary changed.

## API and data compatibility

| Item | Change | Effect on existing consumers |
|---|---|---|
| `get_inbox(ActionHash) -> Vec<Envelope>` | same name, input, output and order (sender, round, sequence) | Decoding is unchanged. A proposal that used to fail with "Equivocation" now returns its unconflicted slots. A sender past its share is served only its share |
| `receive_protocol_message`, `send_protocol_message` | same input and `DeliveryReceipt` output | Error text gains a `<code>: ` prefix; the old wording follows it. `capability_provisioning.rs:138` still matches |
| `get_inbox_slots(ActionHash) -> InboxSlots` | new extern | Not callable through the production signed path yet: the signer policies (`lair_signer.rs`, `signing_signer.rs`, `probe_signer.rs`, `signed_call_policy.rs`) list functions by name and will refuse it |
| Stored `InboxEvent` entries | not changed, not migrated | The integrity zome and entry format are untouched. Records written by the 17 October or Stage 2B coordinator are read by the same rules |
| Capability grants | not changed | `prepare_inbox_grant` still lists only `receive_protocol_message`. `get_inbox_slots` is callable only by the cell's own author |
| New public Rust items | `InboxFailure`, `StoredVariant`, `WithheldSlot`, `InboxSlots`, `partition_inbox`, `sender_quota`, `remote_failure_message`, `MAX_SERVED_INBOX`, `MAX_INBOX_PER_SENDER` | Additive |

### Coordinated client changes (not made; outside this brief's scope)

1. **Conflict detection in the consumers (recommended).** Add `get_inbox_slots`
   to the signer allow-lists and the conductor client. Then `run_signing` and
   the DKG relay abort as soon as `conflicts` or `over_quota` names a slot their
   operation reads: (sender ∈ selected, round 4 or 6, sequence = the plan's) for
   signing; any round 1–3 slot for DKG. That turns "fails at its deadline" into
   "fails now, with the misbehaving sender named".
2. **Late conflicts.** With the old `get_inbox`, a conflict that arrived after a
   consumer had already read variant A made the next poll fail. Now slot A
   simply disappears from later responses. The DKG relay and `run_signing` keep
   what they already accepted and do not notice. Only (1) restores that
   signal. The recipient still acted on one authenticated message only, and
   cross-recipient consistency is still checked by echo broadcast (DKG) and
   FROST aggregation (signing).
3. **`run_signing` silent dedup.** Independently of this patch, `run_signing`
   skips a later envelope for an already-seen slot without comparing it. Under
   Stage 2C the coordinator never serves two variants, so this is not
   reachable. It should still compare, as the DKG relay does.

Rollout: (1) needs a coordinator that exports `get_inbox_slots`, so the
coordinator goes first. Old clients keep working against the new coordinator.
New clients must not be pointed at an old coordinator, where the extern is
missing and the call fails.

## What the fix prevents, and what it does not

Prevents (under the threat model "one group member is malicious or races, the
recipient's coordinator and conductor are honest"):

- One conflicting pair making the recipient's whole inbox unreadable.
- Any variant of a conflicting slot being served as authoritative.
- One sender exhausting the inbox for the others, or pushing the response past
  the native clients' 4,096 limit, by sequential or concurrent delivery.
- A sender claiming another member's share: the share is keyed by
  `call_info().provenance`, and a forged `envelope.sender` is refused first.
- Envelopes of another proposal, session, protocol or recipient being filed or
  served under this proposal.
- Delivery errors losing their kind, and HeadMoved hiding as a network error.

Does not prevent:

- **A silent participant.** DKG needs all three members (L1, unanimous
  ceremony). A member that never sends, or that equivocates in its own slot,
  still stops that DKG, and still stops any signing operation it was selected
  for. A conflicting slot behaves exactly like a missing message.
- **No finality.** Holochain gives no global transaction finality for this
  protocol. Each recipient's inbox is its own source chain; two recipients can
  hold different payloads from the same sender. Echo broadcast and FROST
  verification detect that; the coordinator does not.
- **Write-side overshoot.** Concurrent deliveries can store more than the share
  (measured: see "Test evidence"). The extra records cost the recipient storage
  but are never served. The total stored is still capped by the 16,384 global
  check, which is itself read-before-write.
- **Lifetime exhaustion.** Inbox records are never deleted. With a 2,048 share
  and two messages per sender per signing operation (rounds 4 and 6, one
  sequence per operation), one group can run about 1,020 signing operations
  (2,048 − 3 DKG messages, divided by 2) before an honest signer reaches its
  share and its deliveries are refused. That is the same ceiling the clients'
  4,096 response limit already imposed (4,096 / 2 senders / 2). The fix makes it
  explicit and per sender; it does not lift it. A long-lived group needs a new
  proposal (re-key) before then, or a coordinator design that lets old slots be
  dropped.
- **Cross-proposal storage.** The share is per proposal. A member can store up
  to its share in every proposal the recipient has accepted. Acceptance is the
  recipient's own decision.
- **Duplicate specs.** Two proposals with an identical `SessionSpec` share a
  `session_id`, so an envelope valid for one validates for the other. It can be
  filed under either only if the recipient accepted both.
- **Read cost.** `get_inbox` still scans every `InboxEvent` on the chain, and
  variants in one slot are compared pairwise. Both are bounded by the
  per-sender record count, but a large concurrent burst into one slot makes
  each read slower.
- **A stored record that stops validating** (for example after a future
  `mpc-core` rule change) fails the whole read with
  `inbox_stored_record_invalid`. That cannot be triggered by a member through
  this coordinator, but it is a coordinator-upgrade compatibility check.
- **Grant revocation race.** As before, a delivery authorised just before a
  concurrent grant revocation may be committed after it.

## Operator decisions

1. **Quota value (protocol decision).** Proposed default:
   `clamp(4096 / (members − 1), 1, 4096)` per authenticated sender, per
   recipient, per proposal, for the proposal's lifetime. That gives 2,048 for
   three members. It is below the brief's 4,096 ceiling on purpose. 4,096 per
   sender would let one sender push a three-member recipient's response to
   4,097+ envelopes, which `conductor_client.rs` and the DKG relay refuse
   entirely, so R11 would stay open at the client. Alternatives: raise the
   clients' 4,096 limit together with the share (client change), or keep the
   share and accept the about 1,020-operation lifetime per group (unchanged
   from today's effective limit).
2. **Rejection policy.** Proposed: a delivery past the share is **refused**
   with `inbox_sender_quota` and nothing is stored. Deliveries that overshoot
   by racing are stored but not served, and are reported in `over_quota`. The
   alternative, accepting and silently ignoring, was rejected: the sender
   would get a `Stored` receipt for a message no one will read.
3. **Withhold versus fail for conflicts.** Proposed: withhold the slot and keep
   evidence (implemented). Failing only the consumer immediately needs client
   change 1 above.
4. **Client rollout.** Whether and when to adopt `get_inbox_slots` in the
   signer allow-lists, the conductor client, `run_signing` and the DKG relay.
5. **R10-a.** Whether `DeliveryReceipt.storage_action` should be documented as
   advisory only, or changed in a later coordinator to report the slot rather
   than the pre-commit action hash.
6. **Deployment.** Whether to run `update_coordinators` on the persistent 5C
   cells, and when (procedure below). Until then those cells keep the 17
   October behaviour (HeadMoved, N3 retry text, whole-inbox Equivocation).
7. **Release hashes.** Re-record after review (proposed values above).

## Independent review (required before the operator's tree)

This patch is **not** independently reviewed. The author's own tests are not
an audit. A separate agent (the Agent 7 brief,
`docs/agent-briefs/07-independent-reviewer.md`, extended to this patch) should
check at least:

- **Conflict handling.** `partition_inbox` never serves a slot with two
  variants; that nothing upstream can collapse variants; behaviour for a
  recipient-field-only difference (`None` versus `Some(local)`).
- **Quota and concurrency.** The served bound under any commit order;
  `first < quota` counted per sender in chain order; that `query` returns
  chain order; overshoot size under higher concurrency than the 64 tested;
  the 16,384 global check, also read-before-write.
- **Identity and authorization.** Inline `validate_received` against
  `call_info().provenance` equals `authenticate_incoming`; quota keyed on the
  caller, not on `envelope.sender`; the cap grant still lists only
  `receive_protocol_message`; `get_inbox_slots` is author-only.
- **Error propagation.** `InboxFailure::find` on adversarial remote text (a
  malicious recipient can claim "not stored"; it can lie in any case); no
  capability secret in any text; no retry advice; the "not stored" claims.
- **Data compatibility.** Reading records written by the 17 October and Stage
  2B coordinators; the `inbox_stored_record_invalid` fail-closed path.
- **Coordinator upgrade safety.** The procedure below, and rollback with
  conflicting records present.
- **Identity.** Rebuild from the patch on a fresh Stage 2B copy and compare the
  integrity WASM, the DNA hash and the coordinator hash in this report.

## Patch and how it applies

| Record | Path (under `dkg-v040-stage2c/`) |
|---|---|
| Patch (4 files, unified diff, `-p1`) | `stage2c-coordinator-hardening.patch` |
| SHA-256 of the changed files and the patch | `evidence/stage2c-changed-files.sha256` |
| SHA-256 of the full Stage 2C source tree (excluding `target/`, `__pycache__/`) | `evidence/stage2c-source-manifest.sha256` |
| Starting state | `evidence/stage2b-start-manifest.sha256` (= Stage 2B manifest), `logs/stage2c-start.log` |
| Reference and new identity | `evidence/reference-identity-stage2b.txt`, `evidence/c52292a-coordinator-identity.txt`, `evidence/coordinator-wasm-change.txt`, `evidence/PROPOSED-release_hashes.{json,diff}` |
| Test logs | `logs/tests/*.log`, `logs/test-results.tsv`, `logs/release-check-logs/` |
| Baseline artifacts | `baseline-repro/artifacts/` (Stage 2B WASM, `.dna`, `.happ`); `baseline-repro/coordinator-c52292a-lib.rs` |
| Runner and patch tool | `run_tests.sh` (Stage 2B runner plus Stage 2C steps), `make_patch.sh` |
| Pristine Stage 2B source | `stage2b-pristine/` (read-only) |

Apply it to a fresh copy of the Stage 2B tree (after the Stage 2A and 2B patches):

```bash
R=/mnt/holochain/offloaded/sf/Downloads/holochain-mpc-core-v0.3.3-dkg-source
mkdir new && rsync -a --exclude=/target --exclude=__pycache__ $R/dkg-v040-stage2b/holochain-mpc-core/ new/
cd new
sha256sum -c --quiet $R/dkg-v040-stage2b/evidence/stage2b-source-manifest.sha256   # Stage 2B state, 197 files
grep stage2c-coordinator-hardening.patch $R/dkg-v040-stage2c/evidence/stage2c-changed-files.sha256 \
  | sed "s|  |  $R/dkg-v040-stage2c/|" | sha256sum -c
patch -p1 --dry-run --batch < $R/dkg-v040-stage2c/stage2c-coordinator-hardening.patch \
  && patch -p1 --batch < $R/dkg-v040-stage2c/stage2c-coordinator-hardening.patch
find . -name '*.orig' -o -name '*.rej'                     # must print nothing
npm run build:happ                                          # regenerates mpc.dna and the .happ
sha256sum -c --quiet $R/dkg-v040-stage2c/evidence/stage2c-source-manifest.sha256
hc dna hash dnas/mpc/workdir/mpc.dna                        # uhC0kp2j…P6Mwu
```

The rebuilt `mpc.dna` and `.happ` are not in the text patch. `npm run build:happ`
reproduces them byte for byte (twice-built check above), and the manifest
includes them. On the operator's git tree the patch applies with `git apply -p1`
after the Stage 2A and 2B patches. Commits and checkpoint refs remain
operator-only.

## Handover edits (proposed; the Claude Docs handover was not edited)

- R11 / review R6: move from Open to "fixed in Stage 2C patch, pending
  independent review, operator merge, release-hash re-record and
  `update_coordinators`". State the target met: conflicts localized; served
  share strict per sender; write share soft (measured overshoot 3–4 with 64
  concurrent).
- R10: the offline half is characterized (HeadMoved 30/32 and 15/16 on the 17
  October coordinator) and fixed in code since 22 October. Error kinds are now
  kept (Stage 2C). The persistent half (5C cells) waits for
  `update_coordinators`.
- New R10-a: receipt `storage_action` under relaxed ordering may not be on
  the chain.
- N3 / T15: Stage 2C coordinator text never advises a retry. The 17 October
  text on the persistent cells still does.
- A1-1 (Agent 1 doc claimed a fix): superseded by this report. The draft
  `V040_COORDINATOR_INBOX_HARDENING.md` was never in the integrated tree and is
  not evidence.

## Future operator procedure: `update_coordinators` on the persistent 5C cells

**Documented only. Nothing in this section was run.** Running it is an
operator action (common rule 1) and needs its own approval. It must not start
until the Agent 7 review of this patch has finished and the operator has merged
it.

### What changes on the cells

The persistent `mpc-phase5c` cells run the 17 October coordinator (`c52292a`).
That coordinator writes `InboxEvent` with strict ordering (R10, HeadMoved under
fan-in), tells callers to "retry with the same round/sequence" (N3), and fails
the whole inbox on a conflicting pair. The upgrade replaces only the
coordinator zome `mpc`. The integrity zome, the DNA hash and every entry
already on the cells stay as they are. The deployment report records the
installed DNA hash as `uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu`,
the same hash this build keeps.

The jump is from 17 October to Stage 2C. It includes the 22 October
relaxed-ordering and error-text change as well as this patch.

### Prerequisites

1. The Stage 2C patch has passed the independent review and is merged into the
   operator tree. `npm run check:release` passes there after the operator
   re-records `scripts/release_hashes.json` with
   `python3 -I scripts/release_check.py --record --confirm-record` (see
   "Proposed artifact-hash update").
2. The operator has made the operator decisions in this report (quota and
   policy, R12, client rollout).
3. No DKG relay, `mpc-sign`, vault or probe process is running against either
   cell. No DKG or signing operation is in flight. The coordinator does not
   change chains, but an in-flight run would see the extern change under it.
4. The installed DNA hash on each conductor equals
   `uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu`
   (`hc client call --port <admin> list-apps`). If it does not, stop: the
   coordinator was built against this integrity zome only.
5. The conductor version is the 0.7.1 line used to build and test this patch.

### Backups (before any change)

1. Stop both conductors cleanly. Copy each conductor's data directory (the
   sandbox directory under `~/mpc-phase5c-sandbox`) to dated offline storage,
   including its databases and conductor configuration. A copy taken while the
   conductor runs may be inconsistent.
2. Copy the Lair keystore directory as opaque files. Do not unlock it, read
   passphrases or export keys.
3. Keep the 17 October coordinator artifacts
   (`~/mpc-source-backups/deployed-5c-artifacts-2026-10-17/`). Record the
   SHA-256 of the deployed `mpc.wasm`, `mpc.dna` and `.happ` from that
   directory. They are needed for rollback and are not in this report.
4. Record each cell's chain head (`dump_state` or the admin API) and the
   output of `get_inbox` for every live proposal, as the comparison base.
5. Restart the conductors and confirm they serve the same app state before
   continuing.

### Reference hashes

| Artifact | Before (Stage 2B, release_hashes.json) | After (Stage 2C build, this report) |
|---|---|---|
| Integrity WASM | `2d6aa141…4ffdb` | identical (must be) |
| DNA hash | `uhC0kp2j…P6Mwu` | identical (must be) |
| Coordinator WASM | `432d4d7d…19614` | `e9b46c84542112bd2a860992dfeb4b7d758dc430150d540db57b86d2bb2e8965` |
| `.dna` bundle | `7f77af71…7f7452` | `e0e80b54dd9ce9336184caeb94eb6883cd595d26d2b8551ca952506a49d1f622` |
| `.happ` bundle | `38efb4a9…bac1e5` | `41935b26b752c443b4bd2e88606733684d84e3afdddf9b23ffa25466bd76d71b` |
| Deployed 17 Oct coordinator | operator records from the backup directory | — |

Only the coordinator WASM goes to `update_coordinators`. Rebuild it on the
operator tree and compare its SHA-256 with `e9b46c84542112bd2a860992dfeb4b7d758dc430150d540db57b86d2bb2e8965` before use.

### Upgrade steps (operator)

1. Build from the merged tree: `npm run build:happ`. Check that
   `target/wasm32-unknown-unknown/release/mpc_integrity.wasm` has SHA-256
   `2d6aa141…4ffdb`, that `hc dna hash dnas/mpc/workdir/mpc.dna` prints
   `uhC0kp2j…P6Mwu`, and that `mpc.wasm` equals the reviewed hash.
2. Run `npm run check:wasm-imports` and `npm run check:holochain-versions`.
3. For each conductor in turn, through its admin interface, call
   `update_coordinators` for the cell
   `(uhC0kp2j…P6Mwu, <that conductor's agent key>)` with the source set to the
   reviewed `mpc.dna` bundle (or the coordinator zome alone, as the admin API
   allows). Upgrade one conductor and verify it before the second.
4. Do not restart relays or signers until both conductors have been verified.

### Verification of upgraded cells (read-only first)

1. `list-apps`: the app is enabled, the DNA hash is unchanged and the agent key
   is unchanged.
2. Compare the chain head with the one recorded before the upgrade. The
   upgrade is not expected to add an action; that was not verified here. If
   one appears, record it and stop until it is understood.
3. `get_inbox` returns, for each live proposal, the same envelopes as before.
   One exception is expected: a proposal whose old `get_inbox` failed with
   "Equivocation" now returns its unconflicted slots. A proposal holding more
   than its share from one sender now serves at most the share.
4. `get_inbox_slots` lists any conflicting or over-share slot. Report each one
   to the operator. It is evidence of a misbehaving or racing member. Do not
   delete or "repair" it.
5. Error kinds: on a disposable proposal, never one carrying real keys, a
   repeated delivery with a different payload must fail with
   `inbox_conflict:` and an unauthorized capability with
   `inbox_unauthorized: … not stored`. Run this only if the operator approves
   a test write on the persistent cells. Otherwise rely on the Sweettests.
6. Signed-call path: the existing signers sign `get_inbox` and
   `send_protocol_message` unchanged. Confirm one signed `get_inbox` through
   the normal relay or probe path before resuming operations.

### Rollback

- `update_coordinators` with the backed-up 17 October coordinator restores the
  old behaviour. It does not remove entries written in between. Records that
  the new coordinator would withhold (a conflicting pair, an over-share
  overshoot) make the old `get_inbox` fail for that proposal again.
- A full restore from the data-directory backup discards everything written
  after the backup, including inbox deliveries and grants. Use it only if the
  upgraded coordinator corrupted state, and only with both conductors stopped.
- Rolling back while a peer runs the new coordinator is safe at the protocol
  level. The extern signatures of the existing functions are unchanged, and
  the old sender just sees the new kind prefix in error text.
- Never roll back by modifying the integrity zome or the DNA properties.
