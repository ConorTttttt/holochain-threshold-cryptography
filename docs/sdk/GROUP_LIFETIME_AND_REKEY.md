# Sprint 1.7 — Finite Group Lifetime, Quota and Rekey Policy

**Owner:** Agent 23. **Baseline:** 899e433d057a4d1a0533e2304a2493edb75ad82f. **Finding:** S1-M03 OPEN. **Status:** capacity measured from current source; a proposed fail-closed lifecycle policy, NOT an enforced group-expiry implementation.

## Current accounting, not the historical estimate

The coordinator stores private inbound InboxEvent rows per recipient's source chain, filtered by exact proposal ActionHash. The read path scans the entire chain and partitions records. The core defines MAX_MESSAGES_PER_SESSION = 16,384 raw events. The current coordinator independently limits **served** envelopes to 4,096 per recipient and the per-sender share to:

    Q(n) = min(4096, floor(4096 / max(n-1, 1)))

where n is the proposal roster size. At 2, 3, 5 and 64 members this is respectively 4,096; 2,048; 1,024; and 65 records **per sender, recipient and proposal over its entire lifetime**. This is an entry/write budget, not a sliding window, and not a count of unique operations. Replays returned AlreadyStored do not consume a new row, but concurrently committed duplicate rows, rejected-over-quota rows and equivocation can permanently consume or poison capacity.

For a normal successful n-member DKG, each sender sends to each *other* recipient one Round-1 announce, up to n-1 origin echoes, one Round-2 attestation, and one sealed Round-3 share: **n + 2 inbound records per directed sender → recipient pair**. For n=3 this is 1 + 2 + 1 + 1 = **5**; total nominal DKG traffic per recipient is 10. A signing operation with selected roster S adds **two** records per ordered selected pair (round-4 commitment and round-6 share). A nonselected participant's inbox need not receive these signing frames. Activation and signing-approval attestations currently use DHT records, not this private inbox budget. Real counts vary if failures, retries, concurrent duplicates, malicious messages or future message types occur.

For a 3-member group and one fixed 2-of-3 signer pair: Q=2,048; baseline 5 DKG records per directed pair; ideal no-other-traffic upper bound floor((2,048 - 5) / 2) = **1,021 signing operations**, assuming each succeeded and no extra inbox rows. This is an *upper estimate*, not a guaranteed service-life promise. A selected all-3 signer roster spends two entries on every directed edge; changing rosters changes which edge is the bottleneck. A malicious party can spend quota intentionally; no minimum lifetime or availability is guaranteed.

The read partition applies the quota even if races accepted more writes. Slots stored after the sender quota are returned under over_quota, not served. A conflicting slot is returned under conflicts and never selected. The current native consumers reject relevant DKG or selected-signing withheld slots. They cannot promise a successful signing attempt once an edge's quota is exhausted; publication rejects explicit over-quota receives, but the SDK **does not currently expose remaining budget, proactive rekey, durable group retirement or a group-wide admission gate**. An activated group alone gives no proof of spare quota. Do not advertise unlimited reuse.

## Proposed v1 conservative expiration rule (decision needed)

Use the earliest of the following for starting **any new** signing operation: (a) an authenticated directed edge required by the selected signer roster has fewer than **2 + 128 = 130** safe remaining records, retaining 128 for conservative contingency, (b) any required sender/recipient ledger is unknown, inconsistent, conflicted or unavailable, (c) the proposal's independently persisted group status is Retiring/Expired, (d) an optional operator-approved maximum calendar age of **30 days** is reached. An age rule requires a trusted time policy and durable expiry proof; the present caller clock is not such a proof. Without trusted status/accounting, **fail closed**, never assume unlimited budget.

For an uncontested 3-member DKG and fixed selected pair, a 128-record reserve would stop new starts after floor((2048 - 5 - 128)/2) = **957** successful operations. This is a planning estimate only. To protect even the next candidate operation, check remaining capacity on *every* required directed selected edge, not an average group counter. Require each participating signer to check the same immutable proposal/epoch and its own trustworthy inbox-edge observations before approving/committing. Published approvals must not override a locally exhausted or expired status.

**Missing enforcement:** There is no authoritative quota snapshot/remaining-capacity API and no durable retirement record checked by run_signing / SigningSession::begin / SDK. The expiry rule therefore cannot be claimed as implemented; old attestation evidence still builds an ActivatedGroup. A test demonstrating the intended no-reactivation guarantee is deliberately left ignored/known-red. Implementing this gate requires integration-owner and SDK-owner agreement and a separate validated branch, including crash/restart, concurrent receive, stale-snapshot, DHT delay, and replay tests. No implicit change to wire format, Holochain DNA, SQLite schema, source-chain pruning or quota values is authorized here.

## Future SDK capacity and lifetime contract

A future **read-only** structured status (from an authenticated, pinned conductor and trusted native journal, with explicit observation provenance) should include: proposal ActionHash; application/cell/DNA binding; group descriptor digest and epoch; local observed Active/Retiring/Expired/Unknown; snapshot action/cursor and observed-at with staleness; quota and raw stored inbound count **per authenticated sender**; served unique slots; counts of conflicts, over_quota and concurrent duplicate records; remaining safe records per directed pair; the minimum remaining for a proposed signer roster; planned per-operation cost; reserve threshold; renewal-required reason and irreversible expiry marker; and whether each observation is authoritative, partial, or unavailable. Exact values are not currently exposed. Do not use a caller's claimed aggregate count or DHT attestation as a quota proof.

Never make a weak snapshot into a strong global finality claim: reads are local, source chains may be concurrently extended, and Holochain provides no cross-agent total order. As long as this status is read-only, it does not authorize signing. Before nonce reservation, each signer must enforce a durable local rule and recheck against concurrent use. Retries of ambiguous writes remain forbidden.

## Renewal procedure — fresh ceremony, no implicit reuse

1. Mark old group Retiring **durably** after reaching any admission threshold or explicit operator retirement; deny new signing operations at every selected signer. Allow no silently renewed approval, reused operation ID, or replay of a previously activated plan. In-flight operations must terminate safely or abort and burn nonce slots; whether to let already-published commitments finish needs a separately reviewed policy, not automatic retry.
2. Create a **new SessionProposal ActionHash**, new nonzero session ID/context and new ephemeral DKG/X25519 keys. Record an optional non-authoritative parent/group-replaces reference for operator UX; the *new proposal* itself is the security namespace. Do not resume an abandoned DKG using old ephemeral secrets.
3. Obtain fresh acceptance from **all n** listed members, unanimously verify a new DKG transcript, seal and verify Round 2, and require independent unanimous activation attestations for the new GroupDescriptor. Persist the new share/activation under the new immutable identity; do not mutate an old descriptor or reuse its activation votes.
4. Require new independently approved signing intents/operation IDs against that activated group. Keep the old group for historical signature verification only, never automatic signer reactivation. Backups, restores and device transfers must not revive an expired group's signing authority.

## Verification and unresolved work

The authored quota tests exercise the current **pure coordinator partition function**; they do NOT call real receive_protocol_message. The group renewal unit test checks new descriptor/attestation binding with fabricated values, not a second completed DKG. A real expiry guard, persistent monotonic accounting, status API, and multi-conductor rekey tests remain NOT IMPLEMENTED / NOT RUN.

On the exact integrated commit execute, archive and classify:

~~~sh
git rev-parse HEAD
cargo check --locked --workspace --all-targets
cargo test --locked -p mpc --lib inbox_tests -- --nocapture
cargo test --locked -p holochain-mpc-dkg-worker --test signing_session -- --nocapture
npm run build:happ
npm run test:sweettest
~~~

E1 authored source/doc; E2/E3/E4/E5/E6 NOT RUN; E7 fault scenarios authored but not run; E8 independent review NOT RUN. No persistent Holochain cell or real credentials may be used.
