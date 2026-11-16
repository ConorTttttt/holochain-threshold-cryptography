# ADR proposal — Operation namespace versus legacy v1 sequence collisions

**Status:** PROPOSED / human approval required before a wire, integrity schema, coordinator or SDK contract change. **Agent:** 23, Sprint 1.7. **Baseline:** 899e433d057a4d1a0533e2304a2493edb75ad82f.

## Problem

A 64-bit signing envelope sequence cannot faithfully encode a 256-bit operation ID. The existing first-eight-byte scheme collides, and the modulo causes two further head-value aliases. Two valid, separately approved signing plans may map to one Holochain coordinator slot (proposal, recipient cell, sender, round, sequence). The coordinator cannot reconstruct a secure operation namespace from generic opaque v1 envelopes, and its source chain contains persistent legacy InboxEvent entries. Native FROST checks reject full-operation-ID mismatches but do not restore lost slot availability. Per-sender quotas also bound group lifespan.

## Alternatives

**A — v1 deterministic fail-closed collision rejection and finite rekey (recommended for the current development milestone).** Keep v1 wire/DNA and sequence encoding unchanged; never reinterpret a stored slot; abort on a selected collision/over-quota, preserve nonce burn and exact-approval checks; require a fresh approved operation ID after a terminal failure. Document the finite quota and lack of proactive expiry as OPEN until a separately reviewed durable gate exists. No claim of collision-free IDs or guaranteed lifetime. Compatibility: no wire/DNA migration, no historical write semantics changed; native/SDK error taxonomy and lifecycle status extension still need separate owner approval. Race-free preflight would need a durable operation-to-slot registry or other authoritative source, not just a read-before-write check.

**B — versioned operation namespace / child signing session per operation (preferred future capability).** A new v2 envelope/inbox identity includes full 32-byte operation ID, exact proposal, application/context and pinned DNA/cell identity; alternatively a fresh child session is anchored to an already activated parent group. Specify sender/recipient/round/operation/sequence slot key and how a child operation proves parent activation and selected approvals without redoing DKG. Preserve separate nonce ledger keying by full operation ID. Migration must explicitly version coordinator externs, integrity types and SDK, likely change the DNA hash, refuse implicit fallback to v1, and define behaviour of old InboxEvent rows and deployed cells. May also address S1-M02 exact-proposal/cross-application replay. A child session does not remove source-chain growth or capacity unless indexing/retirement changes are separately designed.

**C — hash 256-bit operation ID to 64 bits, or allocate a pseudo-random u64 (rejected as a full fix).** A hash reduces a simple chosen-prefix collision but cannot eliminate collisions. It also changes historical sequences while old messages persist, risks silent incompatibility and needs a durable collision registry anyway. No ordinary 64-bit hash guarantees uniqueness.

**D — increase MAX_MESSAGES or prune historical source-chain records (out of scope).** Increases DoS/storage exposure or requires an unreviewed integrity/DNA migration; does not resolve distinct 256-bit operation IDs aliasing the same slot.

## Required decision and migration gates

1. For Sprint 1.7 accept A as a **documented development-only response**, or authorize a separate versioned namespace project B. Until B is implemented and validated, do not claim an unbounded reusable multi-application SDK.
2. Before B: approve exact v2 identity tuple, proposal/cell/app bindings, source-chain schema version and DNA hash, v1/v2 coexistence policy, downgrade refusal, full operation-id replay ledger, cursor/capacity interface, and SDK public API owner signoff. Batch any integrity change with the explicitly approved compatibility migration; never silently change sequence encoding or registered release hashes.
3. Independent tests must demonstrate distinct same-prefix IDs at E3, native exact-intent/aggregation refusal, real-conductor same-slot conflict and over-quota behaviour at E5/E7, migration of old immutable rows, partial delivery and concurrent rebase, fresh-proposal renewal without reactivation of the expired group, process crash/rollback, and fail-closed SDK status when capacity cannot be proven.
4. Final security reviewer must assess the **exact combined integration commit**. A source test authored without execution is E1 only. E4/E5/E6/E7/E8 are not inherited from historic 8dec223 evidence. Production custody, cross-application v1 replay and an expiry gate remain independent open blockers.

**No production protocol change is made by this Agent 23 PR.**
