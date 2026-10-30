# Agent 5: Vault app core (Safe-style threshold vault, devnet only)

Read `00-COMMON-RULES.md` first, then `docs/V040_PHASE8_SIGNING.md`.

## Goal

A local service that turns the existing 2-of-3 signing flow into a Safe-style
vault for ONE Ed25519 chain on its devnet or testnet. TARGET CHAIN: confirm with
the operator before starting; if none is given, build the chain adapter behind a
trait and implement a mock chain plus one devnet adapter (propose Solana devnet).

## Scope

You own a NEW crate `crates/mpc-vault` (add it to the workspace `Cargo.toml` only;
no other workspace edits) and `docs/V040_VAULT_APP.md`. Read-only: all existing
crates. Call existing binaries (`mpc-phase5c-provision make-intent` and
`approve-intent`, `mpc-sign`) as processes; do not copy their logic.

## Design

- Vault = one group descriptor and its group public key (the chain address).
- Proposal = a signing plan whose message is the serialized chain transaction.
  Limit: message at most 8 KiB.
- Local HTTP service on 127.0.0.1 with a bearer token, JSON API:
  `POST /vaults`, `GET /vaults/{id}`, `POST /proposals` (build tx, create plan),
  `GET /proposals`, `POST /proposals/{id}/approve` (drives the operator CLI
  approval for this node only), `POST /proposals/{id}/reject`,
  `GET /proposals/{id}` (status, confirmations x of 2, decoded transaction).
- Chain adapter trait: build unsigned tx bytes, decode them into a human-readable
  summary (recipient, amount, fee), attach a signature, broadcast, poll
  confirmation, query balance.
- Decoded summary is derived from the exact bytes that will be signed, never from
  user-supplied fields. A proposal whose bytes differ from its summary is refused.
- Proposal states: proposed, approved (n of 2), signed, broadcast, confirmed,
  rejected, expired, failed. Never retry a broadcast or a signing automatically
  (uncertain writes, R2).

## Tasks

1. Mock chain and tests for the whole state machine, including tampered bytes,
   duplicate approvals, approval by a non-selected node, expiry and replay.
2. Devnet adapter (if the operator confirmed a chain) and one end-to-end run on
   the disposable rehearsal: 2 of 3 disposable nodes sign a devnet transfer
   accepted by the chain. Network access may be required only for this step;
   say so in the report and use throwaway devnet funds only.
3. API contract file `crates/mpc-vault/openapi.yaml`, delivered FIRST (before
   task 1 is finished) so Agent 6 can build against it.

## Done when

Unit tests and the mock-chain suite pass, the API contract is committed to the
patch, and the end-to-end devnet run is either shown or listed as not done with
the reason. Document that policy enforcement (limits, allowlists) is not
implemented and that owner or threshold changes are impossible without a new DKG.
