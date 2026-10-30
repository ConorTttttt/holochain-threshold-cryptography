# v0.4.0 Vault app core — a Safe-style threshold vault (devnet only)

27 October 2026 (Europe/London). Implemented by the coding assistant (agent 5
brief) in a separate copy of the tree; the operator merges.

**Development evidence on a single host, not production custody and not an
independent audit. Devnet only.** No persistent 5B/5C state was touched and no
real key or passphrase was used.

## Result

`crates/mpc-vault` is a local service that wraps the existing 2-of-3 signing
flow (Phase 8) as a vault for one Ed25519 chain:

- 43 automated tests pass: 19 unit tests (`--lib`), 20 state-machine tests
  against the mock chain, and 4 HTTP tests (see Tests).
- `crates/mpc-vault/openapi.yaml` is the API contract. A test fails if the
  router and the contract list different operations.
- **The devnet end-to-end did NOT succeed, by design of the existing signing
  profile, not by a defect found in the vault.** Two disposable 2-of-3 nodes
  signed through the vault API and the signature is a valid Ed25519
  signature, but over a domain-separated wrapper of the transaction, not over
  the transaction bytes. No chain can verify that. The vault detected it,
  kept nothing and broadcast nothing. See "End-to-end run" for the evidence
  and the decision this needs.

## What it is

One service process serves **one node**. A vault is that node's completed
group: the group public key is the chain address (base58 on Solana). A
proposal is a signing plan whose message is the serialized chain transaction.

```
 browser / UI ──HTTP 127.0.0.1, bearer token──▶ mpc-vault (this node)
                                                  │ engine: state machine, store
                          ┌───────────────────────┼─────────────────────────┐
                          ▼                       ▼                         ▼
                    chain adapter           node driver (processes)     JSON store 0700
              mock | Solana devnet RPC   mpc-phase5c-provision make-intent
                                         mpc-phase5c-provision approve-intent
                                         mpc-phase5c-provision signing-status
                                         mpc-phase5c-provision write-signing-policy
                                         mpc-lair-signer --signing-profile
                                         mpc-sign
```

The vault contains no protocol or signing logic. It calls the existing
binaries and reads their results. It never holds a share, a Lair key or a
passphrase.

### Flow across two operators

1. Operator A: `POST /proposals` builds the unsigned transaction, runs
   `make-intent` with those bytes as the message, stores the proposal.
2. A hands `GET /proposals/{id}/plan` to operator C, whose own service does
   `POST /proposals/import`. C's service decodes the plan's bytes with its own
   chain adapter, so C sees a summary derived by C's own code.
3. Each operator reads the decoded transaction and calls
   `POST /proposals/{id}/approve` with `confirm: true` and the
   `message_sha256` they were shown. The service re-decodes the stored bytes,
   then runs `approve-intent` with this node's own copy of the message
   (the tool refuses any plan whose message differs).
4. After its own approval, each service starts the node's signing signer and
   `mpc-sign`. They wait for the other signer, exchange commitments and
   shares over Holochain and both aggregate. The service then checks that the
   group signed exactly the transaction bytes and that the signature verifies
   under the vault key, before it keeps it. **With today's signing profile
   the first check fails** (see "End-to-end run").
5. The proposing node broadcasts once (auto-broadcast, configurable). A
   background poller reads the chain by signature until the transaction is
   `confirmed`. The other node observes the same signature on chain.

## Safety rules, and where each is enforced

| Rule | Enforcement | Test |
|---|---|---|
| The summary is derived from the exact bytes to be signed, never from user fields | `Chain::decode` is the only source of a summary; no API field carries one. Creation, import, approve and broadcast all re-decode | `tampered_bytes_are_refused_everywhere`, `imports_decode_the_bytes_themselves` |
| A proposal whose bytes differ from its summary is refused | `integrity` is recomputed on every read; `mismatch` refuses approve and broadcast with 409 `bytes_summary_mismatch` | same |
| Only recognised transactions are signed | Solana: `[AdvanceNonce]? , Transfer , [Memo]?`, vault as fee payer and sole signer, no unused accounts, no trailing bytes, no versioned messages. Everything else fails closed | `refuses_everything_it_does_not_fully_understand` |
| Message at most 8 KiB | `message_too_large` (413) at build and import; the plan tool enforces it again | `imports_decode_the_bytes_themselves` |
| The approver saw these bytes | `approve` needs `confirm: true` and the exact `message_sha256` | `confirmation_must_name_the_reviewed_bytes` |
| Only selected signers approve | 403 `not_selected` before any tool runs; the tool refuses too | `non_selected_node_cannot_approve` |
| One approval per node | 409 `already_approved` / `busy`; the tool refuses a duplicate write | `duplicate_approvals_are_refused` |
| Never retry a signing (R2) | `sign` runs once; any failure is terminal (`failed`, step `sign`) and says "do not retry". `write-signing-policy` also refuses to overwrite | `signing_failure_is_terminal_and_never_retried` |
| Never retry a broadcast (R2) | The attempt is journalled before the network call. A second call is 409 `broadcast_attempted` whatever the first outcome | `rejected_broadcast_and_chain_failure_are_terminal`, `replay_is_refused` |
| An uncertain broadcast is resolved without resending | State `broadcast` with `uncertain: true`; a poller reads the chain by signature. After a crash the journal says "attempted", never "not sent" | `uncertain_broadcast_is_polled_never_resent`, `restart_during_broadcast_polls_and_never_resends` |
| Replay | Operation ids are single-use; identical bytes are refused while the earlier proposal is open or done; the chain rejects a repeated signature | `replay_is_refused` |
| A signature that does not verify is never kept or sent | The signed bytes must equal the transaction bytes, and `attach_signature` verifies (strict) before the proposal becomes `signed` | `a_signature_over_a_wrapper_is_never_kept_or_broadcast`, mock and Solana unit tests; live: run below |
| Expiry | Open proposals expire at `expires_at` (default 24 h, 60 s to 7 d). Once this node started signing, the proposal is not expired | `expiry_applies_only_before_signing_starts` |
| Restart | In-flight work found at start is settled: signing becomes `failed`, an approval is marked unknown (press Refresh), a broadcast is polled | `restart_*` tests |

## States

`proposed` (no approval seen) → `approved` (n of 2, see `confirmations`) →
`signed` → `broadcast` → `confirmed`. Terminal: `rejected`, `expired`,
`failed`. `signed` may go straight to `confirmed` when another node's
broadcast is observed. The transition table is a unit test
(`engine::tests::transitions`). `local_task` (`approving`, `signing`,
`broadcasting`) says what this node is doing; it is not a state.

Confirmations are known exactly for this node and for everyone once a
signature exists (the protocol signs only after every selected signer
approved). A remote approval is otherwise seen only after
`POST /proposals/{id}/refresh`, because reading it opens Lair (a passphrase
prompt in interactive mode).

## Solana devnet adapter

The group key is an ordinary Ed25519 key, so the FROST signature is a valid
transaction signature. Wire format: one signature (`0x01` + 64 bytes) followed
by the legacy message. The transaction id is the base58 signature.

A human approval can take longer than a recent blockhash lives (about a minute
or two). The adapter therefore supports a **durable nonce account whose
authority is the vault**: the transaction's first instruction advances the
nonce, so the transaction stays valid until that nonce changes. Without a
configured nonce account the adapter uses a recent blockhash and the summary
says so. `mpc-vault solana-setup --nonce` creates the account.

Limit: one nonce value, one transaction. Two open proposals built from the
same nonce value can not both land; the second fails at broadcast or on
chain. Create the next proposal after the previous one is final.

The RPC URL must contain `devnet` or be a local `http://127.0.0.1` validator.
Mainnet URLs are refused at start.

## Running it

```
mpc-vault gen-token /abs/token                 # 0600 file, 32 random bytes hex
mpc-vault serve --config /abs/vault.json       # one per node
mpc-vault demo  --listen 127.0.0.1:8787 --token-file /abs/token --data-dir /abs/demo [--ui-dir ui/vault]
mpc-vault solana-funder --funder-key-file /abs/funder.key
mpc-vault solana-setup  --config vault.json --funder-key-file /abs/funder.key --fund-lamports N --nonce
```

`vault.json` (unknown fields are refused): `listen` (loopback only),
`token_file`, `data_dir` (0700, keep the path short: the per-proposal signer
socket must fit in 107 bytes), optional `ui_dir`, `auto_broadcast`,
`default_expiry_secs`, `solana { rpc_url, nonce_account }` and `node { bin_dir,
agent_b64, record, state_dir, caps_dir, app_port, origin, app_token_file,
lair_root, installed_app_id, dna_hex_file, passphrase_file? }`.

**Passphrase.** Without `passphrase_file` the tools inherit the service's
terminal and Lair prompts there, so the operator types the passphrase on the
machine, never through the API. `passphrase_file` (0600) exists for a
disposable rehearsal only: the service then runs the tool on a private
pseudo-terminal and answers the prompt. Captured output is redacted.

**Demo mode** runs the same service over a mock chain and a simulated
group, with a simulated second operator who approves a few seconds after
this node. All of it is example data; it exists so a UI can run against the
real API without nodes.

**HTTP hardening.** Loopback listen only; constant-time bearer token compare;
Host must be `127.0.0.1:port` or `localhost:port` (DNS rebinding); a
cross-origin `Origin` is refused; 128 KiB body limit; no CORS; static UI
under `/ui/` with plain path components only (dotfiles, `..` and symlinks out
of the directory are refused), CSP `default-src 'self'`.

## Tests

| Command | Covers |
|---|---|
| `cargo test --offline -p holochain-mpc-vault --test state_machine` (20) | Happy path 2-of-3 to confirmed, tampered bytes (bytes, summary, plan), import checks, duplicate approvals, non-selected node, hash confirmation, expiry, replay, uncertain / rejected / on-chain-failed broadcast, stale reference, signing failure, reject, refresh, request validation, restart settling, private store files |
| `... --test http_api` (4) | Auth, host and origin checks, 413, a full flow over HTTP, static-file traversal, router equals `openapi.yaml` |
| `... --lib` (19) | Mock chain; Solana encoding against the known wire layout, durable nonce, memo, 12 refusals; signature binding; nonce account parsing; shortvec; pty prompt answering and redaction; config and token checks |

Not covered by automated tests: the live Holochain tools (only the
rehearsal run exercises `CliNode` against real binaries), and Solana RPC calls
(only the devnet run).

## Not implemented, deliberately

- **Policy enforcement.** There are no spending limits, allowlists, rate
  limits or time locks. Any proposal that two selected signers approve is
  signed. Deciding what may be signed stays with the people approving.
- **Owner or threshold changes.** The group is fixed by its DKG. Adding or
  removing an owner, or changing 2-of-3, needs a new DKG, which produces a
  new vault with a new address and a new balance to migrate.
- **Network-wide rejection.** `reject` is local to one node. There is no
  Holochain record of rejection. It is refused once this node has approved,
  because an approval cannot be retracted. Other nodes can still sign.
- **Multiple chains in one vault, mainnet, token transfers, priority fees.**
- **Production custody**: the share is still decrypted in `mpc-sign` under the
  same UID (Phase 7 limits). The service has no authentication beyond a
  bearer token on loopback.

## Changes outside `crates/mpc-vault` and this doc

- `Cargo.toml`: one workspace member added.
- `Cargo.lock`: one package entry added (`holochain-mpc-vault`). Every
  dependency version it uses is already locked (axum 0.8.9, tokio 1.53.3,
  ureq 3.4.2, ed25519-dalek 2.2.0, bs58, base64, sha2, serde_json, rand 0.8.8,
  libc). `--locked` builds need this entry.

## Findings for the operator

- **The rehearsal symlink blocker is avoidable without touching the harness.**
  `crates/mpc-vault/scripts/vault_rehearsal.py` loads
  `scripts/phase6_rehearsal.py` from the repo unmodified and, in memory only,
  points its root at the resolved path (`HOME` becomes the parent of the
  resolved `~/mpc-phase6-rehearsal`). `propose` then passes. The proper fix
  (resolve in the harness or in `lair_signer.rs:248`) is still the operator's.
- **The devnet RPC faucet is closed** (`requestAirdrop` answers 410 and points
  to https://faucet.solana.com). A person must fund the throwaway funder
  address from that web faucet; the driver prints it and waits.
- **Contract additions beyond the brief's endpoint list** (Agent 6 needs
  these): `GET /vaults`, `POST /proposals/preview`, `POST /proposals/import`,
  `GET /proposals/{id}/plan`, `POST /proposals/{id}/refresh`,
  `POST /proposals/{id}/broadcast`, `GET /events`. `approve` returns 202 and
  runs in the background; clients poll `GET /proposals/{id}`.

## End-to-end run

Driver: `crates/mpc-vault/scripts/vault_rehearsal.py` (disposable rehearsal,
throwaway Lair passphrase, throwaway devnet funder key; network access to the
devnet RPC was used for this step only). Runs on 27 October 2026:
`run-20261027T071419Z` and `run-20261027T081330Z` under
`~/mpc-phase6-rehearsal/` (each has `RESULT-vault.json` and logs). A third
attempt died in the harness's known relay-before-socket race, before any
vault code ran.

**Proven live, in both runs**

- Fresh 2-of-3 DKG across three conductors; all three groups activated.
- The throwaway funder (funded by the operator from the web faucet; the RPC
  faucet is closed) funded the vault address with 0.05 devnet SOL, and
  **devnet accepted the transaction that created a durable nonce account
  whose authority is the vault**. This validates the Solana message encoding
  for CreateAccount and InitializeNonce.
- Three services (one per node) created the same vault; the vault address
  equals the base58 of the group key.
- The proposal was built from the real nonce account's current value, decoded
  from its own bytes (278 bytes: 0.001 SOL, fee 0.000005 SOL, memo), and
  imported on two other nodes with an identical summary.
  A truncated plan and a repeated import were refused; node 2 (not selected)
  was refused with 403 `not_selected`; a second approval was refused.
- Nodes 1 and 3 approved through the API (`approve-intent`, passphrase typed
  by the service into a private pty), `mpc-lair-signer` and `mpc-sign` ran,
  and the signing finished within about seven seconds of the proposal being created.

**Where it stops**

`mpc-sign` writes `signed-message.bin` (493 bytes) beside the 278-byte
transaction. The group signs `frost::signed_message`: the bytes
`holochain-mpc-frost/ed25519/signature/v1` followed by length-prefixed
proposal action, session id, context hash, operation id and message. OpenSSL
confirms that the signature verifies over `signed-message.bin` and **fails**
over the transaction bytes (recorded in `RESULT-vault.json`:
`openssl_valid_over_signed_message: true`, `openssl_valid_over_transaction:
false`). A Solana validator checks the signature over the serialized
transaction message, so it would reject this one. The first run found it as
"signature does not verify under the vault key" at the `attach` step; the
vault now compares the signed bytes first and says why. The proposal ended
`failed` (step `attach`), nothing was broadcast and no funds moved (vault
still holds its 0.05 SOL).

So the brief's acceptance line, "2 of 3 disposable nodes sign a devnet
transfer accepted by the chain", is **not met** with the signing profile as
it is. This is a property of Phase 8, which was built to sign "arbitrary
bytes" under a session-bound domain separator, not to produce a raw chain
signature. It is outside this brief's write scope (the FROST crate, the
`SigningPlan` schema, `signing.rs` and the signer policy).

**Decision for the operator.** The vault, the Solana adapter and the driver
need no change once the group can sign the raw message. A minimal route:

1. A plan field (for example `domain`: `wrapped` default, `raw`), schema
   version 2, and `signed_message` returning the message unchanged for `raw`.
2. A separate signer profile for raw plans (as Phase 8 did with
   `mpc-frost-signing-v1`), so the DKG-time and wrapped profiles cannot sign
   raw bytes, and `verify_activated_artifact` taking the same flag.
3. A security review of what raw mode gives up: the binding of the signature
   to this proposal, session and operation id is no longer inside the signed
   bytes, so cross-protocol and replay protection must come from the chain
   (the durable nonce) and from the vault signing only fully decoded
   transactions. Raw plans should therefore be limited to groups the operator
   explicitly marks as chain vaults.

Until then the vault works end to end on the mock chain (and in demo mode)
and fails closed on a real chain.
