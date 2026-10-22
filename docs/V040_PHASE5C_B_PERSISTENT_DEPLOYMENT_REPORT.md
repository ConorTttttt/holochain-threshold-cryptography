# v0.4.0 Phase 5C-B — Persistent Two-Agent Deployment and Provisioning Report

**Project:** Holochain MPC Core  
**Report date:** 17 October 2026 (Europe/London)  
**Platform:** Holochain 0.7.1, Rust, FROST Ed25519, Holonix, Lair, Kitsune2/Iroh  
**Branch observed:** `feature/v0.4.0-phase5c-live-writes`  
**Deployment:** `mpc-phase5c`, two persistent conductors on one development host  
**Milestone:** Persistent two-agent consent and reciprocal capability provisioning  
**Status:** **Provisioning steps operator-reported successful; final read-only deployment audit outstanding.** Phase 5C-C encrypted delivery has **not** yet been performed.

> **Evidence convention.** **Observed** means that the operator pasted relevant terminal output in the project conversation. **Operator-reported** means that the operator confirmed checks passed but did not provide their complete output. **Pending** means no successful result has yet been supplied. This report records a development result; it is not a production security certification. The live source tree and conductor stores were not remotely inspected.

## 1. Purpose and scope

Phase 5C-B connects two distinct Holochain agent identities to an exact, jointly accepted MPC ceremony and provisions reciprocal, assigned capabilities for future `mpc.receive_protocol_message` delivery. Each grant secret is sealed using the agents' existing Lair signing identities, then imported into local private capability state and incorporated into a restricted signer policy.

This phase **does not** perform autonomous FROST DKG, transmit a live encrypted protocol envelope between these persistent nodes, or establish production-grade key custody. Those outcomes belong to later phases.

**Trust boundary:** Holochain coordinates session proposals, consent, assigned capability grants and message routing; native Rust workers hold and process sensitive MPC material. Shares, signing nonces, worker decryption keys and plaintext capability secrets must not be published to the DHT.

## 2. Environment and stable ceremony identifiers

| Item | Node A | Node B |
|---|---|---|
| Sandbox | `~/mpc-phase5c-sandbox/state/node-a` | `~/mpc-phase5c-sandbox/state/node-b` |
| Installed application | `mpc-phase5c` | `mpc-phase5c` |
| Holochain role | `mpc` | `mpc` |
| App state | Enabled | Enabled |
| Last observed admin WebSocket | `34835` | `35169` |
| App WebSocket | `8891` | `8892` |
| Lair root | `state/node-a/ks` | `state/node-b/ks` |
| Agent key | `uhCAkwfXPxtzM7lKfMBc1BS8TZkPpcBPav6RoxhpA2YfrhGjo0BQo` | `uhCAkU0m8gBCkoSRobThBSYh47kC-DiAhCR1AJKmxUB1uf-Oi6vtb` |

**Installed, matching DNA (both nodes; extracted `.happ` DNA also matched):**

```text
uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu
```

**Persistent 2-of-2 ceremony, created by Agent A:**

```text
proposal_action_b64=uhCkk5YMJyNLP2DXnLnuvXIyY66dMl0mwYqx4tgT0ucDPDgxyIhmD
session_id_hex=e26c6855fd54ab228c5c386196754eaf4cfab16d0377deae0f9b0c7df2684371
participants=2
threshold=2
session-grant-tag-prefix=mpc-session-[e2, 6c, 68, 55]
```

The proposal `ActionHash` is **not** interchangeable with the 32-byte session ID. All operations must retain the same exact pinned `SessionSpec`, proposal, app, DNA and participant roster. Both participants must consent, regardless of threshold.

**Nonsecret state locations:**

```text
Source repo: ~/Downloads/holochain-mpc-core-v0.3.3-dkg-source/holochain-mpc-core
Sandbox:     ~/mpc-phase5c-sandbox
Private ops: ~/.local/state/mpc-phase5c
              a/ceremony.json, b/ceremony.json
              a/offers/, b/offers/          (sealed offers)
              a/caps/, b/caps/              (SECRET capability records)
              a/node/, b/node/              (native node state)
              a/signer-policy.json, b/signer-policy.json  (SECRET-bearing)
```

Do not print or commit tokens, decrypted capability files, signer policies, keystore stores, private keys or passphrases. Any `ceremony.json` contains public ceremony data, but preserve its exact bytes and do not edit it manually.

## 3. Evidence and completed operations

### 3.1 Persistent conductor identity and DNA — observed

`hc client call --port 34835 list-apps` and `--port 35169 list-apps` showed enabled `mpc-phase5c` apps with role `mpc`, the same DNA hash and distinct `agent_pub_key` values. `list-app-ws` returned `8891` and `8892`, respectively. App interfaces were configured with `allowed_origins: "*"` and `installed_app_id: null` (development configuration; see risks).

The existing `workdir/holochain-mpc-core.happ` was unpacked into a separate `/tmp` directory without changing the running conductors. `hc dna hash` on its extracted `mpc.dna` returned the same installed DNA hash. This proves **artifact-to-installed-DNA identity**, but does not by itself prove the precise build provenance or independently test the revocation fix.

### 3.2 Networking and cross-conductor data visibility — observed

`list-agents` on each node returned two transport URLs in the same Kitsune2 space. Each conductor's *remote* entry had `agent_pub_key: null` / `k2_agent: null`, so that diagnostic alone was not treated as proof of resolved agent identity.

`dump-network-stats` showed a **direct** bidirectional Iroh connection (`is_direct: true`):

| Counter | A-to-B transport view | B-to-A transport view |
|---|---:|---:|
| Sent messages | 224 | 224 |
| Sent bytes | 47,888 | 43,439 |
| Received messages | 224 | 224 |
| Received bytes | 43,439 | 47,888 |
| Blocked message counts | `{}` | `{}` |

Previous `LocallyClosed` and `superseded by preferred connection` log messages did not prevent this observed direct traffic. The decisive application-level test came later: **Agent B executed `mpc-phase5c-provision status` against its own conductor and received `PASS: conductor proposal matches the pinned ceremony exactly` for A's proposal.** Agent A independently produced the same verification result.

### 3.3 Private operator state and source preservation — observed

`~/.local/state/mpc-phase5c/{a,b}/{offers,caps,signer}` directories were created with `0700` permissions and were initially empty. Two 7,200-second application tokens were subsequently issued with operator approval; the operator reported their presence and `0600` permissions. **Tokens may have expired** and must not be presumed valid for later audits.

The operator created:

```text
~/mpc-source-backups/holochain-mpc-core-phase5c-b-2026-10-17.tar.gz
```

It was readable via `tar -tzf`, had `0600` permissions, and contained the specifically checked Phase 5C-B sources (`capability_exchange.rs`, `phase5c_provision_main.rs`, `revoke_cap_grant.rs`) and provisioning documentation. **A complete reviewed Git commit and full backup-content audit have not been reported.** Numerous Phase 4/5C files remained modified/untracked on the observed branch. Preserve the working tree; never use `git reset --hard` or `git clean -fd` as a shortcut.

### 3.4 Lair permissions preflight and safe retry — observed

The first `propose` attempt failed with:

```text
FAIL: phase5c provisioning: Lair root must be an owned directory without group/other access
```

The Agent A Lair root initially had `0755`; it was corrected to `0700`. Its `lair-keystore-config.yaml` initially had `0644`; it was corrected to `0600`, with ownership `sf:sf` and one hard link. No keystore reinitialisation or key rotation was required.

Source inspection established that `propose()` calls `App::open(..., lair(&f).await?)` **before** `app.call("propose_session", ...)`. The specific Lair-root error therefore occurred before submission in that attempt. The local `ceremony.json` did not exist at that time. Following corrections, the authorised second attempt succeeded and wrote the local ceremony record.

**General rule:** for all other write failures or timeouts, do **not** infer failure from a missing local output file: Holochain may have committed a source-chain action before the local file write. Inspect state; never blindly retry ambiguous chain writes.

### 3.5 Proposal and mutual acceptance — observed / operator-reported

The proposal command printed:

```text
PROPOSAL CREATED (public identifiers only)
proposal_action_b64=uhCkk5YMJyNLP2DXnLnuvXIyY66dMl0mwYqx4tgT0ucDPDgxyIhmD
session_id_hex=e26c6855fd54ab228c5c386196754eaf4cfab16d0377deae0f9b0c7df2684371
participants=2 threshold=2
ceremony record written
```

- **Observed:** Agent B's read-only `status` verified A's exact pinned proposal with both acceptances initially `pending`, `ready_observed=false`.
- **Observed:** Agent A's read-only `status` also verified the exact proposal with both initially `pending`, `ready_observed=false`.
- **Operator-reported:** Agent A performed one independently approved, Lair-signed `accept_session` write and passed subsequent read-only verification; the operator also reported that B saw A's acceptance.
- **Observed:** After Agent B's separately approved acceptance, pasted read-only status outputs listed **both participants `accepted` on both conductors**; Agent A returned `ready_observed=true`, and a subsequent explicit Agent B status returned `ready_observed=true`.

`ready_observed=true` is a conductor's view of validated acceptance records; it is **not** network finality or consensus.

### 3.6 Reciprocal assigned capability grants — operator-reported

The grant directions are easy to reverse accidentally:

| Grant issuer / recipient inbox | Authorised caller | Permitted function | Who receives the sealed grant secret |
|---|---|---|---|
| **Agent A** | Agent B | `mpc.receive_protocol_message` on A | **Agent B** |
| **Agent B** | Agent A | `mpc.receive_protocol_message` on B | **Agent A** |

- **Observed:** Before A's grant, `list-grants` reported `session grants (tag mpc-session-[e2, 6c, 68, 55]): 0`.
- **Operator-reported:** A's approved `prepare-grant` succeeded, `list-grants` and one encrypted offer for B passed verification.
- **Observed:** Before B's grant, `list-grants` reported zero session-tagged grants for B.
- **Operator-reported:** B's separately approved `prepare-grant` succeeded, its `list-grants` and one encrypted offer for A passed verification.

The provisioning tool reportedly verified each newly created grant's exact action, assigned assignee(s) and sole authorised function. A session-tagged grant count of one alone does **not** prove the grant is cryptographically session-scoped; the 4-byte tag is a label only.

### 3.7 Sealed-offer imports and private native state — operator-reported

- Agent B imported **A's** encrypted offer using **B's** existing Lair identity; Agent A imported **B's** offer using **A's** identity. Import routines check sender authentication and exact DNA, proposal, session, grantor, grantee, grant action and outer/inner consistency.
- The operator reported `PASS: Agent a has one private capability file` and `PASS: Agent b has one private capability file`; checks included `0600` files and controlled directories.
- Both native `mpc-node provision` operations completed using `ids` derived from the pinned ceremony. A and B have separate state directories bound to their respective agent identities and the shared proposal/session.
- Both `mpc-phase5c-provision write-policy` operations completed, and the operator reported both generated `signer-policy.json` files passed existence, nonempty, nonsymlink and `0600` permission checks. The CLI's success is the application-level policy validation evidence; permission checks alone do not revalidate cryptographic content.

**No actual persistent encrypted message exchange or worker-side decryption has been reported.**

## 4. Final read-only acceptance audit — NOT YET REPORTED

The previous conversation requested this audit, but the operator has not yet returned its results. **Do not retroactively mark it complete.** Run from Holonix in a separate terminal while both conductors are live. Commands below display public identifiers and grant metadata only; do not display token or capability contents.

```bash
REPO="$HOME/Downloads/holochain-mpc-core-v0.3.3-dkg-source/holochain-mpc-core"
SB="$HOME/mpc-phase5c-sandbox"
P="$HOME/.local/state/mpc-phase5c"
PROV="$REPO/target/debug/mpc-phase5c-provision"
AGENT_A_B64="uhCAkwfXPxtzM7lKfMBc1BS8TZkPpcBPav6RoxhpA2YfrhGjo0BQo"
AGENT_B_B64="uhCAkU0m8gBCkoSRobThBSYh47kC-DiAhCR1AJKmxUB1uf-Oi6vtb"
ADMIN_A=34835
ADMIN_B=35169

# Recheck app identities and admin ports after any restart.
hc client call --port "$ADMIN_A" list-apps
hc client call --port "$ADMIN_B" list-apps

# Must be exact same frozen ceremony.
cmp -s "$P/a/ceremony.json" "$P/b/ceremony.json" && echo 'PASS: matching ceremony files'

# Expect exactly one matching live session-tagged grant on each side;
# separately inspect redacted metadata for correct assignee/function/action.
"$PROV" list-grants --record "$P/a/ceremony.json" --admin-port "$ADMIN_A" --agent-b64 "$AGENT_A_B64"
"$PROV" list-grants --record "$P/b/ceremony.json" --admin-port "$ADMIN_B" --agent-b64 "$AGENT_B_B64"

# Read-only status; tokens may have expired. Do not repeat writes to repair an expired token.
"$PROV" status --app-port 8891 --origin http://localhost:8891 \
  --app-token-file "$P/a/app-token" --agent-b64 "$AGENT_A_B64" \
  --lair-root "$SB/state/node-a/ks" --record "$P/a/ceremony.json"
"$PROV" status --app-port 8892 --origin http://localhost:8892 \
  --app-token-file "$P/b/app-token" --agent-b64 "$AGENT_B_B64" \
  --lair-root "$SB/state/node-b/ks" --record "$P/b/ceremony.json"

# Local private-state metadata only (do not cat any files).
for agent in a b; do
  dir="$P/$agent"
  test -d "$dir/node" && test ! -L "$dir/node" && echo "PASS: $agent node dir"
  test -f "$dir/signer-policy.json" && test ! -L "$dir/signer-policy.json" \
    && test -s "$dir/signer-policy.json" \
    && test "$(stat -c '%a' "$dir/signer-policy.json")" = 600 \
    && echo "PASS: $agent signer-policy file"
  test "$(stat -c '%a' "$dir/caps")" = 700 \
    && test "$(find "$dir/caps" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 1 \
    && test -z "$(find "$dir/caps" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" \
    && test -z "$(find "$dir/caps" -mindepth 1 -maxdepth 1 -type f ! -perm 600 -print -quit)" \
    && echo "PASS: $agent caps metadata"
done
```

Audit acceptance requires: both `status` results match the existing ceremony with both agents `accepted` and `ready_observed=true`; each node has **one valid expected grant**; the two private node states and signer policies remain intact. If an application token has expired, reissue it via a **separately approved token operation**, not by recreating the proposal/acceptances/grants. Any missing evidence remains **pending**, not assumed passing.

### Final audit evidence to append

```text
Audit performed (local timestamp): PENDING
DNA from both list-apps:          PENDING RECHECK
Agent A status:                  PENDING RECHECK
Agent B status:                  PENDING RECHECK
Agent A grant count/metadata:    PENDING RECHECK
Agent B grant count/metadata:    PENDING RECHECK
Node A/B private-state checks:   PENDING RECHECK
Operator sign-off:               PENDING
```

## 5. Remaining security and operational limitations

1. **Holochain grants are not truly session-scoped.** `CapGrant` restricts assigned caller and function, not one full `SessionSpec`. The 4-byte `mpc-session-...` tag does not enforce the session. Current ceremony and signer policies narrow usage at the application boundary; implement stronger receive-side session/epoch authorisation in future work.
2. **Revocation documentation (corrected 18 October).** `docs/V040_PHASE5C_B_PROVISIONING.md` now says revocation depends on the deployed DNA; the earlier "impossible" wording survives only in the pre-implementation checkpoint. The **new** integrity implementation was reported to pass `revoke_cap_grant` and post-revocation capability Sweettests; the fix changes DNA and does not retroactively erase known secrets or delivered messages. Update the original operator document before release. The exact currently running DNA matches the packaged bundle, but a hash match alone does not independently audit the source-to-WASM build provenance.
3. **Same-Linux-user custody.** The conductor, Lair, worker and signer share one UID in this sandbox. `0700`/`0600` protects against other users but does not isolate a compromised same-UID process. Not production custody.
4. **WebSocket origins.** `allowed_origins: "*"` and unbound `installed_app_id: null` are development settings. App authentication is still required, but restrict origins and interfaces for production.
5. **No blind retries of uncertain writes.** A source-chain write may succeed before local file creation or RPC acknowledgement. Inspect the recorded proposal, acceptance or grant before any remediation. `prepare_inbox_grant` is not inherently idempotent.
6. **Network observation is not finality.** Direct Iroh traffic and remote proposal/acceptance retrieval were demonstrated, but DHT observations can differ temporarily. Use bounded status checks with exact action/spec equality.
7. **Source-control recovery remains incomplete.** A `0600` source archive exists and is readable, but a reviewed commit encompassing modified and untracked Phase 4–5C sources has not been reported. Verify `.gitignore` and exclude tokens, `~/.local/state`, Lair roots, native secret states, and compiled artefacts before staging.
8. **No persistent end-to-end encrypted delivery test yet.** No recipient-side native decryption, restart proof or negative delivery test on the persistent two-node setup has been observed.
9. **Phase 5C-A disposable X25519 private key was discarded.** Its published test key binding must not be reused for live ciphertext or assumed decryptable.
10. **Avoid updates to the Phase 5B reference sandbox.** `~/mpc-phase5b-sandbox` uses an earlier DNA and its proven live reads/writes should remain untouched.

## 6. Phase 5C-C entry criteria and initial plan

**Entry conditions:** complete and record the final read-only Phase 5C-B audit; review/update the stale revocation documentation; safely checkpoint current source work. No previously approved grant/write operation should be repeated.

**Phase 5C-C goal:** send one **bounded** encrypted protocol envelope from native Agent A to native Agent B over the existing Holochain network, with a Lair-signed zome call and recipient-side authenticated decryption using a **new, durably retained worker-owned X25519 private key**.

Proposed work, starting with read-only source inspection/design review:

1. Inspect coordinator entry points (`register_encryption_key`, `get_encryption_key_bindings`, `send_protocol_message`, `receive_protocol_message`, `get_inbox`), existing `SealedPacket` representation, relay/worker interfaces, signer restrictions and durable runtime.
2. Specify cryptographic envelope bindings (exact DNA/proposal/session, sender/recipient agent, encryption-key author/action/epoch, round/sequence, payload digest), replay policy and recipient acceptance checks. Ensure ciphertext is not mistaken for verified plaintext.
3. Specify worker-held key generation, secure retained custody and restart behaviour. Do **not** reuse the discarded Phase 5C-A test key.
4. Perform fresh per-agent key registration only with explicit write approval; verify public binding records against author/action/DNA/proposal and retain private keys locally.
5. Start the restricted signer/relay under pinned policy; authorise a **single** real sealed test message; verify recipient private inbox and native authenticated decryption.
6. Add tests for wrong capability, revoked capability, tampering, wrong recipient, cross-session replay, duplicate/equivocating sequence, process restart and network failure; use fail-closed handling and no blind write retries.

**Success condition for Phase 5C-C:** independent persistent conductors deliver one cryptographically bound ciphertext, B's native worker decrypts and authenticates it using its retained private key, and the stated negative/restart tests pass. Sweettest alone or transport statistics alone are insufficient.

## 7. Source-of-truth references

- `docs/V040_PHASE5C_B_PROVISIONING.md` — existing operator commands; **outdated revocation paragraph**.
- `docs/V040_PHASE5C_B_GRANT_REVOCATION_FIX.md` — reported revocation fix.
- `crates/mpc-dkg-worker/src/phase5c_provision_main.rs` — proposal, status, acceptance, grants, imports, policy CLI.
- `crates/mpc-dkg-worker/src/capability_exchange.rs` — ceremony and sealed-offer checks.
- `crates/mpc-dkg-worker/src/lair_signer.rs` — restricted Lair configuration and signer rules.
- `crates/mpc-dkg-worker/tests/capability_provisioning.rs` — two-agent grant/exchange Sweettest.
- `dnas/mpc/zomes/coordinator/mpc/tests/revoke_cap_grant.rs` — grant revocation regression.
- `dnas/mpc/zomes/integrity/mpc_integrity/src/lib.rs` — integrity validation and deletion boundary.
- Project handover dated 17 October 2026 and operator terminal reports continuing through the two-agent provisioning session.

**Do not replace live terminal/source evidence with this report when making future security or release claims.**


## 8. Handover and offline development addendum — 18 October 2026

The operator's subsequent handover reports the final Phase 5C-B audit passed.
The earlier evidence labels above are retained as historical observations;
this source-only session did not access persistent deployment state to repeat
that audit. Phase 5C-C source implementation and offline evidence are recorded
in `V040_PHASE5C_C_TRANSPORT_PROBE.md` and `V040_PHASE5C_C_OFFLINE_REPORT.md`.
The probe uses a separate protocol/proposal and independent credentials. The
historical suggestion to start RelayEngine for a diagnostic message is not
the approved implementation: that engine initializes FROST DKG. No live
probe delivery has been demonstrated in this implementation session.
