# v0.4.0 Phase 5C-B — two-agent ceremony, assigned grants, private capability exchange

**Development tooling. Not production custody, and not DKG.** This phase
gets two independently keyed conductors to the point where each holds an
exact, verified capability to deliver protocol messages to the other.
Phase 5C-C then sends the first signed, encrypted envelope.

## What was added

| Piece | Purpose |
|---|---|
| `src/capability_exchange.rs` (feature `lair-signer`) | ceremony record + exact spec pinning, secret-free grant verification, sealed capability offers, exact multi-recipient signer policy |
| `src/phase5c_provision_main.rs` → `mpc-phase5c-provision` | operator CLI: one subcommand per step; every write needs its own `--confirm-*` flag |
| `lair_signer::lair_url_from_root` | reads the Lair URL from `<root>/lair-keystore-config.yaml` (owned, private), so it is never on argv |
| `mpc-lair-signer --lair-root` | same, for the long-running signer (preferred over `--lair-url`) |
| `tests/capability_provisioning.rs` | Sweettest: two real conductors and keystores, real grants, real delivery |

## Design

1. **Ceremony record (public).** The proposer writes `ceremony.json`, which pins the
   app ID, DNA, proposal action and the *full* `SessionSpec`. Every later
   step reads the proposal back from its own conductor and requires
   byte-for-byte equality: session, context hash, members, threshold and rounds.
2. **Assigned grant, one per recipient.** `prepare_inbox_grant` creates one
   `assigned` grant for `mpc/receive_protocol_message`, assigned to all other
   participants. The tool refuses to write if a live grant for this session
   already exists (admin `ListCapabilityGrants`, which carries no secrets).
   After the write, it requires *exactly one* live session grant: the returned
   action, `assigned`, exact assignee set, exactly one function. Anything
   broader is rejected as an unauthorised capability.
3. **Private exchange.** For each peer S, the recipient R's Lair seals
   `{dna, proposal, session, grantor R, grantee S, grant action, secret}` with
   `crypto_box_xsalsa_by_sign_pub_key(R → S)`, using the agents' **existing
   signing keys**. Only S's Lair can open it, and opening authenticates R.
   After opening, every field is re-checked against S's own ceremony record:
   wrong session, proposal, DNA, grantor, grantee, or a plaintext/outer
   mismatch are all refused. No keys are exported and nothing touches the DHT.
4. **Exact policy.** `write-policy` requires a node directory pinned to the
   same proposal and session, plus exactly one capability from every other
   participant (no missing, extra, duplicate or self entries). It pins the
   record's full `SessionSpec` in the policy (security-review B2 fix) and
   round-trips the result through the signer's own parser. A policy written
   before that fix has no `spec`; the signer now refuses to load it because
   it carries capabilities. Regenerate it to a NEW path from the same
   ceremony record, caps and node state; no chain write is involved.

## Findings that affect security (not fixed here)

* **Grants are not session-scoped.** `prepare_inbox_grant` authorises
  `receive_protocol_message` for the assignees across *every* session the
  recipient is in, and its tag holds only 4 session-ID bytes. Delivery is
  still limited by the zome's membership and full-acceptance checks. The
  tooling binds secrets to one ceremony and fails closed on tag collisions.
* **Grant revocation depends on the deployed DNA.** The current source fix
  permits deletion of the author's own CapGrant creation action in both
  validation paths. See `V040_PHASE5C_B_GRANT_REVOCATION_FIX.md`. Older DNA
  rejected revocation; never infer deployed behavior from current source.
  Revocation requires separate operator approval and does not erase known
  secrets or already delivered messages.
* **Lair URL `k=`.** In `lair_keystore_api` 0.7.1 the `k` query parameter is
  the Lair **server public key**, used by `hello()` to authenticate the
  server. The client credential is the passphrase (`unlock()`). Seeing `k`
  does not grant access, so **no rotation is required**. The new tooling
  still keeps the URL out of argv, environment and logs. If you want to
  rotate anyway, the only way is to re-`init` the Lair root, which creates a
  new store and **loses the agent key**. Don't do this to a working
  conductor; use a fresh sandbox instead.

## Tests

```bash
npm run test:phase5c-b-unit       # pinning, cross-session, grants, policies, Lair seal/open, CLI gates
npm run test:phase5c-b-sweettest  # two real conductors (Sweettest)
```

## Operator procedure

All commands run in a Holonix shell (`nix develop`). The Phase 5B sandbox
in `~/mpc-phase5b-sandbox` is not used or touched. Approval points are
marked **APPROVAL**.

```bash
REPO=~/Downloads/holochain-mpc-core-v0.3.3-dkg-source/holochain-mpc-core
SB=~/mpc-phase5c-sandbox; P=~/.local/state/mpc-phase5c
PROV=$REPO/target/debug/mpc-phase5c-provision; BOOT=$REPO/target/debug/mpc-phase5b-bootstrap
```

**0. Build:** `cd $REPO && npm run build:happ && npm run build:phase5c-provision && npm run build:phase5b-bootstrap && npm run build:lair-signer`

**1. APPROVAL (new environment, new agent keys, new Lair stores).**
Terminal 1: `kitsune2-bootstrap-srv --listen 127.0.0.1:51000`.
Terminal 2:

```bash
mkdir -m 700 -p $SB/state && cd $SB
hc sandbox generate --app-id mpc-phase5c --root $SB/state -d=node-a,node-b -n 2 \
  --run=8891,8892 $REPO/workdir/holochain-mpc-core.happ \
  network --bootstrap http://127.0.0.1:51000 quic http://127.0.0.1:51000
```

Enter a new passphrase when prompted. Then, in another terminal:

```bash
cd $SB && hc sandbox admin-ports     # ADMIN_A, ADMIN_B (in node order)
hc client call --port $ADMIN_A list-apps   # AGENT_A_B64, DNA_B64
hc client call --port $ADMIN_B list-apps   # AGENT_B_B64 (DNA must equal DNA_B64)
hc client call --port $ADMIN_A list-agents # both agents must appear before step 4
```

**2. Private dirs:** `mkdir -m 700 -p $P/a/offers $P/a/caps $P/a/signer $P/b/offers $P/b/caps $P/b/signer`

**3. APPROVAL (credential issuance), once per node:**

```bash
$BOOT issue-app-token --admin-port $ADMIN_A --installed-app-id mpc-phase5c --out $P/a/app-token --expiry-seconds 7200 --confirm-admin-token-issue
$BOOT issue-app-token --admin-port $ADMIN_B --installed-app-id mpc-phase5c --out $P/b/app-token --expiry-seconds 7200 --confirm-admin-token-issue
```

**4. APPROVAL (source-chain write on A):**

```bash
printf '%s\n%s\n' "$AGENT_A_B64" "$AGENT_B_B64" > $P/participants.txt
$PROV propose --app-port 8891 --origin http://localhost:8891 --app-token-file $P/a/app-token \
  --agent-b64 $AGENT_A_B64 --lair-root $SB/state/node-a/ks --installed-app-id mpc-phase5c \
  --dna-b64 $DNA_B64 --participants-file $P/participants.txt --threshold 2 \
  --record-out $P/a/ceremony.json --confirm-source-chain-write
install -m 600 $P/a/ceremony.json $P/b/ceremony.json
```

**5. APPROVAL (one acceptance write per node):** first run the read-only
`status` on B until the proposal is visible. Then:

```bash
A="--app-port 8891 --origin http://localhost:8891 --app-token-file $P/a/app-token --agent-b64 $AGENT_A_B64 --lair-root $SB/state/node-a/ks --record $P/a/ceremony.json"
B="--app-port 8892 --origin http://localhost:8892 --app-token-file $P/b/app-token --agent-b64 $AGENT_B_B64 --lair-root $SB/state/node-b/ks --record $P/b/ceremony.json"
$PROV status $B
$PROV accept $A --confirm-acceptance-write
$PROV accept $B --confirm-acceptance-write
$PROV status $A    # both accepted, ready_observed=true
```

**6. APPROVAL (one grant write per node):**

```bash
$PROV prepare-grant $A --admin-port $ADMIN_A --offers-dir $P/a/offers --confirm-grant-write
$PROV prepare-grant $B --admin-port $ADMIN_B --offers-dir $P/b/offers --confirm-grant-write
$PROV list-grants --record $P/a/ceremony.json --admin-port $ADMIN_A --agent-b64 $AGENT_A_B64
```

**7. Exchange and import (local only, Lair opens):**

```bash
$PROV import-offer --record $P/b/ceremony.json --agent-b64 $AGENT_B_B64 --lair-root $SB/state/node-b/ks \
  --offer $P/a/offers/offer-*-to-*.json --caps-dir $P/b/caps
$PROV import-offer --record $P/a/ceremony.json --agent-b64 $AGENT_A_B64 --lair-root $SB/state/node-a/ks \
  --offer $P/b/offers/offer-*-to-*.json --caps-dir $P/a/caps
```

On separate machines, carry each `offer-*.json` over any channel. It is
ciphertext, but keep it private anyway.

**8. Node and policy (local only), per node:**

```bash
eval "$($PROV ids --record $P/a/ceremony.json --agent-b64 $AGENT_A_B64)"
$REPO/target/debug/mpc-node provision $P/a/node $AGENT_HEX $PROPOSAL_HEX $SESSION_HEX
$PROV write-policy --record $P/a/ceremony.json --state-dir $P/a/node --caps-dir $P/a/caps --out $P/a/signer-policy.json
# repeat with b / AGENT_B_B64
```

**Stop here for 5C-B.** The dedicated Phase 5C-C probe requires a separate
`mpc-transport-probe` proposal, native state and opt-in signer policy. Do not
send diagnostic traffic under this FROST proposal. See
`V040_PHASE5C_C_TRANSPORT_PROBE.md` for the offline design and proposed live
approval checkpoints.

## Uncertain outcomes

A write that reports `outcome UNKNOWN` is terminal: check with `status` or
`list-grants` before doing anything else. If a grant exists but its secret
was lost, `prepare-grant` refuses to make a duplicate. Revocation depends on
the deployed DNA (see Findings). Stop for operator review; do not revoke or
replace a grant automatically.
