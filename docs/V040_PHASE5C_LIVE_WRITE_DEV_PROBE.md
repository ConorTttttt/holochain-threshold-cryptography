# v0.4.0 Phase 5C-A — live signed acceptance and disposable key registration

**Experimental development-sandbox tooling only. Not a production key, not an
MPC DKG key, and not a Phase 5C multi-agent delivery result.**

The Phase 5B real signed read path has passed against a local Holochain 0.7.1
conductor. The next zome write, `register_encryption_key`, requires an
**accepted** session (`require_fully_accepted`). The Phase 5B bootstrap made
one one-member, threshold-one proposal without its acceptance, so a separate
explicitly approved `accept_session` is needed first.

This patch is **additive only**: a Rust Cargo example under
`crates/mpc-dkg-worker/examples/`. It does not modify the working coordinator,
signer, repo manifests, the installed DNA or existing bootstrap code. Cargo
automatically discovers examples. It is intended to apply even if the user has
Claude Code's Phase 5B bootstrap changes in `Cargo.toml`, `package.json`, and
`check_release.py`.

## Security boundaries and approvals

- There are **two different on-chain writes**, each gated by an exact different
  confirmation flag. Running unit tests has no side effects on the conductor.
- The example restricts **both** operations to a verified one-member,
  threshold-one session containing exactly the pinned agent. Use the existing
  Phase 5B proposal only. Never treat this as a valid three-party FROST group.
- `accept-session` is deliberately **not added** to the Phase 5A signer
  allowlist. Instead, this operator-interactive development utility connects
  directly to the *already authorised Lair keystore*, checks the actual
  app/agent/DNA and existing status, then signs the exact `accept_session`
  operation. It refuses to write if the local agent already accepted.
- `register-dev-key` requires a running Phase 5A signer and uses its existing
  scoped `RegisterEncryptionKey` request. It first reads the real on-chain
  key binding list, refuses any previous registration, verifies the one-member
  session was already accepted, and validates the real conductor's action,
  author and exact public key on readback.
- **The generated X25519 test secret is intentionally destroyed when the
  process exits.** That public registration is permanent test data and is
  **not usable** for decrypting real messages or FROST DKG. Do not run this
  probe against a production or future multi-party proposal. Real DKG
  registration must use the key generated and held by the *actual private MPC
  worker*, as the existing `RelayEngine::start` does.
- `register-dev-key` requires entering the Lair passphrase to fetch an exact,
  freshly signed `get_session_status`, in addition to calling the running
  private signer socket for its own key registration. This is intentionally
  redundant to protect other sessions from disposable-key registration.
- The policy's `recipients: []` remains unchanged. No new recipient grants,
  messages, arbitrary signer operations, keys, tokens, or proposals are created.
- Any uncertain write outcome is terminal. **Do not retry**; inspect the
  source chain and response first. A retry can create additional public
  records.

## Build and static tests in Holonix

```bash
cd ~/Downloads/holochain-mpc-core-v0.3.3-dkg-source/holochain-mpc-core
# Run nix develop if you are not already in Holonix.

cargo test -p holochain-mpc-dkg-worker --features lair-signer \
  --example phase5c_live_writes -- --nocapture
cargo build -p holochain-mpc-dkg-worker --features lair-signer \
  --example phase5c_live_writes
npm run test:signer-phase5
npm run test:signer-phase5b-static
```

The tests cover the CLI's explicit confirmation flags, refusal of arbitrary
operations, separation of operation inputs and rejection of multi-member
sessions. **They do not establish live acceptance or registration.**

## Existing verified environment (replace only if changed)

The prior Phase 5B operator report confirmed:

```bash
PRIV="$HOME/.local/state/mpc-phase5b"
SB="$HOME/mpc-phase5b-sandbox/state/node-a"
DNA_HEX="842d24575ef78f84fd41cda90b1ae25c6e629b53b9670eda17172115926e3c6ebcab1c20cc69b9"
LAIR_URL="$(lair-keystore --lair-root "$SB/ks" url)"
```

Ensure `hc client call --port 43977 list-apps` still reports
`mpc-phase5b` enabled and `hc client call --port 43977 list-app-ws`
reports port 8888. Ensure the Phase 5B token has not expired: it was initially
issued for only **7,200 seconds**, and conductor restart invalidates it.
Do not regenerate a token without separate approval.

### Write 1 — accept existing proposal (operator approval required)

The conductor and external Lair must be running. In a Holonix terminal,
with the variables above in that terminal:

```bash
cargo run -p holochain-mpc-dkg-worker --features lair-signer \
  --example phase5c_live_writes -- \
  accept-session \
  --state-dir "$PRIV/node" \
  --app-socket 127.0.0.1:8888 \
  --origin http://localhost:8888 \
  --app-token-file "$PRIV/app-token" \
  --installed-app-id mpc-phase5b \
  --dna-hex "$DNA_HEX" \
  --lair-url "$LAIR_URL" \
  --confirm-acceptance-write
```

Type the existing Lair passphrase when prompted. The utility checks the
real session status before submitting an acceptance. An already accepted
session is a refusal to write rather than an error to fix by resetting it.
Successful execution prints `PASS: Lair-signed accept_session accepted by real
conductor (action recorded)`.

### Write 2 — register a **disposable** development key

**Only after the acceptance is confirmed**, leave the Phase 5A Lair signer
running on its existing `0600` socket. In another Holonix terminal set the
same `PRIV`, `SB`, `DNA_HEX`, and `LAIR_URL` variables and run:

```bash
cargo run -p holochain-mpc-dkg-worker --features lair-signer \
  --example phase5c_live_writes -- \
  register-dev-key \
  --state-dir "$PRIV/node" \
  --app-socket 127.0.0.1:8888 \
  --origin http://localhost:8888 \
  --app-token-file "$PRIV/app-token" \
  --installed-app-id mpc-phase5b \
  --dna-hex "$DNA_HEX" \
  --lair-url "$LAIR_URL" \
  --signer-socket "$PRIV/signer/signer.sock" \
  --confirm-disposable-key-write
```

The tool produces one fresh local X25519 key, asks the existing Lair signer
to sign the registration, sends the one pre-signed call, then obtains another
fresh signed read from that signer. PASS requires **exactly one** observed
binding with the identical action, author and public key. The private test key
is then discarded. Avoid rerunning; the code refuses any existing key record.

## Next steps

After verifying these two source-chain writes on the **test-only proposal**:

1. For Phase 5C-B/C, create a separate **two- or three-member** proposal with
   independently authorised agents and proper matching acceptances.
2. Provision an assigned **`receive_protocol_message` capability grant** on
   each recipient; distribute capability secrets over an authenticated and
   confidential out-of-band channel, never via DHT or terminal logs.
3. Each real DKG worker generates its own transport key and publishes it with
   the *existing* `RelayEngine::start` path, retaining its private key. Pin
   exact author/action/key evidence; reject duplicates and forks.
4. Send one signed, encrypted sealed envelope through the real conductor,
   verify the intended recipient's private inbox, authenticated sender,
   decrypt locally and check replay/cross-ceremony rejection.
5. Only after this, attempt independent three-node automatic DKG (Phase 6).

The immediate experiments here cannot establish multi-agent delivery or
secure persistent key custody; those remain separate milestones.
