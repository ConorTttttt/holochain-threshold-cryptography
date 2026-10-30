# v0.4.0 Phase 5B — Lair discovery, preflight and operator bootstrap

This increment adds two tools that get a running `hc sandbox` conductor
ready for the Phase 5B live read (`docs/V040_LAIR_LIVE_PROBE_PHASE5B.md`):

* `scripts/phase5b_preflight.py`: **read-only**. Finds the conductor's real
  keystore, checks the Lair IPC socket and the app/cell pin, looks for a
  `SessionProposal` on the local chain, and checks file permissions and the
  exact match between the policy and the node. It never reads the app token's
  contents and never prints Lair URL query strings or secrets.
* `mpc-phase5b-bootstrap` (feature `lair-signer`): one binary with
  narrowly scoped subcommands. Those that write refuse to run without an
  explicit `--confirm-*` flag. **Passing that flag is the operator's
  approval.**

| Subcommand | Effect | Approval flag |
|---|---|---|
| `decode-hash <dna\|agent\|action> <b64>` | validated b64 → 78 hex chars (prefix + DHT checksum checked) | none (read-only) |
| `write-policy` | new 0600 signer policy built from a provisioned node; `recipients: []` | none (local file only) |
| `issue-app-token` | ADMIN API `IssueAppAuthenticationToken`; raw token written to a new 0600 file, never printed | `--confirm-admin-token-issue` |
| `check-app-interfaces` | ADMIN read: lists app interfaces; exits 1 if any allows origin `*` or is not bound to an app (risk R7) | none (read-only) |
| `attach-app-interface` | ADMIN API `AttachAppInterface` for one port, bound to one installed app and to the single origin `http://localhost:<port>`; reads the result back. Refuses a port that already has an interface. Never `*`, never unbound | `--confirm-admin-interface-attach` |
| `propose-session` | authors ONE `SessionProposal` (local agent the only participant, threshold 1), signed by the agent's **existing** Lair key | `--confirm-source-chain-write` |

Nothing here creates, imports or exports Lair keys, installs apps or grants
capabilities. The only conductor configuration change is
`attach-app-interface`, which adds one interface and cannot remove or edit an
existing one. No output file is ever overwritten.

## Keystore discovery: why `lair-keystore url` "failed"

`hc sandbox generate` starts an **external** Lair server for each sandbox,
with its root at `<sandbox>/ks`:

```
lair-keystore --lair-root <sandbox>/ks server --piped
keystore: { type: lair_server, connection_url: unix://<sandbox>/ks/socket?k=… }
```

`lair-keystore url` defaults to `--lair-root .`. Run from any other
directory, it cannot find `lair-keystore-config.yaml`. The correct
invocation is:

```bash
lair-keystore --lair-root <sandbox>/ks url
```

That prints the same `connection_url` the conductor uses; the preflight
checks that the two strings are identical. The `k=` parameter is Lair's
server public key, not a secret, but avoid pasting it into logs anyway:
pass it by command substitution as shown below.

The unlock passphrase is the one you typed into `hc sandbox generate`. The
signer and the bootstrap both prompt for it on the terminal.

## Single-participant probe proposal

`get_inbox` and `get_encryption_key_bindings` both `get()` a real
`SessionProposal`, and `get_inbox` also requires the local agent to be a
participant. A fresh sandbox has only its 3 genesis records, so a proposal
must be authored first. `propose-session` builds a spec with:
`application_id = org.holochain-mpc.phase5b-read-probe`,
`protocol_id = frost-ed25519`, v1, participants `[local agent]`,
threshold 1, `max_round` 6, a random `session_id`, and a
`context_hash` bound to app/DNA/agent/session. This is a **read-probe
ceremony only**. Never use it for DKG.

The tool unlocks Lair, then authenticates to the app interface and checks
that the app ID, the app agent, and the single provisioned `mpc` cell all
match the operator-supplied `--dna-b64` / `--agent-b64`. Only then does it
sign, and it signs once. If the outcome is uncertain (timeout or transport
error), **do not retry**: first inspect the chain with
`hc client call --port <admin> dump-state <dna> <agent>` or the preflight.

## Tests

```bash
npm run test:phase5b-bootstrap   # decoding, spec, private files, confirmation gates
npm run test:phase5b-preflight   # decoder vectors cross-checked against holo_hash 0.7.1
```

Neither test contacts a conductor or Lair.

## Operator procedure

See the Phase 5B operator report delivered with this change for the exact
commands for the `mpc-phase5b` sandbox. In general: preflight →
(approve) issue token → (approve) propose session → `mpc-node provision` →
`write-policy` → start `mpc-lair-signer` → preflight with all files →
probe `get-inbox` and `get-encryption-key-bindings`.

## Limits

* The sandbox conductor, Lair and signer all run as one OS user. The
  Lair socket is `0700` for that user, so a separate "signer" account
  cannot reach it without changing the sandbox. Same-UID processes can
  impersonate one another; this is a development sandbox, not custody.
* Preflight's check that the configured Lair server is reachable does
  **not** show that it holds the agent key. Only a conductor-accepted,
  signer-produced signature shows that.
* App tokens are held in conductor memory. A conductor restart invalidates
  them, and you must re-issue (with approval).
