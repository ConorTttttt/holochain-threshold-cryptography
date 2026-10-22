# v0.4.0 Phase 5B — Read-only live Lair/conductor proof (experimental)

## Purpose

This increment bridges the gap between Phase 5A's standalone Lair signer and
Phase 4's Holochain conductor client **without starting DKG**. It ships a new
binary `mpc-lair-live-probe` that connects to a locally trusted conductor app
WebSocket and to the operator-provisioned Phase 5A signer socket. The binary
asks for a *fresh* Lair-backed signed **read** and submits that request through
`AppRequest::CallZome`. A PASS means the real conductor accepted the signature,
the pinned app/agent/DNA, the zome call, and returned a correctly decoded read.

The program supports **only** `get_inbox` and `get_encryption_key_bindings`.
It cannot publish a message, register a key, create a grant, start DKG or
create any source-chain write. It never prints inbox payloads, signed bytes,
capabilities, Lair credentials or private node keys.

## Required setup

1. Build Phase 5A with the URL conversion fix, and check its tests. Keep the
   signer process under a dedicated operating-system account and confirm
   `mpc-lair-signer` connects successfully to a separately provisioned Lair
   keystore containing **the exact Holochain agent key of the installed app**.
2. A trusted local Holochain 0.7.1 conductor must be running with the MPC hApp
   already installed, an app interface bound to loopback, and a pre-issued
   app token in an owned `0600` regular file. The WebSocket Origin must be
   allowed by that interface. **The probe never uses the admin interface.**
3. The node's `--state-dir` must be an existing private (0700) directory
   created by `mpc-node` provisioning for this ceremony. Its stored agent,
   proposal action, session and channel must match the signer policy exactly.
   The proposal must already be visible to the local conductor and contain
   the local agent; an accepted proposal is required for future DKG but not
   necessarily for these read-only operations.
4. Start `mpc-lair-signer` following `V040_LAIR_SIGNER_PHASE5A.md`. For these
   reads, use `"recipients": []` in its `0600` policy file; this forbids all
   remote outbound sends while testing initial signing.
5. Test static compilation and the read-only operation allowlist:

   ```bash
   npm run check:holochain-versions
   python3 scripts/check_release.py
   npm run test:signer-phase5b-static
   npm run test:signer-phase5
   ```

## Execute a real signed read

Start a **new** terminal while the Phase 5A signer and Holochain conductor
are already running. Replace placeholders with values verified from your
installed app. `DNA_39_BYTES_HEX` is the raw 39-byte DNA hash represented by
exactly 78 hexadecimal characters. Do not pass private keys or capabilities
on the command line.

```bash
cargo run -p holochain-mpc-dkg-worker --features conductor-client \
  --bin mpc-lair-live-probe -- \
  --state-dir /absolute/private/node-state \
  --app-socket 127.0.0.1:PORT \
  --origin http://localhost:PORT \
  --app-token-file /absolute/private/app-token \
  --installed-app-id YOUR_APP_ID \
  --dna-hex DNA_39_BYTES_HEX \
  --signer-socket /absolute/private/signer/signer.sock \
  --operation get-inbox
```

Then repeat with `--operation get-encryption-key-bindings`. Either result
may be empty and still demonstrate a successful authenticated signed read.

**Expected outcomes:** The probe first checks socket ownership and the local
signer's peer UID, then authenticates against the exact app and cell, obtains
one signed call and submits it to the conductor. The final PASS line appears
only on an accepted and correctly decoded zome response. A FAIL line means
*some* precondition, signature, grant, expiry or zome call was rejected;
this does not imply the cryptography or conductor is broken. Do not weaken
cell checks, grant policy or nonce validation to make the test pass.

## Negative verification (required before Phase 6)

* Mismatched installed-app ID, DNA or agent must fail before signing.
* Missing, incorrect, insecure or symlinked signer socket and app token must fail.
* Unrecognised and write-capable `--operation` values must fail.
* A signer policy for a different proposal/session must refuse the request.
* An unavailable or incorrect Lair identity must never produce a PASS.
* A genuine conductor should reject an expired signature or one signed by an
  unrelated agent. These conductor cases are **manual live tests not covered
  by this patch**.

## Security / evidence boundary

Static tests only verify the CLI operation allowlist; they do not stand in for
a real signer or conductor. The new live probe doesn't create Lair keys,
issue cap grants, operate an admin WebSocket, or spin up a conductor itself.
An accepted signed **read** does not prove `send_protocol_message` and remote
capability-grant flow works, nor that a three-node ceremony completes.

Lair IPC availability depends on the conductor's deployment. Some setups use
in-process Lair rather than a compatible standalone IPC endpoint; in that
case the signer must be redesigned to use the supported key custody interface
instead of exporting an agent key.

Next: Phase 5C tests real grant provisioning and one signed, encrypted,
recipient-authorized message with three independent conductors, followed by
Phase 6 autonomous DKG and post-DKG signing-key persistence.
