# v0.4.0 Phase 5A — Lair-backed local signer (experimental)

This is the **first Phase 5 increment**, not the autonomous 3-node ceremony or
production custody milestone. It adds a real signer daemon to the Phase 4
Unix-socket signer client. Phase 5B should test live conductor-signed calls,
including real granted recipient remote capabilities, and then an autonomous
three-conductor DKG without a centrally trusted test runner.

## Threat model

* Only a **pre-existing, separately operated Lair keystore** containing the
  exact pinned Holochain agent key is allowed to sign. This signer does not
  create or export agent keys. Holochain 0.7.1 `ZomeCallParams` are serialized
  canonically; the agent signs the **hash** returned by `serialize_and_hash`,
  not arbitrary JSON or raw serialized bytes.
* The socket is in an operator-owned **0700 directory**, with an operator-owned
  **0600 socket**. Peers are checked using Linux SO_PEERCRED, but a compromised
  same-UID process can impersonate either side. Run the whole node under a
  dedicated OS account. This is not process-code attestation.
* A **0600 regular policy file** pins app ID, `mpc` role, 39-byte agent/DNA and
  proposal hashes, session ID and channel ID. The signer refuses other apps,
  cells, recipients, key registrations, and all other zome functions.
* The client does not transmit recipient capability secrets. The signer must
  load them from a separately provisioned private policy file. Do NOT commit
  policy files containing capability secrets. Never print them or put them in
  command arguments. No recipient secret means outbound calls are refused.
* Ed25519 signatures use fresh OS CSPRNG nonces in Holochain call params and a
  30-second expiry. Holochain's conductor enforces the signature, nonce replay
  rules, app grant and expiry at the application boundary. **Socket requests
  themselves do not have durable replay admission**. Operators must not reuse
  potentially committed authorizations after uncertain RPC failures.
* Neither this program nor its unit tests prove a genuine conductor accepts
  signed calls or that Lair is reachable through a standalone IPC URL. Some
  conductors operate an **in-process Lair keystore**; those deployments need a
  different signing integration and must not expose agent private keys.
* The signing policy file is a trusted configuration file. Secure provisioning,
  capability rotation/revocation, metadata rollback detection and OS hardening
  are outside this increment. Do not use this prototype with valuable keys.

## Source

* `crates/mpc-dkg-worker/src/lair_signer.rs`: strict request policy, private
  policy reader, ceremony pinning, recipient capabilities, fresh nonce creation,
  Lair-backed `ZomeCallParamsSigned` construction, policy tests.
* `crates/mpc-dkg-worker/src/lair_signer_main.rs`: Lair IPC unlock prompt,
  private socket listener, same-UID peer checking, one request per connection,
  bounded requests/replies/timeouts. Errors never log payload or secrets.
* Uses the **unchanged Phase 4 `SignerRequest` and `SignerResponse` wire format**.

## Setup prerequisites

1. Build Phase 5 on your **patched and successfully tested Phase 4** source.
2. Start an independently provisioned Lair keystore that contains the
   installed Holochain agent's Ed25519 signing key and exposes a local Lair IPC
   connection URL (`lair-keystore url`, if supported by your deployment).
3. Save an operator-reviewed JSON policy as an absolute owned **0600** file,
   with *exactly* this object structure:

   ```json
   {
     "binding": {
       "installed_app_id": "<the-installed-app-id>",
       "role": "mpc",
       "dna_hash": ["<39 numeric byte values>"],
       "agent": ["<39 numeric byte values>"],
       "proposal_action": ["<39 numeric byte values>"],
       "session_id": ["<32 numeric byte values>"],
       "channel_id": ["<32 numeric byte values>"]
     },
     "recipients": [
       {
         "agent": ["<the recipient agent's 39 numeric bytes>"],
         "cap_secret": "<use the JSON encoding of the Holochain CapSecret provided by the recipient>"
       }
     ],
     "spec": "<the full SessionSpec of the conductor-verified ceremony record>"
   }
   ```

   **The angle-bracket placeholders are illustrative, not valid JSON values
   for the byte-array fields.** Byte arrays must contain integers 0–255.
   The `cap_secret` field must be serialized as Holochain 0.7.1's `CapSecret`
   type (not a quoted display string). The exact recipient capability values
   must be independently verified and granted by each recipient using the
   coordinator's grant API.

   **`spec` (security-review B2 fix).** `SendMessage` signs neither the
   protocol nor the session, so the signer pins the proposal's full
   `SessionSpec` and only authorises an envelope equal to the one the
   coordinator rebuilds from it. The spec must be a valid FROST ceremony for
   the pinned proposal and session, and every recipient must be a member.
   Without `spec` a policy is **read-only**: it may carry no recipients, and
   key registration and sends are refused. Policies written before this fix
   (including the 17 October 5C-B policies) therefore lose send/registration
   until regenerated with `mpc-phase5c-provision write-policy`, which copies
   the spec from the conductor-verified `ceremony.json`. Use `"recipients": []`
   with no `spec` for read-only testing.
4. Create a private directory for the Unix socket:

   ```bash
   mkdir -m 700 -p "$HOME/.local/state/mpc-private-signer"
   chmod 700 "$HOME/.local/state/mpc-private-signer"
   chmod 600 /absolute/path/to/operator-reviewed-policy.json
   ```

   The policy file's *parent directory* should also be private.

5. In Holonix compile and test:

   ```bash
   npm run check:holochain-versions
   python3 scripts/check_release.py
   npm run test:lair-signer-policy
   npm run test:signer-socket
   npm run build:lair-signer
   npm run build:relay-service
   npm run test:native
   npm run test:sweettest
   ```

6. Run the signer as the same dedicated OS user as `mpc-relay-service`:

   ```bash
   cargo run -p holochain-mpc-dkg-worker --features lair-signer \
     --bin mpc-lair-signer -- \
     --policy-file /absolute/path/to/operator-reviewed-policy.json \
     --signer-socket "$HOME/.local/state/mpc-private-signer/sign.sock" \
     --lair-url 'unix:///<the-url-from-your-Lair-instance>'
   ```

   Supply the unlock passphrase through the terminal prompt, never via CLI,
   environment variables, shell history or checked-in secrets. The signer
   deliberately refuses to overwrite a preexisting socket path. To clean a
   stale socket after an unclean shutdown, check no signer is running and
   inspect the file manually before removal.

7. Point the Phase 4 `mpc-relay-service --signer-socket` option at the same
   absolute path. The relay continues to use its own restricted app token,
   authenticated conductor preflight, node service and ceremony specification.

## Validation boundary

The new unit tests prove signed-call *intent construction*, exact ceremony
binding, function allowlisting, required fields and fresh nonce creation.
They do **not** exercise a running Lair instance or a conductor. The next
required evidence is a real signing fixture validating Ed25519 signatures
against an app-interface zome call and a live three-conductor run.


## Separate Phase 5C-C probe profile

The default signer still uses the FROST-only policy above. A separately
approved `--probe-profile` mode reads a different strict policy schema and
serves only a pinned `mpc-transport-probe` v1 proposal. It requires independent
probe capability provisioning and never imports an existing FROST policy as
a fallback. See `V040_PHASE5C_C_TRANSPORT_PROBE.md`. This does not authorize
starting a signer, accessing live Lair state or changing existing policies.
