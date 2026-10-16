# Embedding Holochain MPC Core v0.2 into an application

v0.2 provides a self-contained `mpc` DNA role and portable Rust core.

## Integration choices

**Option A — separate DNA role:** install this package's `dnas/mpc` DNA alongside
an application's existing DNA. Use a coordinator cross-DNA call to propose a
session with the application-specific `context_hash`. This isolates the schema
but requires explicit cross-DNA logic and separate acceptance/capabilities.

**Option B — integrate the zome pair:** copy/use `mpc_integrity` and `mpc`
inside your app's DNA and register both in the DNA manifest. The coordinator
must depend on the integrity zome. Use the same Cargo crates pinned to the
exact v0.2 release commit after verification.

## Application contract

1. Serialize the operation description canonically and hash it into
   `context_hash`. A server-provided opaque hash without a locally verified
   operation does **not** establish informed participant consent.
2. Generate a collision-resistant, unique session identifier. Bind future
   protocol transcripts to the **proposal action hash**, not only the 32-byte
   session ID, to avoid accidental aliasing across separate proposals.
3. Set `application_id` to a unique namespace and `protocol_id`/version to
   an explicitly selected cryptographic provider (or `opaque-demo` for tests).
4. Supply sorted, unique raw 39-byte `AgentPubKey` encodings.
5. Call `propose_session` then require an `accept_session` from each named
   member. `get_session_status.ready_observed` is a network observation, not
   distributed consensus or proof of malicious-agent cooperation.
6. Each participant calls `prepare_inbox_grant`, provisions that secret to
   approved participants using an already trusted encrypted channel, and uses
   the recipient's secret in `send_protocol_message`.
7. Each receiver stores inbound messages privately. `get_inbox` reads logical
   (deduplicated) envelope entries; the application must not treat these as
   processed MPC protocol events until a proper transactional provider exists.
8. Optionally publish a commitment with `publish_result_commitment`. Neither
   an empty verification artifact nor a nonempty arbitrary artifact is a proof.

## API wire contracts

See exported Rust structs in coordinator `src/lib.rs` for full types:
`SessionStatus`, `PreparedGrant`, `IncomingMessage`, `SendMessage`,
`DeliveryReceipt`, `ReceiptStatus`, `PublishResult`.

The core's opaque `Envelope` and `SessionSpec` are unchanged from v0.1. Session
proposals, acceptances and commitments are public; `InboxEvent` is private.

## Not included

A UI, cap-secret provisioning UI, a secure cryptographic engine, outbox queue,
retransmission scheduler, AEAD session key management, multi-DNA bridge code,
or integration with wallet/governance/identity applications.
