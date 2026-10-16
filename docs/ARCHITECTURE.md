# v0.2 architecture and trust boundaries

```text
Application UI / native controller (trusted on each participant's machine)
        │ local zome call
        ▼
Coordinator zome `mpc` (HDK 0.7)
  • propose → accept → check all-member consent
  • assign restricted capability grants
  • send/receive remote call, authenticate caller provenance
  • private append-only inbound journal, logical replay deduplication
        │ public entries/links                │ private entries
        ▼                                     ▼
Integrity zome `mpc_integrity`              Local source chain
  • immutable public entries               InboxEvent { proposal, envelope }
  • proposal-author membership
  • acceptance-author membership
  • link base/target integrity
        │
        ▼
Public Holochain DHT
  SessionProposal, SessionAcceptance, OutputProposal (unverified)

future v0.3: secure *local* cryptographic provider / transactional state store
```

## Data model

| Entry | Visibility | Checks |
| --- | --- | --- |
| SessionProposal | Public | `SessionSpec` structure, 39-byte valid Holochain keys, membership |
| SessionAcceptance | Public | exact proposal hash, session ID, author membership |
| OutputProposal | Public | protocol/session binding, artifact size, author membership |
| InboxEvent | Private | validated by recipient coordinator; not DHT-readable |

Links `SessionToAcceptances`, `SessionToOutputs`, and `AgentToSessions`
are append-only. Each link must target an appropriate entry type and follow
the link author's actual signed identity.

## Delivery lifecycle

1. A member creates a proposal with a unique `session_id` and
   `context_hash` bound to the application operation.
2. Every named participant independently accepts the exact proposal action.
   A threshold of 2-of-3 **does not mean** only two members consent to creation.
3. Each recipient creates an assigned capability grant permitting only the
   named peer pubkeys to invoke `receive_protocol_message`.
4. Capability secrets are provisioned out of band. The demo's Sweettest
   passes Bob's secret directly to Alice as a fixture; this is **not** a
   production secret-exchange protocol.
5. Alice constructs the versioned `Envelope`, makes `call_remote`, and
   provides Bob's capability secret.
6. Bob checks local session acceptance, observes all acceptances, confirms
   `call_info()?.provenance` equals envelope sender, validates payload limits,
   and appends an `InboxEvent` privately before acknowledging.
7. If Alice's ACK is lost, she re-sends with the SAME round/sequence. Bob
   returns `AlreadyStored` if the matching event is found.
8. A local cryptographic plugin may later consume the logical inbox but
   **must not execute non-repeatable cryptographic effects** until its state
   and replay cursor live in a transactional host-side store.

## Failure modes

- Peer offline: `call_remote` returns a network failure. Sender manually
  retries with the same message ID when reachable; there is no autosend queue.
- DHT convergence delay: receiver may temporarily see fewer acceptances and
  reject traffic; sender must retry after gossip convergence.
- Concurrent duplicate deliveries: two writes are possible after a racing
  read; `get_inbox` reduces identical events to one logical message and rejects
  conflicting duplicates. This is NOT atomic
  uniqueness or exactly-once execution.
- Crash after private write but before response: send retries are idempotent
  when the previous journal event is recovered. Durability relies on the
  conductor's local source-chain storage and requires crash/restart testing.
- Malicious/compromised local conductor: this prototype cannot ensure
  protection of its own private entries, grant secrets, or keys.
- Network partition: no consensus, no global ordering, no guaranteed
  readiness; DHT observations can differ across participants.

## Protocol plugin contract (future)

Do not run cryptography inside the coordinator's receive function. A future
`MpcProvider` must validate its own transcript rounds, bind to the **proposal
action hash** as well as `session_id`, enforce fresh nonces, persist its state
transition and processed-message cursor atomically, and reject malformed,
equivocating and out-of-order messages according to its own protocol.

## v0.3 native crypto boundary

```
Native application controller (non-WASM, per participating device)
  Binding ── DkgParty ── KeyPackage (private)
               │              │
          Frame/Envelope     Signer (single-use nonce)
               │              │
            HDK 0.7        SignatureShare
          remote call           │
               │           aggregate + verify
      authenticated inbox       │
               └───────────────┘
             SignedArtifact (public)
```

See `docs/FROST_PROVIDER.md`. No changes to v0.2's private-inbox and public
integrity validation guarantees. Crypto is done in a native local process,
not in the integrity `validate` callback.
