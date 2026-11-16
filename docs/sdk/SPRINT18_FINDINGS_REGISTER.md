# Sprint 1.8 — Security findings register

**CHANGES REQUIRED**. E1 source checks and imported tests are not equivalent to executed fixes. Owners are implementation/review workstreams, not GitHub assignments. This document does not close or downgrade any historic issue without passing exact-head acceptance tests.

| Finding | Severity | Source status | Dynamic evidence on final head | Remaining limitation / release impact | Owner |
| --- | --- | --- | --- | --- | --- |
| S1-H01 production custody | HIGH | OPEN; PR #9 intentionally excluded (non-production design) | NOT RUN | Keys, separate trust domain and anti-rollback independent witness unapproved; production blocker | Custody/operator |
| S1-M01 inbox conflict handling | MED | SOURCE MITIGATION in base | NOT RUN | Verify late conflicts, quota, and real conductor behaviour; release blocker | Transport/Holochain |
| S1-M02 cross-application isolation | MED | OPEN; PR #8 v2 design not deployed | NOT RUN | v1 does not provide strict generic multi-app separation; generic SDK release blocked | Architecture |
| S1-M03 lifetime quotas | MED | OPEN; PR #13 tests/docs imported | NOT RUN; ignored expiry is **not** PASS | Finite group lifetime/rekey policy required | Protocol/operator |
| S1-M04 unanimous activation | MED | SOURCE MITIGATION | NOT RUN | Local DKG completion is not group activation; E5/E6 remain required | FROST/Holochain |
| S1-L01 signing slot collisions | LOW | OPEN; PR #13 characterisation | NOT RUN | Colliding legacy sequence values; approval required for wire breaking change | Protocol |
| S1-L02 receipt identity | LOW | OPEN | NOT RUN | Receipt binding needs independent check | Transport |
| S1-L03 DKG abort accounting | LOW | SOURCE MITIGATION in base | NOT RUN | Durable abort after disconnect/fault not conductor-tested | Runtime |
| S15-L01 Signing Begin abort | LOW | SOURCE FIX checkpoint `710159af`: journal abort after deadline on preparation/encoding error | NOT RUN | New invalid-time + reopen regression pending; an abort journal storage failure still blocks release | Signing runtime |
| Fable F-8 signer after storage failure | MED | PR #15 nonce cleanup + fault tests integrated | NOT RUN | No verified fail-closed recovery until tests execute on exact head; never retry ambiguous publish | Signing/FROST |
| Fable F-9 duplicate Round-2 | MED | PR #17 relay/native tests integrated | NOT RUN | Verify uniqueness across envelopes/conductors; incomplete independent key approval | DKG |
| INV-13 independent Round-2 key approval | HIGH | **BLOCKED LIVE**: `ConductorBridge::round_two` rejects until externally authorised roster contract exists | NOT RUN | Cannot safely complete live DKG. Architecture and operator approval required; **release hard blocker** | Operator/protocol |
| FROST share-attribution | HIGH security investigation | SOURCE FIX: explicit `frost_core::verify_signature_share` before aggregate; original failed negative assertion retained | NOT RUN on integrated head; prior PR #14 test failed | Valid aggregate does not prove individual signer identities; require E3/E7 and independent cryptographic review | FROST/reviewer |

## Closure rule
Each finding must receive an immutable commit, command, exit code, captured test output and security rationale. A fail-closed block is a valid containment decision, **not** a completed live feature. No E8 signoff has been provided for Sprint 1.8. Future owner/operator decisions must distinguish the 2026-11-16 historical Fable 8dec223 review, Sprint1 baseline 899e433 review and current integrated source.
