# v0.4.0 release hardening

27 October 2026 (Europe/London). **Result:** `npm run check:release` passes on
the development host: a from-scratch offline rebuild of both zomes, the
`.dna` and the `.happ` is byte-identical to the 17 and 22 October artifacts,
all 11 binaries print a non-production notice, and 127 native tests pass.
Remaining gaps are listed by risk ID below. **Development evidence, not
production custody, not an independent audit.**

## 1. Release check (`npm run check:release`)

`scripts/release_check.py` runs, with `--offline --locked` on every cargo
command and nothing that touches a conductor, Lair or the network:

| Step | What it proves |
|---|---|
| `validator-tests` | *(Stage 2B)* the release validator's own unit tests (`npm run test:release-tools`) |
| `manifest`, `versions` | `check_release.py` (since Stage 2B: against the approved inventory `scripts/release_inventory.json`) and `check_holochain_versions.py` |
| `wasm-build` | `cargo build --release --target wasm32-unknown-unknown` of both zomes into a **fresh, empty** target dir (about 30 s), so no cached artifact can satisfy the comparison |
| `wasm-imports` | `check_wasm_imports.py` on those fresh files (the brief's order puts this before the build; it needs the build) |
| `pack` | `hc dna pack` and `hc app pack` from staged manifests that point at the fresh WASM |
| `identity` | SHA-256 of both WASM files, the `.dna` and the `.happ`, and the DNA hash, against `scripts/release_hashes.json` |
| `help-notices` | every `bin` target in the workspace (from `cargo metadata`) is in the approved binary inventory; each exits 0 on `--help` and `-h` and prints the exact notice of `notice.rs`; `mpc-custody` and `mpc-vault` also print the custody warning (Stage 2B, see [V040_STAGE2B_RELEASE_VALIDATION.md](V040_STAGE2B_RELEASE_VALIDATION.md)) |
| `native` | every suite in `npm run test:native` (expanded from `package.json`, so the list lives in one place) |
| `lockfile` | `Cargo.lock` unchanged by the run |

Exit status: 0 pass, 1 any failure, 2 a step was skipped (`--skip-native`).
`--record --confirm-record` rewrites the hash file from a fresh build; it is
for an operator after reviewing a coordinator change.

Recorded values (rustc 1.99.0 `b940084d7`, `holochain_cli 0.7.0`):

| Artifact | SHA-256 |
|---|---|
| `mpc_integrity.wasm` | `2d6aa14170e4e1d40a78fc270d89a7534e943813b18811a66a84c88c6bb4ffdb` |
| `mpc.wasm` (coordinator) | `432d4d7d2e0244cad46c1c747f4fd2bdb2f9b15cf510218dd4a4b6ef8ee19614` |
| `mpc.dna` | `7f77af71ba633536139f77702de1d8e74b77b8f437f33bf9328ec3856d7f7452` |
| `holochain-mpc-core.happ` | `38efb4a9bcc3accd2eff2da0fbf451c8f1d981b366819d00c1eac52655bac1e5` |
| DNA hash | `uhC0kp2jDNMx69W8JpT4jqkZR5XtHBKwdKcWneyb_judb2zoP6Mwu` |

These were **not** copied from a document (no hashes were recorded before).
They come from a fresh build in a copy of the tree under a different path, and
they equal the SHA-256 of the existing in-tree artifacts and the deployed 5C DNA
hash. The integrity WASM and DNA hash are frozen (L2). The other three change
with any coordinator change, so merging the Agent 1 coordinator patch makes the
`identity` step fail until an operator re-records. A tampered recorded hash was
confirmed to fail the step, then restored.

Limits: the build is reproducible on this host and toolchain only. It is not
signed, attested or cross-checked on a second machine, and the compiler and
`hc` are trusted as installed (R9). `native` reuses the cached test build, so
"clean state" applies to the WASM, `.dna` and `.happ`.

Observed run (`target/check-release.out`): all steps PASS; `native` 20 result
groups, 127 passed, 0 failed. Also run: `--features lair-signer --lib --bins`
(57 lib, 8 bootstrap, 6 provision, 2 probe, 1 transport-probe, all passing).

## 2. Input and protocol validation

Inventory of external parsers (read from source). `deny` = `deny_unknown_fields`.

| Parser | Size bound | Version | Unknown fields |
|---|---|---|---|
| IPC frame `AuthFrame<Command>` (`node_service.rs`, `ipc.rs`) | 512 KiB line, read with `take` before allocation; unterminated line refused | `version == 1` | deny on frame, context, `Reply`, struct commands; **ignored on unit commands** (serde limitation, gap G1) |
| Signer socket request and response (`socket_signer.rs`) | 384 KiB / 512 KiB | `version == 1` | deny |
| Signing plan (`signing.rs`) | message 8 KiB, compact plan 48 KiB, file 64 KiB | `schema == 1` | deny on plan; **ignored on the nested descriptor and spec** (G2) |
| Group descriptor file (`node_service.rs`) | 64 KiB | none | **ignored** (G2); digest is over a re-serialisation |
| Node config | 8 KiB | `schema == 1` | deny |
| Inbox `Envelope` (`mpc-core`) | payload 64 KiB; hash checked | `wire_version`, `protocol_version` vs spec | **ignored** (G3) |
| `SealedPacket` | ciphertext 16 B to 48 KiB | `version == 1` | **ignored** (G3) |
| `BoundBroadcastV2` | announcement 8 KiB | `version == 2` | **ignored** (G3) |
| FROST `Frame` and `Message` | inside the envelope bound | none of their own (envelope `protocol_version`) | **ignored** (G3) |
| Provisioning files, offers, ceremony record | 64 KiB, mode checks | `schema` | deny |
| Signed zome-call policy (`signed_call_policy.rs`) | 128 KiB send payload | n/a | payload structs ignore extras by design |

Tests added (all passing, inside `npm run check:release`):

- `crates/mpc-security/tests/wire_validation.rs` (5): envelope wire version,
  protocol, session and the 64 KiB boundary; sealed-packet version, key and
  size bounds; broadcast version, ceremony binding, garbage payloads and wrong
  round; announcement bounds; `known_gap_unknown_fields_are_ignored_by_wire_types`.
- `crates/mpc-dkg-worker/tests/input_validation.rs` (6): IPC frame unknown
  fields, short tag and wrong version (and that refusals do not advance the
  sequence); command unknown ops; signing-plan schema, operation id, message,
  roster, threshold, descriptor fields; plan JSON unknown or missing fields;
  `known_gap_unit_commands_ignore_unknown_fields`;
  `known_gap_descriptor_unknown_fields_are_ignored_but_cannot_change_the_digest`.

These tests pass against the unmodified code: they pin existing behaviour and
document gaps, they did not catch a regression. The `known_gap_*` tests assert
today's behaviour and must be flipped when a gap is fixed.

Gaps (nothing fixed; product code is outside this brief):

- **G1.** `Command::Attest` and `Command::Finalize` accept extra keys. The HMAC
  is over the re-serialised body, so extras are dropped before authentication.
- **G2.** The group descriptor and session spec ignore unknown fields. Digests
  are unaffected (tested for the descriptor).
- **G3.** `Envelope`, `SealedPacket`, `BoundBroadcastV2`, `Frame` and `Message`
  ignore unknown fields. Whether the same re-serialisation protects every use
  of these was not checked. Adding `deny_unknown_fields` to stored or deployed
  wire types needs a compatibility decision.
- **G4.** The relay refuses an inbox above `MAX_INBOX = 4096` (`relay.rs`),
  while the coordinator allows 16,384 messages per session. A member who
  delivers more than 4,096 messages to one node stops that node's relay.
  Related to R11.
- **G5.** The signed-call policy admits a send payload of 128 KiB; the envelope
  limit is 64 KiB. The coordinator refuses the excess, so this fails closed,
  later than needed.
- **Not tested.** The oversized-IPC-line path in `serve_connection` (needs a
  live process and a socket); the conductor response wires in
  `conductor_client.rs` (they come from the pinned conductor and need a
  conductor to produce); coordinator inputs (need Sweettest; not run here).
  Whether `read_config` and the provisioning offers bound their input before
  parsing beyond the file-size checks above was not examined.

## 3. Supply chain (R9)

`cargo audit --no-fetch` offline against the local database (git commit of 21
October 2026, 1,348 advisories): 10 vulnerabilities, 9 warnings. Same 10 as the
handover. Shipped binaries are the workspace crates other than `mpc` and
`mpc_integrity` (normal edges, `--all-features`); the zomes ship as WASM.
Method: `cargo tree --locked -e normal,build` sets for each target, then
`-i` for each advisory crate.

| Advisory | Crate | In shipped native binaries | In zome WASM | Where it comes from |
|---|---|---|---|---|
| RUSTSEC-2026-0185, -0338, -0339, -0340, -0342 | quinn-proto 0.11.14 | no | no | test-only: dev-dependency `holochain` |
| RUSTSEC-2026-0344 | ruzstd 0.8.3 | no | no | test-only: dev-dependency `holochain` |
| RUSTSEC-2026-0383 | webpki-root-certs 1.0.9 | no | no | not found in any shipped set; I could not place it |
| RUSTSEC-2026-0367, -0368, -0369 | zip 8.6.0 | build script only | no | build-dependency of `libsodium-sys-stable` (I did not trace which crate pulls that in); compiled and run at build time, not linked |

Warnings: `lru 0.17.0` (RUSTSEC-2026-0253, unsound) **is linked into the
`lair-signer`-feature binaries** (`mpc-lair-signer`, `mpc-sign`, the
bootstrap, provisioning and probe tools) through `lair_keystore_api 0.7.1`.
`inout 0.2.3` (yanked) is in the native graph. `paste` and `proc-macro-error`
are compile-time macros. `ansi_term`, `atomic-polyfill`, `proc-macro-error2`,
`rustls-pemfile` and `memmap2` are not in a shipped set.

This agrees with the handover's "not in the shipped binaries" for all 10
vulnerabilities, with two caveats: `webpki-root-certs` is unplaced, and the
`holochain` conductor binary, which is not built here, probably carries the
same `quinn-proto` line (unverified). `lru` is new information for R9.
`lru` and `inout` are pinned by Holochain 0.7.1's Lair family, so a fix is an
upstream Holochain/Lair release, not something to bump here.

- **Version bumps.** None made. No patch bump of a direct non-Holochain
  dependency was proposed: I did not examine them.
- **Toolchain provenance.** There is no `rust-toolchain` file, so the build
  uses whatever `stable` resolves to. This host: `rustc 1.99.0 (b940084d7
  2026-09-28)`, `cargo 1.99.0`, `holochain_cli 0.7.0`, `cargo-audit 0.22.2`;
  rustup also holds 1.95.0, 1.96.1 and 1.98.1. None is hash-pinned or attested.
  `release_hashes.json` records the `rustc`, `cargo` and `hc` strings, and the
  `identity` step prints a note when `rustc` differs. Proposal for the
  operator: add a `rust-toolchain.toml` pinning 1.99.0 (a repo file outside this
  brief) and record the toolchain archive hashes.

## 4. R7: app interfaces

`allowed_origins: "*"` and `installed_app_id: null` came from outside the
repository: `hc sandbox generate --run=<ports>` and the persistent 5C
conductors. No Rust code attached interfaces, so there was nothing to edit in
`conductor_client.rs` (which already requires loopback, a 0600 token file and a
matching app id, role, agent and DNA).

Added to `mpc-phase5b-bootstrap` (provisioning code):

- `check-app-interfaces --admin-port P [--installed-app-id A]`: read-only; lists
  interfaces and exits 1 if any allows `*` or is unbound or bound to another app.
- `attach-app-interface --admin-port P --installed-app-id A --app-port N
  --confirm-admin-interface-attach`: attaches one loopback interface bound to
  `A` and to the single origin `http://localhost:N` (the origin the Phase 5B/5C
  tools already send), refuses an occupied port, and reads the result back.

Unit tests cover the request shape (no wildcard, no bind address, bad ids and
ports refused), the finding rules and the confirmation refusal.

**Live check on a disposable conductor** (one `hc sandbox` conductor with a
local bootstrap server, a random throwaway passphrase piped on stdin, a temp
directory under `/tmp` that the script created and removed; no persistent
state, no DKG). Note this used its own directory, not
`~/mpc-phase6-rehearsal`. Observed:

- `check-app-interfaces` on the `hc sandbox` interface: both findings, exit 1.
- `attach-app-interface` without the flag: refused. With it: attached and read
  back. A second attach on the same port: refused.
- WebSocket upgrade by `Origin`: the wildcard interface accepted
  `http://localhost:<port>`, `http://evil.example` and `http://localhost:1`
  (101). The bound interface accepted only its own origin (101) and answered
  400 to the other two and to a missing `Origin`.
- Not tested: the app-binding refusal of a token issued for another app (the
  throwaway conductor had one app).

Not done: the persistent 5C conductors still have wildcard interfaces. The
operator runs `check-app-interfaces` against them (read-only), attaches bound
interfaces, and repoints the tools. Whether Holochain 0.7.1 can detach the old
interface was not checked. `scripts/phase6_rehearsal.py` still uses
`hc sandbox --run`; it belongs to another brief.

## 5. Non-production warnings

Added to `README.md` (top banner), the new root `SECURITY.md` (status, reasons
and six proposed removal criteria for the operator to confirm) and
`docs/SECURITY.md`. All 11 binaries print the notice for `--help`/`-h` through
`notice::exit_on_help`, which runs before any stdin, file or network access;
`release_check.py` asserts it for every `[[bin]]`. The notice has no effect on
other invocations.
*Stage 2B:* `mpc-custody` and `mpc-vault`, which were outside that list (I-2),
now print the same notice plus "Development build. Not production custody. Do not use
with real funds.", and the check covers all 13 workspace binaries.

## 6. Remaining gaps by risk ID

| ID | Remaining after this work |
|---|---|
| R1 | Unchanged: grants are function-scoped (DNA design) |
| R2 | Unchanged |
| R3 | Unchanged: same-UID custody, no anti-rollback |
| R4 | Unchanged: no 5C-B audit output on the persistent cells. The recorded hashes now let an operator compare the installed WASM, but no one has |
| R5 | Unchanged |
| R6 | Unchanged: the tree is uncommitted. This work is a separate copy |
| R7 | Tooling and a live check exist; persistent conductors still wildcard; token-binding refusal untested |
| R8 | No such row in the handover |
| R9 | 10 advisories test-only or build-only (one unplaced); `lru` ships; toolchain unpinned and unattested |
| R10 | Unchanged: the 5C cells still run the 17 October coordinator |
| R11 | Unchanged; G4 adds a relay-side limit to the same availability question |
| L1 to L4 | Unchanged |
