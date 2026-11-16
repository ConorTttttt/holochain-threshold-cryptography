# Sprint 1.8 — Proposed release-inventory change (NOT APPROVED)

**Status: REVIEW ONLY / NOT APPLIED.** This proposal identifies the intentional differences for a human release maintainer to review. `scripts/release_inventory.json` and `scripts/release_hashes.json` are unchanged on this branch. Cargo.lock is source-managed, not an approved artifact-hash override.

## Human-reviewable semantic diff

```diff
 scripts/release_inventory.json  (PROPOSED ONLY)
 workspace.members:
   "crates/mpc-dkg-worker",
+  "crates/holochain-dkg-sdk",
   "crates/mpc-vault",
 packages:
+  "holochain-dkg-sdk": {
+    "path": "crates/holochain-dkg-sdk",
+    "version": "0.1.0",
+    "dependencies": {
+      "dependencies": {
+        "holochain-mpc-core": {"path": "../mpc-core"},
+        "holochain-mpc-security": {"path": "../mpc-security"},
+        "holochain-mpc-dkg-worker": {"path": "../mpc-dkg-worker",
+          "features": ["conductor-client"], "optional": true},
+        "tokio": {"version": "1", "features": ["sync"], "optional": true}
+      },
+      "dev-dependencies": {
+        "tokio": {"version": "1", "features": ["macros", "rt"]},
+        "serde": {"workspace": true},
+        "serde_json": "1.0"
+      }
+    },
+    "manifest_sha256": "<recalculate from reviewed immutable head>"
+  }
 packages["holochain-mpc-frost-ed25519"].dependencies.dependencies:
+  "frost-core": "=3.0.0"
 packages["holochain-mpc-dkg-worker"].dependencies.dependencies.holochain_zome_types:
-  {"version": "=0.7.1", "optional": true}
+  "=0.7.1"
 cargo_lock.packages:
+  "holochain-dkg-sdk 0.1.0 (workspace)"
 cargo_lock.sha256:
-  <approved hash>
+  <recalculate from final reviewed Cargo.lock>
```

The proposal above is a **semantic review diff**, not a raw byte-for-byte JSON patch. On operator approval, the maintainer must generate the exact full JSON from the final reviewed manifest and lockfile, verify the entire diff (including `workspace.manifest_sha256`, the two affected existing manifest hashes, sorted package list, SDK manifest hash, `Cargo.lock` SHA, and any documented binary inventory changes), and explicitly approve it. Do not apply this sketch literally, especially its placeholders.

## Dependency justification and limits
- SDK workspace member `holochain-dkg-sdk 0.1.0`: thin read-only facade; native conductor interface and Tokio are opt-in via `native-holochain`. The existing `live_status` example is gated on that feature and is not a new shipped binary.
- `frost-core 3.0.0` is **already transitively locked**; adding it to the provider's direct dependencies is needed to explicitly verify each signer’s individual share before aggregation. No cryptographic version upgrade is proposed.
- `holochain_zome_types 0.7.1` is already in the graph. Changing its worker dependency from optional to direct allows default Unix native relay/signing code to compile its structured inbox wire types while leaving `conductor-client` and `lair-signer` privileged configurations optional.
- The `phase5c_live_writes` example is explicitly `required-features = ["lair-signer"]`; do not treat the example as production-authorised.
- The SDK's additional `serde` and `serde_json` dev dependencies are included as part of the SDK manifest; SDK package lock entry includes them.
- Existing WASM, DNA, hApp and version approval hashes were neither regenerated nor approved; no actual artifact replacement is proposed.

## Operator-only approval workflow
After exact-head native checks and separate security review: inspect `git diff -- Cargo.toml Cargo.lock crates/*/Cargo.toml` plus this semantic diff, calculate a read-only expected inventory using the repository's official inventory generator on an isolated copy, compare the exact output, and **only with explicit authority** record approved inventory using the documented release procedure. Repeat `python3 -I scripts/check_release.py` and preserve logs. Never change `scripts/release_hashes.json` without its separate artifact-release authority.

Until that approval, the release gate is **EXPECTED FAIL / BLOCKED** and Sprint 1.8 remains **CHANGES REQUIRED**.
