# Phase 5C-B — grant revocation integrity fix (Holochain 0.7.1)

## Change

`FlatOp::CreateRecord(OpRecord::DeleteEntry)` previously rejected **every**
entry deletion before the more selective `FlatOp::Delete` rule could allow
capability grant revocation. Both paths now run one shared validator that:

* Fetches the original action via `must_get_action` (no private grant plaintext required).
* Requires original action **author** == deletion **author**.
* Requires the original action to be `ActionData::Create` with `EntryType::CapGrant`.
* Rejects deletion of application entries, capability claims, agent entries,
  updated grants, and unrelated records. MPC links stay append-only.

## Run in Holonix

```bash
# From the repository root, with `nix develop` active
python3 scripts/check_release.py
npm run check:holochain-versions
npm run build:happ
cargo test -p mpc --test revoke_cap_grant -- --nocapture
npm run test:native
npm run test:sweettest
```

The `build:happ` command must retain the Rust 1.96 WASM flag
`-C link-arg=--allow-undefined` in its `build:zomes` step.

## Additional Phase 5C-B test update required

If `crates/mpc-dkg-worker/tests/capability_provisioning.rs` still expects
revocation to fail, change that assertion **on your branch**: it must now
expect an accepted revocation action and prove that the previously valid
secret fails with Unauthorized. This file was not included in the supplied
Phase 5B source snapshot, so this patch does not modify it blindly.

The new `revoke_cap_grant` Sweettest demonstrates that a real Holochain
conductor accepts and records a revocation, but does **not by itself** prove
that a previously accepted remote call is rejected afterwards. Before live
provisioning, run the updated two-conductor test with the old secret after
revocation and assert explicit `Unauthorized` (not a generic error).

## Operational boundary

This patch modifies **integrity WASM**, so the packed DNA hash changes.
Use the new DNA only in a **new** Phase 5C-B sandbox. Do not reinstall,
replace, or reset the proven Phase 5B/5C-A conductor or its agent identity.
No live chain writes are performed by applying this patch or running builds;
Sweettest writes occur only in ephemeral test conductors.

Grant revocation removes authorisation, not previously delivered private
messages or copies of grant secrets already held by other agents. The grant
scope is still function/assignee based, not truly per-session.
