# Integration-agent handoff

This SDK branch deliberately does not edit shared workspace or native signer
files owned by other sprint agents.

Apply the following workspace-only patch to root Cargo.toml:

~~~diff
 [workspace]
 members = [
   "crates/mpc-core",
   "crates/mpc-frost-ed25519",
   "crates/mpc-security",
   "crates/mpc-runtime",
   "crates/mpc-dkg-worker",
+  "crates/holochain-dkg-sdk",
   "crates/mpc-vault",
~~~

After merging, run cargo test -p holochain-dkg-sdk and
cargo test -p holochain-dkg-sdk --features native-holochain, then regenerate
Cargo.lock and update release/source inventories according to release policy.
An unmerged nested crate is not guaranteed to be independently testable via
cargo --manifest-path until included in workspace.members.

Native signer handoff: the existing FROST SignerPolicy deliberately refuses
MpcCall::GetProbeSessionStatus. The SDK's optional native backend uses this
already-wired signed read; the signer owner must separately evaluate a
read-only FROST get_session_status profile. Do not remove the explicit
approval controls or weaken the transport-probe signer boundary.

No FROST signing or group activation APIs are represented as operational.
