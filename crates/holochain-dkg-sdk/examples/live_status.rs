//! Real (NOT fixture) SDK status read from an existing, disposable Holochain
//! 0.7.1 conductor + dedicated --frost-status-profile signer.
//!
//! Usage (no credentials in argv):
//!   cargo run --locked -p holochain-dkg-sdk --features native-holochain
//!     --example live_status -- /absolute/private/status-policy.json
//!     127.0.0.1:APP_PORT http://localhost:ORIGIN_PORT
//!     /absolute/private/app-token /absolute/private/signer/status.sock
//!
//! The policy JSON is the exact policy supplied to mpc-lair-signer. It is
//! independently operator-provisioned, NOT populated from the status response.
use holochain_dkg_sdk::{CeremonyId, DkgSdk, ParticipantId, SdkConfig};
use holochain_dkg_sdk::native::NativeCoordinatorBackend;
use holochain_mpc_core::SessionSpec;
use holochain_mpc_dkg_worker::connection_policy::{parse_local_app_socket, ConductorPin};
use holochain_mpc_dkg_worker::ipc::ChannelContext;
use holochain_mpc_dkg_worker::socket_signer::SignerBinding;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedStatusPolicy {
    profile: String,
    binding: SignerBinding,
    spec: SessionSpec,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: live_status POLICY_JSON APP_SOCKET ORIGIN APP_TOKEN_FILE SIGNER_SOCKET".into());
    }
    let policy: ApprovedStatusPolicy = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    if policy.profile != "mpc-frost-status-read-v1" {
        return Err("expected dedicated FROST status-only signer policy".into());
    }
    let b = policy.binding;
    let local = ParticipantId::try_from(b.agent.as_slice())?;
    let ceremony = CeremonyId::try_from(b.proposal_action.as_slice())?;
    let pin = ConductorPin {
        app_id: b.installed_app_id,
        role: b.role,
        dna_hash: b.dna_hash,
        node: ChannelContext {
            worker_agent: b.agent,
            proposal_action: b.proposal_action,
            session_id: b.session_id,
            channel_id: b.channel_id,
        },
    };
    let sdk_app = policy.spec.application_id.clone();
    let backend = NativeCoordinatorBackend::connect(
        parse_local_app_socket(&args[2])?,
        args[3].clone(),
        PathBuf::from(&args[4]),
        pin,
        PathBuf::from(&args[5]),
        policy.spec,
    ).await?;
    let sdk = DkgSdk::new(SdkConfig::new(sdk_app, local)?, backend)?;
    let observed = sdk.group_status(ceremony).await?;
    println!(
        "PASS: live signed FROST coordinator read: state={:?} accepted={}/{} ready_observed={} (local only)",
        observed.state, observed.accepted.len(), observed.participants.len(),
        observed.ready_observed,
    );
    // This line is emitted ONLY after one real signed conductor response and
    // the SDK's strict, context-bound validation succeed. No write was made.
    Ok(())
}
