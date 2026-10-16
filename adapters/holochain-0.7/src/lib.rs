//! Small HDK 0.7 adapter: authenticated caller identity only.
//! This crate does NOT configure capability grants, send messages, persist
//! state, or implement cryptographic MPC. Those belong to the owning hApp.
use hdk::prelude::*;
use holochain_mpc_core::{Envelope, SessionSpec};

/// Check that the *authenticated* caller, not an untrusted user-provided
/// string, matches the sender and that the message targets this agent.
///
/// The enclosing coordinator zome MUST independently:
/// - provision restrictive capability grants,
/// - load a locally accepted session manifest, not just an untrusted proposal,
/// - atomically persist the replay ledger before executing protocol effects,
/// - use an authenticated confidential transport for any secret payload.
pub fn authenticate_incoming(
    session: &SessionSpec,
    message: &Envelope,
) -> ExternResult<()> {
    let caller = call_info()?.provenance;
    let local = agent_info()?.agent_initial_pubkey;
    message
        .validate_received(session, local.get_raw_39(), caller.get_raw_39())
        .map_err(|error| wasm_error!(WasmErrorInner::Guest(error.to_string())))
}

/// Useful when recording a session proposal: prevents a nonmember from
/// proposing a session as themselves. Does not establish consent by others.
pub fn ensure_local_member(session: &SessionSpec) -> ExternResult<()> {
    session.validate().map_err(|error| {
        wasm_error!(WasmErrorInner::Guest(error.to_string()))
    })?;
    let local = agent_info()?.agent_initial_pubkey;
    if !session.contains(local.get_raw_39()) {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Local agent is not a participant".to_string()
        )));
    }
    Ok(())
}
