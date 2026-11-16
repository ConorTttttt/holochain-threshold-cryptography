//! Optional real read-only adapter to existing signed native conductor RPC.
//! The operator must run a signer policy *explicitly allowing*
//! get_session_status for this proposal. Existing generic FROST DKG signer
//! profiles do not currently grant that read; they must not be bypassed.
use crate::{BackendFuture, CeremonyId, CoordinatorSessionStatus, DkgBackend, ParticipantId, SdkError};
use holochain_mpc_dkg_worker::conductor_client::{
    authenticate_and_pin, submit_signed_mpc_call, MpcZomeResult,
};
use holochain_mpc_dkg_worker::connection_policy::ConductorPin;
use holochain_mpc_dkg_worker::signed_call_policy::MpcCall;
use holochain_mpc_dkg_worker::signed_relay::{FreshMpcSigner, SignIntent};
use holochain_mpc_dkg_worker::socket_signer::UnixMpcSigner;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::sync::Mutex;

/// Local-only, exact-agent, exact-DNA, exact-proposal pinned backend.
/// It cannot propose, approve, run DKG, inspect native shares or sign.
pub struct NativeCoordinatorBackend {
    addr: SocketAddr,
    origin: String,
    token_path: PathBuf,
    pin: ConductorPin,
    signer: Mutex<UnixMpcSigner>,
}
impl NativeCoordinatorBackend {
    pub async fn connect(
        addr: SocketAddr,
        origin: impl Into<String>,
        token_path: PathBuf,
        pin: ConductorPin,
        signer_socket: PathBuf,
    ) -> Result<Self, SdkError> {
        let origin = origin.into();
        let signer = UnixMpcSigner::new(signer_socket, pin.clone())
            .map_err(SdkError::Backend)?;
        signer.probe().await.map_err(SdkError::Backend)?;
        authenticate_and_pin(addr, &origin, &token_path, &pin)
            .await.map_err(SdkError::Transport)?;
        Ok(Self { addr, origin, token_path, pin, signer: Mutex::new(signer) })
    }
}
impl DkgBackend for NativeCoordinatorBackend {
    fn local_identity(&self) -> Option<ParticipantId> {
        ParticipantId::try_from(self.pin.node.worker_agent.as_slice()).ok()
    }
    fn get_session_status(&self, ceremony: CeremonyId)
        -> BackendFuture<'_, CoordinatorSessionStatus> {
        Box::pin(async move {
            if ceremony.as_bytes().as_slice() != self.pin.node.proposal_action.as_slice() {
                return Err(SdkError::InvalidIdentifier("proposal differs from pinned native node"));
            }
            // Each call obtains a fresh operator-authorised nonce/signature.
            // No signer fallback, retry on ambiguity, or implicit approval.
            let signed = self.signer.lock().await
                .sign(SignIntent::ReadProbeSession).await
                .map_err(SdkError::Backend)?;
            let response = submit_signed_mpc_call(
                self.addr, &self.origin, &self.token_path,
                &self.pin, MpcCall::GetProbeSessionStatus, signed,
            ).await.map_err(SdkError::Transport)?;
            match response {
                MpcZomeResult::ProbeSession { spec, accepted, ready } => {
                    if spec.session_id != self.pin.node.session_id ||
                       !spec.contains(&self.pin.node.worker_agent) {
                        return Err(SdkError::InvalidResponse("status disagrees with pinned native node"));
                    }
                    Ok(CoordinatorSessionStatus { spec, accepted, ready_observed: ready })
                }
                _ => Err(SdkError::InvalidResponse("wrong coordinator response kind")),
            }
        })
    }
}
