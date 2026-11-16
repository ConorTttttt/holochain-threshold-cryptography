//! Live read-only adapter to a pinned Holochain coordinator using a distinct
//! opt-in FROST ceremony-status signing profile. No fallback to the transport
//! probe signer or broader DKG/signing authority is permitted.
use crate::{BackendFuture, CeremonyId, CoordinatorSessionStatus, DkgBackend, ParticipantId, SdkError};
use holochain_mpc_core::SessionSpec;
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

/// Read-only native backend, pinned to the *entire* approved SessionProposal:
/// application context digest, FROST protocol, roster, threshold, rounds,
/// session id, exact proposal action, app id, agent, cell role and DNA.
///
/// The authorised signer must run with --frost-status-profile and a matching
/// operator-approved policy. Probe and DKG signer profiles cannot grant this
/// distinct intent. No SDK component receives worker secrets or Lair keys.
pub struct NativeCoordinatorBackend {
    addr: SocketAddr,
    origin: String,
    token_path: PathBuf,
    pin: ConductorPin,
    expected_spec: SessionSpec,
    signer: Mutex<UnixMpcSigner>,
}

fn validate_approved_spec(pin: &ConductorPin, expected: &SessionSpec) -> Result<(), SdkError> {
    pin.node.validate().map_err(|_| SdkError::InvalidConfiguration("invalid native ceremony pin"))?;
    expected.validate().map_err(|_| SdkError::InvalidConfiguration("invalid approved session spec"))?;
    if pin.role != "mpc" || pin.app_id.is_empty() || pin.dna_hash.len() != 39 ||
       pin.dna_hash.iter().all(|b| *b == 0) ||
       expected.protocol_id != "frost-ed25519" || expected.protocol_version != 1 ||
       expected.threshold < 2 || expected.participants.len() < 2 ||
       expected.max_round < 6 ||
       expected.session_id != pin.node.session_id ||
       !expected.contains(&pin.node.worker_agent) {
        return Err(SdkError::InvalidConfiguration("approved FROST spec differs from pinned node"));
    }
    Ok(())
}

fn validated_status(
    pin: &ConductorPin,
    expected: &SessionSpec,
    response: MpcZomeResult,
) -> Result<CoordinatorSessionStatus, SdkError> {
    match response {
        MpcZomeResult::ProbeSession { spec, accepted, ready } => {
            // The response has no proposal-action field. The signed request
            // already pins the proposal; compare *every* spec field here.
            // This also prevents cross-app, cross-context and same-session
            // equivocation from appearing as a valid SDK observation.
            if &spec != expected || spec.session_id != pin.node.session_id ||
               !spec.contains(&pin.node.worker_agent) {
                return Err(SdkError::InvalidResponse("status differs from approved FROST ceremony"));
            }
            Ok(CoordinatorSessionStatus { spec, accepted, ready_observed: ready })
        }
        _ => Err(SdkError::InvalidResponse("wrong or obsolete coordinator response kind")),
    }
}

impl NativeCoordinatorBackend {
    /// This is the only native SDK connect method. The full SessionSpec must
    /// come from an independently approved proposal, NOT from the untrusted
    /// status reply being validated. No network or signer request is issued
    /// before the local FROST pin passes validation.
    pub async fn connect(
        addr: SocketAddr,
        origin: impl Into<String>,
        token_path: PathBuf,
        pin: ConductorPin,
        signer_socket: PathBuf,
        expected_spec: SessionSpec,
    ) -> Result<Self, SdkError> {
        validate_approved_spec(&pin, &expected_spec)?;
        let origin = origin.into();
        let signer = UnixMpcSigner::new(signer_socket, pin.clone())
            .map_err(SdkError::Backend)?;
        signer.probe().await.map_err(SdkError::Backend)?;
        authenticate_and_pin(addr, &origin, &token_path, &pin)
            .await.map_err(SdkError::Transport)?;
        Ok(Self { addr, origin, token_path, pin, expected_spec, signer: Mutex::new(signer) })
    }
}

impl DkgBackend for NativeCoordinatorBackend {
    fn local_identity(&self) -> Option<ParticipantId> {
        ParticipantId::try_from(self.pin.node.worker_agent.as_slice()).ok()
    }

    fn get_session_status(&self, ceremony: CeremonyId)
        -> BackendFuture<'_, CoordinatorSessionStatus>
    {
        Box::pin(async move {
            if ceremony.as_bytes().as_slice() != self.pin.node.proposal_action.as_slice() {
                return Err(SdkError::InvalidIdentifier("proposal differs from pinned native node"));
            }
            // Obtain exactly one fresh, operator-authorised signature; do
            // not silently retry, downgrade to probe, or request other calls.
            let signed = self.signer.lock().await
                .sign(SignIntent::ReadFrostCeremonyStatus).await
                .map_err(SdkError::Backend)?;
            let response = submit_signed_mpc_call(
                self.addr, &self.origin, &self.token_path,
                &self.pin, MpcCall::GetProbeSessionStatus, signed,
            ).await.map_err(SdkError::Transport)?;
            validated_status(&self.pin, &self.expected_spec, response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use holochain_mpc_dkg_worker::ipc::ChannelContext;

    fn spec() -> SessionSpec {
        SessionSpec {
            session_id: [5;32], application_id: "org.example.sdk".into(),
            protocol_id: "frost-ed25519".into(), protocol_version: 1,
            context_hash: [7;32], participants: vec![vec![1;39],vec![2;39]],
            threshold: 2, max_round: 6,
        }
    }
    fn pin() -> ConductorPin {
        ConductorPin {
            app_id: "installed-frost-app".into(), role: "mpc".into(),
            dna_hash: vec![3;39],
            node: ChannelContext {
                worker_agent: vec![1;39], proposal_action: vec![9;39],
                session_id: [5;32], channel_id: [4;32],
            },
        }
    }
    fn response(s: SessionSpec) -> MpcZomeResult {
        MpcZomeResult::ProbeSession { spec: s, accepted: vec![vec![1;39]], ready: false }
    }

    #[test]
    fn rejects_unapproved_context_and_protocol_before_network() {
        validate_approved_spec(&pin(), &spec()).unwrap();
        let mut s = spec(); s.protocol_id = "mpc-transport-probe".into();
        assert!(validate_approved_spec(&pin(), &s).is_err());
        let mut s = spec(); s.session_id = [8;32];
        assert!(validate_approved_spec(&pin(), &s).is_err());
        let mut s = spec(); s.context_hash = [0;32];
        assert!(validate_approved_spec(&pin(), &s).is_err());
        let mut s = spec(); s.participants = vec![vec![2;39],vec![3;39]];
        assert!(validate_approved_spec(&pin(), &s).is_err());
        let mut p=pin(); p.role="other".into();
        assert!(validate_approved_spec(&p, &spec()).is_err());
        let mut p=pin(); p.dna_hash.clear();
        assert!(validate_approved_spec(&p, &spec()).is_err());
    }
    #[test]
    fn refuses_changed_app_context_roster_and_threshold_in_signed_reply() {
        assert!(validated_status(&pin(), &spec(), response(spec())).is_ok());
        let mut s=spec();s.application_id="another.app".into();
        assert!(validated_status(&pin(), &spec(), response(s)).is_err());
        let mut s=spec();s.context_hash=[8;32];
        assert!(validated_status(&pin(), &spec(), response(s)).is_err());
        let mut s=spec();s.threshold=1;
        assert!(validated_status(&pin(), &spec(), response(s)).is_err());
        let mut s=spec();s.participants=vec![vec![1;39],vec![3;39]];
        assert!(validated_status(&pin(), &spec(), response(s)).is_err());
        assert!(validated_status(&pin(), &spec(), MpcZomeResult::Inbox(vec![])).is_err());
    }
}
