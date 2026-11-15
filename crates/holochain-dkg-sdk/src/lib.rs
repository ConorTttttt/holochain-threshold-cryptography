//! Typed, application-independent SDK facade for Holochain FROST DKG.
//!
//! This crate does not perform DKG, load shares, approve ceremonies or sign.
//! Read-only status is an observation from one authenticated coordinator cell,
//! not global finality. Secret custody remains with existing native services.

use holochain_mpc_core::SessionSpec;
use holochain_mpc_security::activation::GroupDescriptor as NativeGroupDescriptor;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

#[cfg(all(feature = "native-holochain", unix))]
pub mod native;

/// A Holochain AgentPubKey in its raw 39-byte form. The conductor must
/// authenticate its provenance; this value alone is not a credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParticipantId([u8; 39]);
impl ParticipantId {
    pub fn as_bytes(&self) -> &[u8; 39] { &self.0 }
}
impl TryFrom<&[u8]> for ParticipantId {
    type Error = SdkError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; 39] = bytes.try_into()
            .map_err(|_| SdkError::InvalidIdentifier("participant must be 39 bytes"))?;
        if raw.iter().all(|x| *x == 0) {
            return Err(SdkError::InvalidIdentifier("zero participant"));
        }
        Ok(Self(raw))
    }
}

/// An exact SessionProposal action hash, not a session id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CeremonyId([u8; 39]);
impl CeremonyId {
    pub fn as_bytes(&self) -> &[u8; 39] { &self.0 }
}
impl TryFrom<&[u8]> for CeremonyId {
    type Error = SdkError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let raw: [u8; 39] = bytes.try_into()
            .map_err(|_| SdkError::InvalidIdentifier("ceremony action must be 39 bytes"))?;
        if raw.iter().all(|x| *x == 0) {
            return Err(SdkError::InvalidIdentifier("zero ceremony action"));
        }
        Ok(Self(raw))
    }
}

/// Digest of a validated public GroupDescriptor, NOT proof of activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GroupId([u8; 32]);
impl GroupId { pub fn as_bytes(&self) -> &[u8; 32] { &self.0 } }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperationId([u8; 32]);
impl OperationId {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, SdkError> {
        if bytes == [0; 32] { return Err(SdkError::InvalidIdentifier("zero operation id")); }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

/// Running and later states require durable native evidence. A read-only
/// coordinator status cannot assert them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyState {
    Proposed,
    AwaitingAcceptance,
    ReadyToStart,
    Running,
    AwaitingActivation,
    Active,
    Aborted,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyStatus {
    pub id: CeremonyId,
    pub session_id: [u8; 32],
    pub participants: Vec<ParticipantId>,
    pub threshold: u16,
    pub accepted: Vec<ParticipantId>,
    /// Local DHT observation only; not a durable start or group activation.
    pub ready_observed: bool,
    pub state: CeremonyState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupActivationState {
    NotStarted,
    AwaitingAttestations { observed: usize, required: usize },
    Verified,
    Aborted,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningApprovalState {
    Proposed,
    AwaitingApprovals { observed: usize, required: usize },
    Approved,
    Rejected,
    Expired,
}

/// Public metadata from an existing native GroupDescriptor. Conversion
/// validates structure and computes its canonical digest; this is *not* an
/// activation certificate or proof of secret-share custody.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicGroupDescriptor {
    pub id: GroupId,
    pub ceremony_id: CeremonyId,
    pub session_id: [u8; 32],
    pub epoch: u64,
    pub threshold: u16,
    pub participants: Vec<ParticipantId>,
    pub group_verifying_key: [u8; 32],
    pub dkg_transcript_hash: [u8; 32],
    pub public_key_package_hash: [u8; 32],
    pub encryption_key_binding_actions: Vec<[u8; 39]>,
}
impl TryFrom<NativeGroupDescriptor> for PublicGroupDescriptor {
    type Error = SdkError;
    fn try_from(d: NativeGroupDescriptor) -> Result<Self, Self::Error> {
        d.validate().map_err(|_| SdkError::InvalidResponse("invalid native group descriptor"))?;
        if d.spec.protocol_id != "frost-ed25519" || d.spec.protocol_version != 1 {
            return Err(SdkError::InvalidResponse("unsupported group protocol"));
        }
        let digest = d.digest().map_err(|_| SdkError::InvalidResponse("invalid descriptor digest"))?;
        let participants = d.spec.participants.iter()
            .map(|p| ParticipantId::try_from(p.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SdkError::InvalidResponse("invalid group participant"))?;
        let ceremony_id = CeremonyId::try_from(d.proposal_action.as_slice())
            .map_err(|_| SdkError::InvalidResponse("invalid proposal action"))?;
        let group_verifying_key: [u8; 32] = d.group_verifying_key.as_slice().try_into()
            .map_err(|_| SdkError::InvalidResponse("invalid group verifying key"))?;
        if group_verifying_key == [0; 32] {
            return Err(SdkError::InvalidResponse("zero group verifying key"));
        }
        let encryption_key_binding_actions = d.encryption_key_binding_actions.iter()
            .map(|a| a.as_slice().try_into()
                .map_err(|_| SdkError::InvalidResponse("invalid binding action")))
            .collect::<Result<Vec<[u8; 39]>, _>>()?;
        Ok(Self { id: GroupId(digest), ceremony_id,
            session_id: d.spec.session_id, epoch: d.epoch,
            threshold: d.spec.threshold, participants, group_verifying_key,
            dkg_transcript_hash: d.dkg_transcript_hash,
            public_key_package_hash: d.public_key_package_hash,
            encryption_key_binding_actions })
    }
}

/// This opaque wrapper can only be returned by a future backend that verifies
/// unanimous activation evidence against the exact descriptor and local pin.
#[derive(Clone, Debug)]
pub struct ActivatedGroup {
    descriptor: PublicGroupDescriptor,
    certificate_digest: [u8; 32],
}
impl ActivatedGroup {
    pub fn descriptor(&self) -> &PublicGroupDescriptor { &self.descriptor }
    pub fn certificate_digest(&self) -> &[u8; 32] { &self.certificate_digest }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningRequest {
    pub group: GroupId,
    pub operation: OperationId,
    /// Never publish plaintext in a DHT approval entry.
    pub message: Vec<u8>,
    pub selected_signers: Vec<ParticipantId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedArtifact {
    operation: OperationId,
    group: GroupId,
    signature: [u8; 64],
    signed_message: Vec<u8>,
}
impl SignedArtifact {
    pub fn operation(&self) -> OperationId { self.operation }
    pub fn group(&self) -> GroupId { self.group }
    pub fn signature(&self) -> &[u8; 64] { &self.signature }
    pub fn signed_message(&self) -> &[u8] { &self.signed_message }
}

/// Stable categories; never include private tokens, signed call bytes or keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SdkError {
    InvalidConfiguration(&'static str),
    InvalidIdentifier(&'static str),
    InvalidResponse(&'static str),
    NotFound,
    NotReady,
    Unauthorized,
    Conflict,
    Transport(String),
    Backend(String),
    Unsupported(&'static str),
}
impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(m) => write!(f, "invalid configuration: {m}"),
            Self::InvalidIdentifier(m) => write!(f, "invalid identifier: {m}"),
            Self::InvalidResponse(m) => write!(f, "invalid coordinator/native response: {m}"),
            Self::NotFound => f.write_str("ceremony or group not found"),
            Self::NotReady => f.write_str("ceremony or group not ready"),
            Self::Unauthorized => f.write_str("operator authorisation required"),
            Self::Conflict => f.write_str("conflicting ceremony or activation evidence"),
            Self::Transport(_) => f.write_str("coordinator transport failed"),
            Self::Backend(_) => f.write_str("native backend refused the operation"),
            Self::Unsupported(m) => write!(f, "unsupported SDK operation: {m}"),
        }
    }
}
impl Error for SdkError {}

#[derive(Clone, Debug)]
pub struct SdkConfig {
    pub application_id: String,
    pub local_participant: ParticipantId,
}
impl SdkConfig {
    pub fn new(application_id: impl Into<String>, local_participant: ParticipantId)
        -> Result<Self, SdkError>
    {
        let application_id = application_id.into();
        if application_id.is_empty() || application_id.len() > 96 ||
            !application_id.bytes().all(|b|
                b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
            return Err(SdkError::InvalidConfiguration("invalid application namespace"));
        }
        Ok(Self { application_id, local_participant })
    }
}

/// Mirrors the existing coordinator get_session_status response, decoded by
/// the authenticated native bridge. A backend MUST pin the exact proposal.
#[derive(Clone, Debug)]
pub struct CoordinatorSessionStatus {
    pub spec: SessionSpec,
    pub accepted: Vec<Vec<u8>>,
    pub ready_observed: bool,
}

pub type BackendFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SdkError>> + Send + 'a>>;

/// Backend implementations must never invent success, implicit consent, or
/// group activation. Native operations may require operator signer policy.
pub trait DkgBackend: Send + Sync {
    fn get_session_status(&self, ceremony: CeremonyId)
        -> BackendFuture<'_, CoordinatorSessionStatus>;
    fn local_identity(&self) -> Option<ParticipantId> { None }
}

pub struct DkgSdk<B: DkgBackend> {
    config: SdkConfig,
    backend: B,
}
impl<B: DkgBackend> DkgSdk<B> {
    /// Construct an SDK over an already authenticated backend. This method
    /// does not authenticate the conductor; native::connect does.
    pub fn new(config: SdkConfig, backend: B) -> Result<Self, SdkError> {
        if backend.local_identity().is_some_and(|id| id != config.local_participant) {
            return Err(SdkError::InvalidConfiguration("SDK agent differs from backend pin"));
        }
        Ok(Self { config, backend })
    }

    /// Genuine read-only coordinator operation. All later lifecycle states
    /// require evidence unavailable from get_session_status alone.
    pub async fn group_status(&self, ceremony: CeremonyId)
        -> Result<CeremonyStatus, SdkError>
    {
        let raw = self.backend.get_session_status(ceremony).await?;
        raw.spec.validate().map_err(|_|
            SdkError::InvalidResponse("invalid session specification"))?;
        if raw.spec.protocol_id != "frost-ed25519" || raw.spec.protocol_version != 1 ||
           raw.spec.application_id != self.config.application_id {
            return Err(SdkError::InvalidResponse("wrong application or protocol"));
        }
        let participants = raw.spec.participants.iter()
            .map(|p| ParticipantId::try_from(p.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SdkError::InvalidResponse("invalid participant identity"))?;
        if !participants.contains(&self.config.local_participant) {
            return Err(SdkError::InvalidResponse("local agent is not a ceremony member"));
        }
        let accepted = raw.accepted.iter()
            .map(|p| ParticipantId::try_from(p.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SdkError::InvalidResponse("invalid acceptance author"))?;
        let unique: BTreeSet<_> = accepted.iter().copied().collect();
        if unique.len() != accepted.len() ||
            accepted.iter().any(|a| !participants.contains(a)) {
            return Err(SdkError::InvalidResponse("duplicate or nonmember acceptance"));
        }
        let all_accepted = accepted.len() == participants.len();
        if all_accepted != raw.ready_observed {
            return Err(SdkError::InvalidResponse("inconsistent coordinator readiness"));
        }
        let state = if all_accepted { CeremonyState::ReadyToStart }
            else if accepted.is_empty() { CeremonyState::Proposed }
            else { CeremonyState::AwaitingAcceptance };
        Ok(CeremonyStatus { id: ceremony, session_id: raw.spec.session_id,
            participants, threshold: raw.spec.threshold, accepted,
            ready_observed: raw.ready_observed, state })
    }

    pub async fn propose_group(&self, _participants: Vec<ParticipantId>, _threshold: u16)
        -> Result<CeremonyId, SdkError> {
        Err(SdkError::Unsupported("proposal and consent workflow not yet wired"))
    }
    pub async fn get_activated_group(&self, _ceremony: CeremonyId)
        -> Result<ActivatedGroup, SdkError> {
        Err(SdkError::Unsupported("verified activation backend not yet wired"))
    }
    pub async fn propose_signing(&self, _request: SigningRequest)
        -> Result<OperationId, SdkError> {
        Err(SdkError::Unsupported("operator-approved signing backend not yet wired"))
    }
    pub async fn get_signature(&self, _operation: OperationId)
        -> Result<SignedArtifact, SdkError> {
        Err(SdkError::Unsupported("signature verification/retrieval not yet wired"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use holochain_mpc_security::activation::GroupDescriptor;

    fn agent(n: u8) -> ParticipantId {
        ParticipantId::try_from(&[n; 39][..]).unwrap()
    }
    fn ceremony() -> CeremonyId {
        CeremonyId::try_from(&[9; 39][..]).unwrap()
    }
    fn spec() -> SessionSpec {
        SessionSpec {
            session_id: [4; 32], application_id: "org.example.sdk".into(),
            protocol_id: "frost-ed25519".into(), protocol_version: 1,
            context_hash: [6; 32],
            participants: vec![vec![1; 39], vec![2; 39], vec![3; 39]],
            threshold: 2, max_round: 6,
        }
    }
    struct MockBackend { result: Result<CoordinatorSessionStatus, SdkError> }
    impl DkgBackend for MockBackend {
        fn get_session_status(&self, _ceremony: CeremonyId)
            -> BackendFuture<'_, CoordinatorSessionStatus> {
            Box::pin(async move { self.result.clone() })
        }
        fn local_identity(&self) -> Option<ParticipantId> { Some(agent(1)) }
    }
    fn sdk(status: CoordinatorSessionStatus) -> DkgSdk<MockBackend> {
        DkgSdk::new(SdkConfig::new("org.example.sdk", agent(1)).unwrap(),
            MockBackend { result: Ok(status) }).unwrap()
    }
    fn status(accepted: &[u8], ready_observed: bool) -> CoordinatorSessionStatus {
        CoordinatorSessionStatus { spec: spec(), accepted: accepted.iter()
            .map(|n| vec![*n; 39]).collect(), ready_observed }
    }

    #[tokio::test]
    async fn observed_acceptances_never_imply_running_or_active() {
        assert_eq!(sdk(status(&[], false)).group_status(ceremony()).await.unwrap().state,
            CeremonyState::Proposed);
        assert_eq!(sdk(status(&[1], false)).group_status(ceremony()).await.unwrap().state,
            CeremonyState::AwaitingAcceptance);
        let ready = sdk(status(&[1, 2, 3], true)).group_status(ceremony()).await.unwrap();
        assert_eq!(ready.state, CeremonyState::ReadyToStart);
        assert_eq!(ready.threshold, 2);
        assert_eq!(ready.accepted.len(), 3);
    }

    #[tokio::test]
    async fn rejects_ambiguous_or_forged_coordinator_observation() {
        for bad in [status(&[1, 1], false), status(&[1, 4], false),
            status(&[1], true), status(&[1, 2, 3], false)] {
            assert!(matches!(sdk(bad).group_status(ceremony()).await,
                Err(SdkError::InvalidResponse(_))));
        }
        let mut bad = status(&[], false);
        bad.spec.application_id = "other.app".into();
        assert!(sdk(bad).group_status(ceremony()).await.is_err());
        let mut bad = status(&[], false);
        bad.spec.protocol_id = "other-protocol".into();
        assert!(sdk(bad).group_status(ceremony()).await.is_err());
    }

    #[tokio::test]
    async fn backend_errors_are_not_converted_to_status() {
        let client = DkgSdk::new(SdkConfig::new("org.example.sdk", agent(1)).unwrap(),
            MockBackend { result: Err(SdkError::Unauthorized) }).unwrap();
        assert_eq!(client.group_status(ceremony()).await.unwrap_err(), SdkError::Unauthorized);
    }

    #[tokio::test]
    async fn unsupported_mutations_fail_closed() {
        let client = sdk(status(&[], false));
        assert!(matches!(client.propose_group(vec![agent(1)], 1).await,
            Err(SdkError::Unsupported(_))));
        assert!(matches!(client.get_activated_group(ceremony()).await,
            Err(SdkError::Unsupported(_))));
        assert!(matches!(client.get_signature(OperationId::try_new([3;32]).unwrap()).await,
            Err(SdkError::Unsupported(_))));
        let req = SigningRequest { group: GroupId([1; 32]),
            operation: OperationId::try_new([2;32]).unwrap(),
            message: b"test".to_vec(), selected_signers: vec![agent(1), agent(2)] };
        assert!(matches!(client.propose_signing(req).await, Err(SdkError::Unsupported(_))));
    }

    #[test]
    fn sdk_pin_and_identifier_guards() {
        assert!(ParticipantId::try_from(&[1; 38][..]).is_err());
        assert!(CeremonyId::try_from(&[0; 39][..]).is_err());
        assert!(OperationId::try_new([0;32]).is_err());
        assert!(SdkConfig::new("bad namespace!", agent(1)).is_err());
        let wrong = DkgSdk::new(SdkConfig::new("org.example.sdk", agent(2)).unwrap(),
            MockBackend { result: Ok(status(&[], false)) });
        assert!(matches!(wrong, Err(SdkError::InvalidConfiguration(_))));
    }

    #[test]
    fn converts_public_native_descriptor_without_claiming_activation() {
        let native = GroupDescriptor {
            proposal_action: vec![9; 39], spec: spec(), epoch: 0,
            dkg_transcript_hash: [7;32], public_key_package_hash: [8;32],
            group_verifying_key: vec![10;32],
            encryption_key_binding_actions: vec![vec![11;39],vec![12;39],vec![13;39]],
        };
        let digest = native.digest().unwrap();
        let public = PublicGroupDescriptor::try_from(native.clone()).unwrap();
        assert_eq!(public.id.as_bytes(), &digest);
        assert_eq!(public.ceremony_id, ceremony());
        assert_eq!(public.threshold, 2);
        let mut bad = native;
        bad.encryption_key_binding_actions[1] = bad.encryption_key_binding_actions[0].clone();
        assert!(PublicGroupDescriptor::try_from(bad).is_err());
    }
}
