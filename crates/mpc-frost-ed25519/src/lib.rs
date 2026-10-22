//! Native FROST Ed25519 provider for Holochain MPC Core.
//!
//! Experimental source: **not audited, compiled, or safe for production keys**.
//! Cryptographic protocol from Zcash Foundation's `frost-ed25519` 3.0.0.
//! One DKG per session and any number of distinct signing operation identifiers.
//!
//! SECURITY CONTRACT:
//! - The caller MUST authenticate origin and ensure consistent broadcast of
//!   DKG round-one packages before approving transcript attestations.
//! - The caller MUST deliver DKG round-two packages confidentially.
//! - KeyPackages and ephemeral nonces stay in private native memory only.
//! - An operation needs independent human/application authorization before signing.
//! - Do not execute side effects directly from Holochain inbox notifications.

use frost_ed25519 as frost;
use holochain_mpc_security::{Ceremony, SecurityError, VerifiedTranscript};
use holochain_mpc_security::activation::GroupDescriptor;
use holochain_mpc_security::sealed::{ChannelHeader, NativeChannelKey, SealedPacket};
use holochain_mpc_core::{commitment, Envelope, PrimitiveError, SessionSpec};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub const PROTOCOL_ID: &str = "frost-ed25519";
pub const PROTOCOL_VERSION: u16 = 1;

pub type Identifier = frost::Identifier;
pub type RoundOne = frost::keys::dkg::round1::Package;
pub type RoundTwo = frost::keys::dkg::round2::Package;
pub type PublicKeyPackage = frost::keys::PublicKeyPackage;
pub type KeyPackage = frost::keys::KeyPackage;
pub type SigningCommitments = frost::round1::SigningCommitments;
pub type SignatureShare = frost::round2::SignatureShare;
pub type SigningPackage = frost::SigningPackage;

#[derive(Debug)]
pub enum ProviderError {
    Invalid(&'static str),
    Protocol(String),
    Wire(String),
    WrongState,
    MissingPeer,
    InconsistentTranscript,
    SigningNonceUnavailable,
}
impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(x) => write!(f, "invalid request: {x}"),
            Self::Protocol(x) => write!(f, "FROST error: {x}"),
            Self::Wire(x) => write!(f, "wire error: {x}"),
            Self::WrongState => write!(f, "invalid protocol state transition"),
            Self::MissingPeer => write!(f, "missing/unknown participant"),
            Self::InconsistentTranscript => write!(f, "DKG broadcast transcripts disagree"),
            Self::SigningNonceUnavailable => write!(f, "signing nonce unavailable or already consumed"),
        }
    }
}
impl std::error::Error for ProviderError {}
impl From<frost::Error> for ProviderError {
    fn from(e: frost::Error) -> Self { Self::Protocol(e.to_string()) }
}
impl From<PrimitiveError> for ProviderError {
    fn from(e: PrimitiveError) -> Self { Self::Wire(e.to_string()) }
}
impl From<SecurityError> for ProviderError {
    fn from(e: SecurityError) -> Self { Self::Wire(e.to_string()) }
}
impl From<serde_json::Error> for ProviderError {
    fn from(e: serde_json::Error) -> Self { Self::Wire(e.to_string()) }
}

/// The proposal's *action hash*, unlike its app-level session id, is unique to
/// the Holochain-DNA instance and prevents reuse across recreated proposals.
/// The host MUST verify this exact action hash against the accepted session.
///
/// Deserialization runs the same checks as `new`. Fields stay public for
/// reading, so a struct literal can still bypass `new`: every entry point that
/// generates FROST randomness or admits a DKG calls `validate` again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BindingWire")]
pub struct Binding {
    pub proposal_action: Vec<u8>,
    pub spec: SessionSpec,
}
#[derive(Deserialize)]
struct BindingWire {
    proposal_action: Vec<u8>,
    spec: SessionSpec,
}
impl TryFrom<BindingWire> for Binding {
    type Error = ProviderError;
    fn try_from(wire: BindingWire) -> Result<Self, ProviderError> {
        Self::new(wire.proposal_action, wire.spec)
    }
}
impl Binding {
    pub fn new(proposal_action: Vec<u8>, spec: SessionSpec) -> Result<Self, ProviderError> {
        let binding = Self { proposal_action, spec };
        binding.validate()?;
        Ok(binding)
    }

    /// Reject any spec this provider does not run: other protocols (such as
    /// the transport probe), other versions, sub-2 thresholds, short sessions.
    pub fn validate(&self) -> Result<(), ProviderError> {
        self.spec.validate()?;
        if self.spec.protocol_id != PROTOCOL_ID || self.spec.protocol_version != PROTOCOL_VERSION {
            return Err(ProviderError::Invalid("expected frost-ed25519 v1"));
        }
        if self.spec.threshold < 2 || self.spec.participants.len() < 2 {
            return Err(ProviderError::Invalid("FROST needs at least two participants"));
        }
        if self.spec.max_round < 6 {
            return Err(ProviderError::Invalid("the Holochain session must allow rounds 1..6"));
        }
        if self.proposal_action.len() != 39 {
            return Err(ProviderError::Invalid("expected 39-byte Holochain proposal action hash"));
        }
        Ok(())
    }

    /// Map sorted Holochain identities to stable FROST ids 1..N. Do not let
    /// peers choose their own identifier independent of authenticated identity.
    pub fn id_of(&self, participant: &[u8]) -> Result<Identifier, ProviderError> {
        let n = self.spec.participants.iter().position(|p| p == participant)
            .ok_or(ProviderError::MissingPeer)? + 1;
        (n as u16).try_into().map_err(|_| ProviderError::Invalid("FROST identifier invalid"))
    }
    pub fn member_for(&self, id: Identifier) -> Result<&[u8], ProviderError> {
        for member in &self.spec.participants {
            if self.id_of(member)? == id { return Ok(member); }
        }
        Err(ProviderError::MissingPeer)
    }
    pub fn all_ids(&self) -> Result<Vec<Identifier>, ProviderError> {
        self.spec.participants.iter().map(|p| self.id_of(p)).collect()
    }
}

/// The provider's typed payloads, never public DHT entries. Payloads must be
/// parsed only after the `Envelope` has been authenticated by a host adapter.
#[derive(Clone, Serialize, Deserialize)]
pub enum Message {
    DkgRound1(RoundOne),
    DkgRound1Digest([u8; 32]),
    DkgRound2(RoundTwo),
    SigningCommitment(SigningCommitments),
    SigningPackage(SigningPackage),
    SignatureShare(SignatureShare),
}
impl Message {
    pub fn round(&self) -> u32 {
        match self {
            Self::DkgRound1(_) => 1,
            Self::DkgRound1Digest(_) => 2,
            Self::DkgRound2(_) => 3,
            Self::SigningCommitment(_) => 4,
            Self::SigningPackage(_) => 5,
            Self::SignatureShare(_) => 6,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Frame {
    pub proposal_action: Vec<u8>,
    /// The session ID for DKG; unique operation ID for each signing request.
    pub operation_id: [u8; 32],
    pub message: Message,
}
impl Frame {
    pub fn encode(&self, binding: &Binding, sender: &[u8], recipient: &[u8], sequence: u64)
        -> Result<Envelope, ProviderError>
    {
        if self.proposal_action != binding.proposal_action { return Err(ProviderError::Invalid("wrong proposal hash")); }
        if self.operation_id == [0; 32] { return Err(ProviderError::Invalid("zero operation id")); }
        let is_dkg = self.message.round() <= 3;
        if is_dkg != (self.operation_id == binding.spec.session_id) {
            return Err(ProviderError::Invalid("DKG vs signing operation identifier mismatch"));
        }
        Ok(Envelope::new(&binding.spec, sender.to_vec(), Some(recipient.to_vec()),
                         self.message.round(), sequence, serde_json::to_vec(self)?)?)
    }
    /// Use trusted transport `authenticated_sender`, NEVER `envelope.sender`
    /// as the source of identity. Does not provide reliable broadcast itself.
    pub fn decode(binding: &Binding, env: &Envelope, recipient: &[u8], authenticated_sender: &[u8])
        -> Result<Self, ProviderError>
    {
        env.validate_received(&binding.spec, recipient, authenticated_sender)?;
        let frame: Frame = serde_json::from_slice(&env.payload)?;
        if frame.proposal_action != binding.proposal_action || env.round != frame.message.round() {
            return Err(ProviderError::Invalid("frame not bound to proposal or transport round"));
        }
        if frame.operation_id == [0; 32] { return Err(ProviderError::Invalid("zero operation id")); }
        let is_dkg = frame.message.round() <= 3;
        if is_dkg != (frame.operation_id == binding.spec.session_id) {
            return Err(ProviderError::Invalid("DKG/signing ceremony mixed up"));
        }
        Ok(frame)
    }
}

/// Wrap one DKG Round-2 frame in recipient-specific authenticated encryption.
/// No cleartext share enters the Holochain coordinator inbox. Key identity
/// MUST be registered and pinned to a verified agent-authored DHT key binding.
/// Returned `Envelope` can be transported with the normal Holochain RPC.
pub fn seal_dkg_round_two(binding: &Binding, frame: &Frame, sender: &[u8], recipient: &[u8],
                          sequence: u64, local_key: &NativeChannelKey,
                          pinned_recipient_key: [u8; 32]) -> Result<Envelope, ProviderError> {
    if !matches!(&frame.message, Message::DkgRound2(_)) ||
        frame.proposal_action != binding.proposal_action ||
        frame.operation_id != binding.spec.session_id {
        return Err(ProviderError::Invalid("expected a DKG round-two frame"));
    }
    let ceremony = Ceremony { spec: binding.spec.clone(), proposal_action: binding.proposal_action.clone() };
    let header = ChannelHeader { sender: sender.to_vec(), recipient: recipient.to_vec(), round: 3, sequence };
    let sealed = local_key.seal(&ceremony, header, pinned_recipient_key, &serde_json::to_vec(frame)?)?;
    Ok(Envelope::new(&binding.spec, sender.to_vec(), Some(recipient.to_vec()),
                     3, sequence, serde_json::to_vec(&sealed)?)?)
}

/// Verify authenticated transport provenance, pinned sender encryption key,
/// ciphertext integrity, and embedded session/round binding before parsing FROST.
pub fn open_dkg_round_two(binding: &Binding, envelope: &Envelope,
                          local_recipient: &[u8], authenticated_sender: &[u8],
                          local_key: &NativeChannelKey, pinned_sender_key: [u8; 32])
    -> Result<Frame, ProviderError> {
    envelope.validate_received(&binding.spec, local_recipient, authenticated_sender)?;
    if envelope.round != 3 || envelope.recipient.as_deref() != Some(local_recipient) {
        return Err(ProviderError::Invalid("expected addressed, encrypted DKG round two"));
    }
    let sealed: SealedPacket = serde_json::from_slice(&envelope.payload)?;
    let ceremony = Ceremony { spec: binding.spec.clone(), proposal_action: binding.proposal_action.clone() };
    let header = ChannelHeader { sender: authenticated_sender.to_vec(), recipient: local_recipient.to_vec(),
                                 round: 3, sequence: envelope.sequence };
    let cleartext = local_key.open(&ceremony, &header, pinned_sender_key, &sealed)?;
    let frame: Frame = serde_json::from_slice(&cleartext)?;
    if !matches!(&frame.message, Message::DkgRound2(_)) ||
        frame.proposal_action != binding.proposal_action ||
        frame.operation_id != binding.spec.session_id {
        return Err(ProviderError::Invalid("unexpected encrypted DKG frame"));
    }
    Ok(frame)
}

/// Bind the actual application message (not a raw digest), the exact Holochain
/// proposal and the unique operation identifier to the signed bytes.
/// A verifier must reconstruct exactly these bytes.
pub fn signed_message(binding: &Binding, operation_id: [u8; 32], message: &[u8])
    -> Result<Vec<u8>, ProviderError>
{
    if operation_id == [0; 32] || operation_id == binding.spec.session_id || message.is_empty() {
        return Err(ProviderError::Invalid("invalid signing operation/message"));
    }
    let mut result = b"holochain-mpc-frost/ed25519/signature/v1".to_vec();
    for item in [binding.proposal_action.as_slice(), binding.spec.session_id.as_slice(),
                 binding.spec.context_hash.as_slice(), operation_id.as_slice(), message] {
        result.extend_from_slice(&(item.len() as u64).to_be_bytes());
        result.extend_from_slice(item);
    }
    Ok(result)
}

/// Produce the same transcript hash independently on each party. The host
/// must gather *authenticated* round-one acknowledgements from ALL peers and
/// ensure each peer attests to exactly this value; this is a precondition, not
/// an implementation of a Byzantine reliable-broadcast protocol.
pub fn round_one_digest(binding: &Binding, packages: &BTreeMap<Identifier, RoundOne>)
    -> Result<[u8; 32], ProviderError>
{
    if packages.len() != binding.spec.participants.len() ||
       !binding.all_ids()?.iter().all(|id| packages.contains_key(id)) {
        return Err(ProviderError::MissingPeer);
    }
    let mut raw = Vec::new();
    raw.extend_from_slice(&binding.proposal_action);
    raw.extend_from_slice(&binding.spec.session_id);
    for id in binding.all_ids()? {
        let bytes = serde_json::to_vec(&packages[&id])?;
        let id_bytes = id.serialize();
        raw.extend_from_slice(&(id_bytes.len() as u64).to_be_bytes());
        raw.extend_from_slice(&id_bytes);
        raw.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        raw.extend_from_slice(&bytes);
    }
    Ok(commitment("frost-dkg-r1", &raw))
}

/// Each participant creates secrets locally. Never clone, log, send or publish
/// The native controller derives this from successful FROST part3 *after*
/// a locally verified echo transcript. This is a public proposal for group
/// activation, not a multi-party certificate by itself.
/// A local completion token: not deserializeable and fields are private so
/// a network peer cannot directly fabricate this Rust value. The controller
/// must still validate unanimous *remote* group activation attestations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgPublicProposal {
    proposal_action: Vec<u8>,
    session_id: [u8; 32],
    transcript_hash: [u8; 32],
    public_key_package_hash: [u8; 32],
    group_verifying_key: Vec<u8>,
}
impl DkgPublicProposal {
    pub fn transcript_hash(&self) -> [u8; 32] { self.transcript_hash }
    pub fn public_key_package_hash(&self) -> [u8; 32] { self.public_key_package_hash }
    pub fn group_verifying_key(&self) -> &[u8] { &self.group_verifying_key }
    /// Use the exact returned PublicKeyPackage; each participant independently
    /// attests to the resulting GroupDescriptor, including all verifying shares.
    pub fn group_descriptor(&self, binding: &Binding, epoch: u64,
                            encryption_key_binding_actions: Vec<Vec<u8>>)
        -> Result<GroupDescriptor, ProviderError> {
        if self.proposal_action != binding.proposal_action ||
           self.session_id != binding.spec.session_id ||
           self.transcript_hash == [0;32] || self.public_key_package_hash == [0;32] {
            return Err(ProviderError::InconsistentTranscript);
        }
        let descriptor = GroupDescriptor {
            proposal_action: binding.proposal_action.clone(),
            spec: binding.spec.clone(), epoch,
            dkg_transcript_hash: self.transcript_hash,
            public_key_package_hash: self.public_key_package_hash,
            group_verifying_key: self.group_verifying_key.clone(),
            encryption_key_binding_actions,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
}

/// the secret packages. The caller should abort the DKG on any inconsistency.
pub struct DkgParty {
    binding: Binding,
    id: Identifier,
    own_public: RoundOne,
    round_one_secret: Option<frost::keys::dkg::round1::SecretPackage>,
    round_two_secret: Option<frost::keys::dkg::round2::SecretPackage>,
    approved_digest: Option<[u8; 32]>,
    verified_echo_hash: Option<[u8; 32]>,
}
impl DkgParty {
    pub fn begin(binding: Binding, own_agent: &[u8]) -> Result<(Self, RoundOne), ProviderError> {
        binding.validate()?;
        let id = binding.id_of(own_agent)?;
        let mut rng = OsRng;
        let (secret, public) = frost::keys::dkg::part1(
            id, binding.spec.participants.len() as u16, binding.spec.threshold, &mut rng)?;
        Ok((Self {
            binding, id, own_public: public.clone(), round_one_secret: Some(secret),
            round_two_secret: None, approved_digest: None, verified_echo_hash: None,
        }, public))
    }
    pub fn identifier(&self) -> Identifier { self.id }
    /// Only a locally verified unanimous authenticated echo + transcript
    /// attestation gate may enable Round 2. A digest map supplied by a caller
    /// is no longer accepted as evidence of broadcast consistency.
    pub fn part2(&mut self, packages: &BTreeMap<Identifier, RoundOne>,
                 gate: &VerifiedTranscript)
        -> Result<BTreeMap<Identifier, RoundTwo>, ProviderError>
    {
        if self.round_two_secret.is_some() { return Err(ProviderError::WrongState); }
        let digest = round_one_digest(&self.binding, packages)?;
        if packages.get(&self.id) != Some(&self.own_public) {
            return Err(ProviderError::InconsistentTranscript);
        }
        if gate.ceremony().spec != self.binding.spec ||
           gate.ceremony().proposal_action != self.binding.proposal_action ||
           gate.packages().len() != packages.len() ||
           self.binding.spec.participants.iter().any(|member| {
               let Ok(id) = self.binding.id_of(member) else { return true; };
               let Some(package) = packages.get(&id) else { return true; };
               let Ok(serialized) = serde_json::to_vec(package) else { return true; };
               gate.package(member) != Some(serialized.as_slice())
           }) {
            return Err(ProviderError::InconsistentTranscript);
        }
        let secret = self.round_one_secret.take().ok_or(ProviderError::WrongState)?;
        let others = packages.iter().filter(|(id,_)| **id != self.id)
            .map(|(id,p)| (*id, p.clone())).collect();
        let (private, outgoing) = frost::keys::dkg::part2(secret, &others)?;
        self.round_two_secret = Some(private);
        self.approved_digest = Some(digest);
        self.verified_echo_hash = Some(gate.hash());
        Ok(outgoing)
    }
    pub fn part3(&mut self, packages: &BTreeMap<Identifier, RoundOne>,
                 private_incoming: &BTreeMap<Identifier, RoundTwo>)
        -> Result<(KeyPackage, PublicKeyPackage), ProviderError>
    {
        if self.approved_digest != Some(round_one_digest(&self.binding, packages)?) {
            return Err(ProviderError::InconsistentTranscript);
        }
        if private_incoming.len() != self.binding.spec.participants.len()-1 ||
            self.binding.all_ids()?.into_iter().filter(|id| *id != self.id)
                .any(|id| !private_incoming.contains_key(&id)) {
            return Err(ProviderError::MissingPeer);
        }
        let secret = self.round_two_secret.take().ok_or(ProviderError::WrongState)?;
        let others = packages.iter().filter(|(id,_)| **id != self.id)
            .map(|(id,p)| (*id, p.clone())).collect();
        Ok(frost::keys::dkg::part3(&secret, &others, private_incoming)?)
    }
    /// Stronger DKG completion boundary: the returned public-key package is
    /// computed locally, checked against the exact Round-1 transcript accepted
    /// by this party, and must STILL receive unanimous activation attestations.
    pub fn part3_with_evidence(&mut self,
        packages: &BTreeMap<Identifier, RoundOne>,
        private_incoming: &BTreeMap<Identifier, RoundTwo>,
        gate: &VerifiedTranscript)
        -> Result<(KeyPackage, PublicKeyPackage, DkgPublicProposal), ProviderError> {
        if self.verified_echo_hash != Some(gate.hash()) ||
           gate.ceremony().spec != self.binding.spec ||
           gate.ceremony().proposal_action != self.binding.proposal_action ||
           gate.packages().len() != packages.len() ||
           self.binding.spec.participants.iter().any(|member| {
               let Ok(id) = self.binding.id_of(member) else { return true; };
               let Some(package) = packages.get(&id) else { return true; };
               let Ok(raw) = serde_json::to_vec(package) else { return true; };
               gate.package(member) != Some(raw.as_slice())
           }) {
            return Err(ProviderError::InconsistentTranscript);
        }
        let (local_key, public) = self.part3(packages, private_incoming)?;
        let public_key_package_hash = commitment("frost-public-key-package-v1", &serde_json::to_vec(&public)?);
        let proposal = DkgPublicProposal {
            proposal_action: self.binding.proposal_action.clone(),
            session_id: self.binding.spec.session_id,
            transcript_hash: gate.hash(),
            public_key_package_hash,
            group_verifying_key: public.verifying_key().serialize()?,
        };
        Ok((local_key, public, proposal))
    }
}

/// A signer permanently loses its nonce before it signs (even on failure).
/// Crash/restart ABORTS in-flight operations; no nonce recovery is supported.
pub struct Signer {
    binding: Binding,
    key: KeyPackage,
    pending: Option<PendingNonce>,
}
struct PendingNonce {
    operation_id: [u8; 32],
    bound_message: Vec<u8>,
    nonces: frost::round1::SigningNonces,
    commitments: SigningCommitments,
}
impl Signer {
    pub fn new(binding: Binding, own_agent: &[u8], key: KeyPackage) -> Result<Self, ProviderError> {
        binding.validate()?;
        if key.identifier() != &binding.id_of(own_agent)? ||
            *key.min_signers() != binding.spec.threshold {
            return Err(ProviderError::Invalid("key package identifier/threshold mismatch"));
        }
        Ok(Self { binding, key, pending: None })
    }
    pub fn commit(&mut self, operation_id: [u8; 32], message: &[u8])
        -> Result<SigningCommitments, ProviderError>
    {
        if self.pending.is_some() { return Err(ProviderError::WrongState); }
        let bound_message = signed_message(&self.binding, operation_id, message)?;
        let mut rng = OsRng;
        let (nonces, commitments) = frost::round1::commit(self.key.signing_share(), &mut rng);
        self.pending = Some(PendingNonce { operation_id, bound_message, nonces, commitments });
        Ok(commitments)
    }
    /// Application MUST have verified signer roster and shown the *exact*
    /// human-readable intent to the signer before calling `sign`.
    pub fn sign(&mut self, operation_id: [u8; 32], signing_package: &SigningPackage)
        -> Result<SignatureShare, ProviderError>
    {
        // Consume nonce first: no retry after a partial/failed computation.
        let pending = self.pending.take().ok_or(ProviderError::SigningNonceUnavailable)?;
        if operation_id != pending.operation_id || signing_package.message() != &pending.bound_message {
            return Err(ProviderError::Invalid("signing context/message changed"));
        }
        if signing_package.signing_commitments().len() < self.binding.spec.threshold as usize ||
           signing_package.signing_commitments().keys().any(|id| self.binding.member_for(*id).is_err()) ||
           signing_package.signing_commitment(self.key.identifier()) != Some(pending.commitments) {
            return Err(ProviderError::Invalid("signer set or local commitment changed"));
        }
        Ok(frost::round2::sign(signing_package, &pending.nonces, &self.key)?)
    }
}

pub fn signing_package(binding: &Binding, operation_id: [u8; 32], message: &[u8],
                       commitments: BTreeMap<Identifier, SigningCommitments>)
    -> Result<SigningPackage, ProviderError>
{
    if commitments.len() < binding.spec.threshold as usize ||
       commitments.len() > binding.spec.participants.len() ||
       commitments.keys().any(|id| binding.member_for(*id).is_err()) {
        return Err(ProviderError::Invalid("bad signing roster"));
    }
    Ok(frost::SigningPackage::new(commitments, &signed_message(binding, operation_id, message)?))
}

/// Public proof bytes which anyone can verify against a *trusted group key*.
/// The verifier MUST obtain/authorize the group public key independently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedArtifact {
    pub proposal_action: Vec<u8>,
    pub session_id: [u8; 32],
    pub operation_id: [u8; 32],
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn aggregate(binding: &Binding, operation_id: [u8; 32], message: &[u8],
                 package: &SigningPackage, shares: &BTreeMap<Identifier, SignatureShare>,
                 group_key: &PublicKeyPackage) -> Result<SignedArtifact, ProviderError>
{
    if package.message() != &signed_message(binding, operation_id, message)? ||
        shares.len() != package.signing_commitments().len() ||
        shares.keys().any(|id| !package.signing_commitments().contains_key(id)) {
        return Err(ProviderError::Invalid("aggregation context/share set mismatch"));
    }
    let sig = frost::aggregate(package, shares, group_key)?;
    Ok(SignedArtifact {
        proposal_action: binding.proposal_action.clone(),
        session_id: binding.spec.session_id,
        operation_id,
        public_key: group_key.verifying_key().serialize()?,
        signature: sig.serialize()?,
    })
}

pub fn verify_artifact(binding: &Binding, message: &[u8], artifact: &SignedArtifact,
                       trusted_public_key: &[u8]) -> Result<(), ProviderError>
{
    if artifact.proposal_action != binding.proposal_action ||
       artifact.session_id != binding.spec.session_id ||
       artifact.public_key != trusted_public_key {
        return Err(ProviderError::Invalid("artifact context or public key mismatch"));
    }
    let vk = frost::VerifyingKey::deserialize(trusted_public_key)?;
    let sig = frost::Signature::deserialize(&artifact.signature)?;
    vk.verify(&signed_message(binding, artifact.operation_id, message)?, &sig)?;
    Ok(())
}

// v0.3.2 native deployment entry point. The legacy `Signer` remains available
// for protocol simulations but MUST NOT be used for funded/production work.
// `ControlledSigner` enforces group activation, explicit intent approval,
// durable nonce reservation and durable commitment burn-before-publish.
use holochain_mpc_security::activation::{
    ActivatedGroup, ApprovedIntent, SigningProfile,
};
use holochain_mpc_runtime::RuntimeStore;

impl From<holochain_mpc_runtime::RuntimeError> for ProviderError {
    fn from(e: holochain_mpc_runtime::RuntimeError) -> Self { Self::Wire(e.to_string()) }
}

pub struct ControlledSigner {
    underlying: Signer,
    group: ActivatedGroup,
    own_agent: Vec<u8>,
    pending_approval: Option<[u8;32]>,
}
impl ControlledSigner {
    pub fn new(binding: Binding, own_agent: &[u8], key: KeyPackage,
               public: &PublicKeyPackage, activated: ActivatedGroup) -> Result<Self,ProviderError> {
        if activated.descriptor().spec != binding.spec ||
           activated.descriptor().proposal_action != binding.proposal_action ||
           activated.descriptor().public_key_package_hash !=
                commitment("frost-public-key-package-v1", &serde_json::to_vec(public)?) ||
           activated.descriptor().group_verifying_key != public.verifying_key().serialize()? {
            return Err(ProviderError::Invalid("untrusted or conflicting active group public key package"));
        }
        let underlying = Signer::new(binding,own_agent,key)?;
        Ok(Self { underlying, group:activated, own_agent:own_agent.to_vec(), pending_approval:None })
    }
    fn validate_approval(&self, approved: &ApprovedIntent, message: &[u8]) -> Result<(), ProviderError> {
        let intent = approved.intent();
        if intent.proposal_action != self.underlying.binding.proposal_action ||
           intent.group_epoch != self.group.descriptor().epoch ||
           intent.group_certificate_digest != self.group.digest() ||
           intent.message_hash != commitment("signing-intent-message", message) ||
           intent.profile != SigningProfile::ContextBoundV1 ||
           !intent.selected.contains(&self.own_agent) ||
           approved.digest() != intent.digest()? {
            return Err(ProviderError::Invalid("no approved, bound, context-specific signing intent"));
        }
        Ok(())
    }
    /// Reserve in SQLite BEFORE generating a FROST nonce. On any failure the
    /// operation's nonce slot remains unusable. The signing commitment is
    /// released to the caller ONLY AFTER the publication/burn record is fsynced.
    pub fn prepare(&mut self, store: &mut RuntimeStore, approved: &ApprovedIntent,
                   message: &[u8], now_ms: i64) -> Result<SigningCommitments,ProviderError> {
        self.validate_approval(approved, message)?;
        if self.pending_approval.is_some() { return Err(ProviderError::WrongState); }
        let intent = approved.intent();
        store.reserve_nonce(&intent.proposal_action,intent.group_epoch,
                            &intent.operation_id,&self.own_agent,now_ms)?;
        let commitments = self.underlying.commit(intent.operation_id,message)?;
        let serialized = serde_json::to_vec(&commitments)?;
        store.authorize_commitment(&intent.proposal_action,intent.group_epoch,
                                   &intent.operation_id,&self.own_agent,&serialized)?;
        self.pending_approval = Some(approved.digest());
        Ok(commitments)
    }
    pub fn sign(&mut self, store: &mut RuntimeStore, approved: &ApprovedIntent, message: &[u8],
                package: &SigningPackage, now_ms: i64) -> Result<SignatureShare,ProviderError> {
        // Consume the in-memory signing authority, including on a failed check.
        let stored = self.pending_approval.take().ok_or(ProviderError::SigningNonceUnavailable)?;
        let intent = approved.intent();
        if let Err(err) = store.ensure_live(&intent.proposal_action, &intent.operation_id, now_ms) {
            self.underlying.pending.take();
            return Err(err.into());
        }
        let roster_matches = package.signing_commitments().len() == intent.selected.len() &&
            intent.selected.iter().all(|member| {
                self.underlying.binding.id_of(member)
                    .map(|id| package.signing_commitments().contains_key(&id))
                    .unwrap_or(false)
            });
        if stored != approved.digest() || !roster_matches ||
           self.validate_approval(approved,message).is_err() {
            // The FROST nonce is dropped when the signer is dropped; do not
            // permit further signing through this wrapper after an error.
            self.underlying.pending.take();
            return Err(ProviderError::Invalid("signer roster or authorised intent changed"));
        }
        self.underlying.sign(intent.operation_id,package)
    }
}

/// Use the group key from completed activation, not the key included in an
/// untrusted signing artifact.
pub fn verify_activated_artifact(binding: &Binding, message: &[u8],
                                artifact: &SignedArtifact, group: &ActivatedGroup)
    -> Result<(),ProviderError> {
    if group.descriptor().proposal_action != binding.proposal_action ||
       group.descriptor().spec != binding.spec {
        return Err(ProviderError::Invalid("verification group belongs to another session"));
    }
    verify_artifact(binding,message,artifact,&group.descriptor().group_verifying_key)
}

/// Signature shares obtained from authentically identified Holochain callers.
/// The caller must use the actual authenticated provenance, never a sender
/// asserted in the message. This collector cannot by itself validate a
/// portable signature over the network transport; preserve signed evidence.
pub struct AuthenticatedShareCollector {
    binding: Binding,
    expected_package_digest: [u8;32],
    received: BTreeMap<Identifier,SignatureShare>,
}
impl AuthenticatedShareCollector {
    pub fn new(binding: Binding, package: &SigningPackage) -> Result<Self,ProviderError> {
        binding.validate()?;
        let expected_package_digest=commitment("frost-signing-package-v1",&serde_json::to_vec(package)?);
        Ok(Self { binding,expected_package_digest,received:BTreeMap::new() })
    }
    pub fn ingest(&mut self, authenticated_sender: &[u8], share: SignatureShare,
                  package: &SigningPackage) -> Result<(),ProviderError> {
        if commitment("frost-signing-package-v1",&serde_json::to_vec(package)?) != self.expected_package_digest {
            return Err(ProviderError::Invalid("signature share belongs to different signing package"));
        }
        let id=self.binding.id_of(authenticated_sender)?;
        if !package.signing_commitments().contains_key(&id) {
            return Err(ProviderError::Invalid("sender not in signed roster"));
        }
        if let Some(previous)=self.received.get(&id) {
            if serde_json::to_vec(previous)? != serde_json::to_vec(&share)? {
                return Err(ProviderError::Invalid("conflicting signature share from same signer"));
            }
        } else { self.received.insert(id,share); }
        Ok(())
    }
    pub fn aggregate(self, binding: &Binding, operation_id: [u8;32], message: &[u8],
                     package: &SigningPackage, group: &PublicKeyPackage,
                     active: &ActivatedGroup) -> Result<SignedArtifact,ProviderError> {
        if self.binding != *binding ||
           self.expected_package_digest != commitment("frost-signing-package-v1",&serde_json::to_vec(package)?) ||
           active.descriptor().spec != binding.spec ||
           active.descriptor().proposal_action != binding.proposal_action ||
           active.descriptor().public_key_package_hash != commitment("frost-public-key-package-v1",&serde_json::to_vec(group)?) ||
           self.received.len() != package.signing_commitments().len() {
            return Err(ProviderError::Invalid("untrusted group, sender, package or missing share"));
        }
        aggregate(binding,operation_id,message,package,&self.received,group)
    }
}
