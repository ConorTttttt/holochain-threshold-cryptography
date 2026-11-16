//! Protocol-neutral MPC coordination primitives. NOT an MPC algorithm.
//!
//! Every adapter MUST independently authenticate the transport caller and
//! persist inbound replay state atomically with message handling.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

pub const MAX_PARTICIPANTS: usize = 64;
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_MESSAGES_PER_SESSION: usize = 16_384;
pub const MAX_ROUNDS: u32 = 1_000_000;
/// Legacy v1: valid only under the historical session-only isolation contract.
/// Do not use this type for a new cross-application SDK or a v2 ceremony.
pub const WIRE_VERSION: u16 = 1;

mod bound_v2;
pub use bound_v2::{
    BoundEnvelopeV2, BoundInboxV2, CeremonyBindingV2, BOUND_WIRE_VERSION,
};

pub type SessionId = [u8; 32];
pub type ContextHash = [u8; 32];
/// An application-defined stable, authenticated public identifier (e.g. a
/// Holochain agent public key's 39 raw bytes). NOT a secret key.
pub type ParticipantId = Vec<u8>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSpec {
    pub session_id: SessionId,
    /// A stable namespace, such as "org.example.collaboration".
    pub application_id: String,
    /// Cryptographic plugin name, e.g. "frost-ed25519".
    pub protocol_id: String,
    pub protocol_version: u16,
    /// SHA-256 of a canonical, application-specific operation description.
    /// The host application must construct and verify the description.
    pub context_hash: ContextHash,
    /// Sorted lexicographically, unique, nonempty authenticated identities.
    pub participants: Vec<ParticipantId>,
    /// A protocol-defined threshold; the core only checks the numeric bounds.
    pub threshold: u16,
    /// Largest protocol round number this session accepts (rounds start at 1).
    pub max_round: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub wire_version: u16,
    pub session_id: SessionId,
    pub protocol_id: String,
    pub protocol_version: u16,
    pub sender: ParticipantId,
    /// None means broadcast to all session members other than the sender.
    pub recipient: Option<ParticipantId>,
    pub round: u32,
    /// Unique for the (session, sender, round) tuple; start at 1.
    pub sequence: u64,
    /// Domain-separated SHA-256 of payload, NOT a digital signature or MAC.
    pub payload_hash: [u8; 32],
    /// PRIVATE protocol message. Do not publish on a Holochain DHT.
    pub payload: Vec<u8>,
}

/// Ciphertext-only v0.3.1 transport shape for confidential protocol rounds.
/// Decryption and trusted public-key checks are performed by a native client;
/// a Holochain zome can only enforce structural constraints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPacket {
    pub version: u16,
    pub sender_key: [u8; 32],
    pub recipient_key: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}
impl SealedPacket {
    pub fn structurally_valid(&self) -> bool {
        self.version == 1 && self.sender_key != [0; 32] &&
        self.recipient_key != [0; 32] && self.ciphertext.len() >= 16 &&
        self.ciphertext.len() <= 48 * 1024
    }
}

/// An optional public artifact that commits to an opaque result. Does NOT
/// establish the correctness of the computation without a plugin verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultCommitment {
    pub session_id: SessionId,
    pub protocol_id: String,
    pub protocol_version: u16,
    pub result_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrimitiveError {
    InvalidSession(&'static str),
    InvalidEnvelope(&'static str),
    SenderNotMember,
    RecipientNotMember,
    WrongRecipient,
    AuthenticatedSenderMismatch,
    WrongProtocol,
    WrongSession,
    PayloadDigestMismatch,
    Replay,
    InboxFull,
}

impl fmt::Display for PrimitiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrimitiveError::InvalidSession(s) => write!(f, "invalid session: {s}"),
            PrimitiveError::InvalidEnvelope(s) => write!(f, "invalid envelope: {s}"),
            PrimitiveError::SenderNotMember => write!(f, "sender is not a session member"),
            PrimitiveError::RecipientNotMember => write!(f, "recipient is not a session member"),
            PrimitiveError::WrongRecipient => write!(f, "message addressed to a different recipient"),
            PrimitiveError::AuthenticatedSenderMismatch => write!(f, "authenticated caller does not match envelope sender"),
            PrimitiveError::WrongProtocol => write!(f, "incorrect protocol identifier or version"),
            PrimitiveError::WrongSession => write!(f, "incorrect session identifier"),
            PrimitiveError::PayloadDigestMismatch => write!(f, "payload digest mismatch"),
            PrimitiveError::Replay => write!(f, "duplicate message identifier"),
            PrimitiveError::InboxFull => write!(f, "per-session replay state is full"),
        }
    }
}

impl std::error::Error for PrimitiveError {}

/// SHA-256 with a fixed label and unambiguous length-delimited inputs.
/// This is only a commitment/digest helper; not signature authentication.
pub fn commitment(label: &str, input: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"holochain-mpc-core/v1");
    digest.update((label.len() as u64).to_be_bytes());
    digest.update(label.as_bytes());
    digest.update((input.len() as u64).to_be_bytes());
    digest.update(input);
    digest.finalize().into()
}

impl SessionSpec {
    pub fn validate(&self) -> Result<(), PrimitiveError> {
        if self.session_id == [0; 32] {
            return Err(PrimitiveError::InvalidSession("zero session ID"));
        }
        if self.context_hash == [0; 32] {
            return Err(PrimitiveError::InvalidSession("missing context binding"));
        }
        validate_namespace(&self.application_id)
            .map_err(PrimitiveError::InvalidSession)?;
        validate_namespace(&self.protocol_id)
            .map_err(PrimitiveError::InvalidSession)?;
        if self.protocol_version == 0 {
            return Err(PrimitiveError::InvalidSession("protocol version must be positive"));
        }
        if self.participants.is_empty() || self.participants.len() > MAX_PARTICIPANTS {
            return Err(PrimitiveError::InvalidSession("invalid number of participants"));
        }
        if self.threshold == 0 || usize::from(self.threshold) > self.participants.len() {
            return Err(PrimitiveError::InvalidSession("threshold outside participant range"));
        }
        if self.max_round == 0 || self.max_round > MAX_ROUNDS {
            return Err(PrimitiveError::InvalidSession("max_round outside allowed range"));
        }
        for participant in &self.participants {
            if participant.len() < 16 || participant.len() > 128 {
                return Err(PrimitiveError::InvalidSession("participant ID must be 16..=128 bytes"));
            }
        }
        for pair in self.participants.windows(2) {
            if pair[0] >= pair[1] {
                return Err(PrimitiveError::InvalidSession("participant IDs must be sorted and unique"));
            }
        }
        Ok(())
    }

    pub fn contains(&self, participant: &[u8]) -> bool {
        self.participants.iter().any(|member| member == participant)
    }
}

fn validate_namespace(s: &str) -> Result<(), &'static str> {
    if s.is_empty() || s.len() > 96 {
        return Err("namespace must be 1..=96 ASCII characters");
    }
    if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
        return Err("namespace may only contain ASCII letters, digits, '-', '_' or '.'");
    }
    Ok(())
}

impl Envelope {
    pub fn new(
        spec: &SessionSpec,
        sender: ParticipantId,
        recipient: Option<ParticipantId>,
        round: u32,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<Self, PrimitiveError> {
        spec.validate()?;
        let envelope = Envelope {
            wire_version: WIRE_VERSION,
            session_id: spec.session_id,
            protocol_id: spec.protocol_id.clone(),
            protocol_version: spec.protocol_version,
            sender,
            recipient,
            round,
            sequence,
            payload_hash: commitment("envelope-payload", &payload),
            payload,
        };
        envelope.validate_against(spec)?;
        Ok(envelope)
    }

    /// Checks structural/session binding but NOT transport authenticity.
    pub fn validate_against(&self, spec: &SessionSpec) -> Result<(), PrimitiveError> {
        spec.validate()?;
        if self.wire_version != WIRE_VERSION {
            return Err(PrimitiveError::InvalidEnvelope("unsupported wire version"));
        }
        if self.session_id != spec.session_id {
            return Err(PrimitiveError::WrongSession);
        }
        if self.protocol_id != spec.protocol_id || self.protocol_version != spec.protocol_version {
            return Err(PrimitiveError::WrongProtocol);
        }
        if !spec.contains(&self.sender) {
            return Err(PrimitiveError::SenderNotMember);
        }
        if let Some(recipient) = self.recipient.as_ref() {
            if !spec.contains(recipient) {
                return Err(PrimitiveError::RecipientNotMember);
            }
        }
        if self.round == 0 || self.round > spec.max_round {
            return Err(PrimitiveError::InvalidEnvelope("round outside session range"));
        }
        if self.sequence == 0 {
            return Err(PrimitiveError::InvalidEnvelope("sequence must be positive"));
        }
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(PrimitiveError::InvalidEnvelope("payload size limit exceeded"));
        }
        if self.payload_hash != commitment("envelope-payload", &self.payload) {
            return Err(PrimitiveError::PayloadDigestMismatch);
        }
        Ok(())
    }

    /// `authenticated_sender` MUST be provided by a trusted transport adapter,
    /// for example Holochain's call_info()?.provenance; never use a user field.
    pub fn validate_received(
        &self,
        spec: &SessionSpec,
        local_recipient: &[u8],
        authenticated_sender: &[u8],
    ) -> Result<(), PrimitiveError> {
        self.validate_against(spec)?;
        if self.sender.as_slice() != authenticated_sender {
            return Err(PrimitiveError::AuthenticatedSenderMismatch);
        }
        if !spec.contains(local_recipient) || self.sender.as_slice() == local_recipient {
            return Err(PrimitiveError::WrongRecipient);
        }
        if self.recipient.as_deref().is_some_and(|recipient| recipient != local_recipient) {
            return Err(PrimitiveError::WrongRecipient);
        }
        Ok(())
    }
}

impl ResultCommitment {
    pub fn new(spec: &SessionSpec, result_bytes: &[u8]) -> Result<Self, PrimitiveError> {
        spec.validate()?;
        Ok(Self {
            session_id: spec.session_id,
            protocol_id: spec.protocol_id.clone(),
            protocol_version: spec.protocol_version,
            result_hash: {
                // Bind commitments to the unique session as well as the
                // result bytes, reducing cross-session correlation.
                let mut bound = Vec::with_capacity(32 + result_bytes.len());
                bound.extend_from_slice(&spec.session_id);
                bound.extend_from_slice(result_bytes);
                commitment("result", &bound)
            },
        })
    }
}

/// A per-session, serializable replay ledger. Adapter MUST persist this before
/// acknowledging/acting on a message, and ensure atomic read-modify-write.
/// This does not solve distributed consensus or durable exactly-once delivery.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inbox {
    seen: BTreeSet<(ParticipantId, u32, u64)>,
}

impl Inbox {
    pub fn new() -> Self { Self::default() }

    pub fn len(&self) -> usize { self.seen.len() }

    pub fn is_empty(&self) -> bool { self.seen.is_empty() }

    pub fn accept(
        &mut self,
        spec: &SessionSpec,
        local_recipient: &[u8],
        authenticated_sender: &[u8],
        envelope: &Envelope,
    ) -> Result<(), PrimitiveError> {
        envelope.validate_received(spec, local_recipient, authenticated_sender)?;
        let key = (envelope.sender.clone(), envelope.round, envelope.sequence);
        if self.seen.contains(&key) {
            return Err(PrimitiveError::Replay);
        }
        if self.seen.len() >= MAX_MESSAGES_PER_SESSION {
            return Err(PrimitiveError::InboxFull);
        }
        self.seen.insert(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> ParticipantId { vec![byte; 39] }

    fn spec() -> SessionSpec {
        SessionSpec {
            session_id: [9; 32],
            application_id: "org.example.reusable".into(),
            protocol_id: "opaque-demo-v1".into(),
            protocol_version: 1,
            context_hash: [7; 32],
            participants: vec![id(1), id(2), id(3)],
            threshold: 2,
            max_round: 8,
        }
    }

    fn message() -> Envelope {
        Envelope::new(&spec(), id(1), Some(id(2)), 1, 1, b"not-secret-test-data".to_vec()).unwrap()
    }

    #[test]
    fn session_is_valid() { spec().validate().unwrap(); }

    #[test]
    fn duplicate_and_unsorted_participants_rejected() {
        let mut s = spec();
        s.participants = vec![id(1), id(1)];
        assert!(s.validate().is_err());
        s.participants = vec![id(2), id(1)];
        assert!(s.validate().is_err());
    }

    #[test]
    fn invalid_threshold_and_context_rejected() {
        let mut s = spec();
        s.threshold = 4;
        assert!(s.validate().is_err());
        s.threshold = 2;
        s.context_hash = [0; 32];
        assert!(s.validate().is_err());
    }

    #[test]
    fn valid_message_received_once() {
        let mut inbox = Inbox::new();
        let m = message();
        inbox.accept(&spec(), &id(2), &id(1), &m).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox.accept(&spec(), &id(2), &id(1), &m), Err(PrimitiveError::Replay));
    }

    #[test]
    fn forged_caller_rejected() {
        assert_eq!(message().validate_received(&spec(), &id(2), &id(3)),
            Err(PrimitiveError::AuthenticatedSenderMismatch));
    }

    #[test]
    fn wrong_recipient_rejected() {
        assert_eq!(message().validate_received(&spec(), &id(3), &id(1)),
            Err(PrimitiveError::WrongRecipient));
    }

    #[test]
    fn modified_payload_rejected() {
        let mut m = message();
        m.payload.push(42);
        assert_eq!(m.validate_against(&spec()), Err(PrimitiveError::PayloadDigestMismatch));
    }

    #[test]
    fn session_and_protocol_binding_enforced() {
        let mut m = message();
        m.session_id = [5; 32];
        assert_eq!(m.validate_against(&spec()), Err(PrimitiveError::WrongSession));
        m = message();
        m.protocol_id = "other".to_string();
        assert_eq!(m.validate_against(&spec()), Err(PrimitiveError::WrongProtocol));
    }

    #[test]
    fn rejects_nonmember_and_bad_round() {
        assert_eq!(Envelope::new(&spec(), id(4), None, 1, 1, vec![]),
            Err(PrimitiveError::SenderNotMember));
        assert!(Envelope::new(&spec(), id(1), None, 9, 1, vec![]).is_err());
    }

    #[test]
    fn enforces_payload_limit() {
        let bytes = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        assert!(Envelope::new(&spec(), id(1), None, 1, 1, bytes).is_err());
    }

    #[test]
    fn result_commitment_is_deterministic_and_bound() {
        let c1 = ResultCommitment::new(&spec(), b"result").unwrap();
        let c2 = ResultCommitment::new(&spec(), b"result").unwrap();
        assert_eq!(c1, c2);
        assert_ne!(c1.result_hash, commitment("envelope-payload", b"result"));
    }
}
