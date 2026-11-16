//! Opt-in, non-deployed v2 ceremony-bound transport primitive (S1-M02).
//!
//! This type deliberately does NOT replace v1 `Envelope` or the existing
//! Holochain coordinator's InboxEvent. A new DNA/transport protocol needs a
//! separate architectural decision. Never coerce a v1 envelope into v2.

use crate::{
    commitment, ParticipantId, PrimitiveError, SessionId, SessionSpec,
    MAX_MESSAGES_PER_SESSION, MAX_PAYLOAD_BYTES,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const BOUND_WIRE_VERSION: u16 = 2;

/// The trusted host must load the exact fully accepted proposal action from
/// the intended DNA and verify the application-specific *canonical* operation
/// description before constructing this value. Raw hashes are identifiers,
/// not proof of a valid Holochain proposal or a canonical application intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyBindingV2 {
    /// Raw Holochain DnaHash bytes (not a network label or caller claim).
    pub dna_hash: Vec<u8>,
    /// Raw ActionHash of the exact SessionProposal entry in that DNA.
    pub proposal_action: Vec<u8>,
    /// Exact accepted proposal's session spec, including the application's
    /// canonical context digest and entire roster.
    pub spec: SessionSpec,
}

fn append(parts: &mut Vec<u8>, bytes: &[u8]) {
    parts.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    parts.extend_from_slice(bytes);
}

impl CeremonyBindingV2 {
    /// Stable, domain-separated commitment. All variable-length inputs and
    /// participant identities have explicit lengths; participants are sorted.
    /// This is not a signature, MAC, or validation of Holochain hash prefixes.
    pub fn digest(&self) -> Result<[u8; 32], PrimitiveError> {
        self.spec.validate()?;
        if self.dna_hash.len() != 39 || self.dna_hash.iter().all(|x| *x == 0) {
            return Err(PrimitiveError::InvalidSession("expected a nonzero 39-byte DNA hash"));
        }
        if self.proposal_action.len() != 39 || self.proposal_action.iter().all(|x| *x == 0) {
            return Err(PrimitiveError::InvalidSession("expected a nonzero 39-byte proposal action"));
        }
        let s = &self.spec;
        let mut data = Vec::new();
        append(&mut data, &self.dna_hash);
        append(&mut data, &self.proposal_action);
        append(&mut data, &s.session_id);
        append(&mut data, s.application_id.as_bytes());
        append(&mut data, s.protocol_id.as_bytes());
        append(&mut data, &s.protocol_version.to_be_bytes());
        append(&mut data, &s.context_hash);
        append(&mut data, &(s.participants.len() as u64).to_be_bytes());
        for member in &s.participants {
            append(&mut data, member);
        }
        append(&mut data, &s.threshold.to_be_bytes());
        append(&mut data, &s.max_round.to_be_bytes());
        Ok(commitment("ceremony-binding/v2", &data))
    }
}

/// An intentionally distinct v2 wire type: no new fields are added to v1,
/// and there is no implicit conversion from v1. An adapter MUST explicitly
/// decode this type and MUST reject any wire_version other than exactly 2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundEnvelopeV2 {
    pub wire_version: u16,
    pub binding_hash: [u8; 32],
    pub session_id: SessionId,
    pub protocol_id: String,
    pub protocol_version: u16,
    pub sender: ParticipantId,
    pub recipient: Option<ParticipantId>,
    pub round: u32,
    pub sequence: u64,
    /// Domain-separated digest of the bound envelope, not an origin signature.
    pub payload_hash: [u8; 32],
    /// Private; do not put the plaintext on the DHT.
    pub payload: Vec<u8>,
}

impl BoundEnvelopeV2 {
    fn digest_payload(&self) -> [u8; 32] {
        let mut data = Vec::new();
        append(&mut data, &self.wire_version.to_be_bytes());
        append(&mut data, &self.binding_hash);
        append(&mut data, &self.session_id);
        append(&mut data, self.protocol_id.as_bytes());
        append(&mut data, &self.protocol_version.to_be_bytes());
        append(&mut data, &self.sender);
        match &self.recipient {
            None => append(&mut data, &[0]),
            Some(recipient) => {
                append(&mut data, &[1]);
                append(&mut data, recipient);
            }
        }
        append(&mut data, &self.round.to_be_bytes());
        append(&mut data, &self.sequence.to_be_bytes());
        append(&mut data, &self.payload);
        commitment("bound-envelope-payload/v2", &data)
    }

    pub fn new(
        binding: &CeremonyBindingV2,
        sender: ParticipantId,
        recipient: Option<ParticipantId>,
        round: u32,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<Self, PrimitiveError> {
        let mut env = Self {
            wire_version: BOUND_WIRE_VERSION,
            binding_hash: binding.digest()?,
            session_id: binding.spec.session_id,
            protocol_id: binding.spec.protocol_id.clone(),
            protocol_version: binding.spec.protocol_version,
            sender,
            recipient,
            round,
            sequence,
            payload_hash: [0; 32],
            payload,
        };
        env.payload_hash = env.digest_payload();
        env.validate_against(binding)?;
        Ok(env)
    }

    /// Validates the EXACT trusted DNA, proposal, application and full spec.
    /// This does NOT authenticate the sender; use validate_received.
    pub fn validate_against(&self, binding: &CeremonyBindingV2) -> Result<(), PrimitiveError> {
        let expected = binding.digest()?;
        if self.wire_version != BOUND_WIRE_VERSION {
            return Err(PrimitiveError::InvalidEnvelope("v2 required; no legacy downgrade"));
        }
        if self.binding_hash != expected {
            return Err(PrimitiveError::InvalidEnvelope("wrong DNA, proposal or application context"));
        }
        let spec = &binding.spec;
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
        if self.payload_hash != self.digest_payload() {
            return Err(PrimitiveError::PayloadDigestMismatch);
        }
        Ok(())
    }

    /// Caller identity MUST come from an authenticated transport such as
    /// Holochain call_info().provenance, never from these untrusted bytes.
    pub fn validate_received(
        &self,
        binding: &CeremonyBindingV2,
        local_recipient: &[u8],
        authenticated_sender: &[u8],
    ) -> Result<(), PrimitiveError> {
        self.validate_against(binding)?;
        if self.sender.as_slice() != authenticated_sender {
            return Err(PrimitiveError::AuthenticatedSenderMismatch);
        }
        if !binding.spec.contains(local_recipient) || self.sender.as_slice() == local_recipient {
            return Err(PrimitiveError::WrongRecipient);
        }
        if self.recipient.as_deref().is_some_and(|r| r != local_recipient) {
            return Err(PrimitiveError::WrongRecipient);
        }
        Ok(())
    }
}

/// Separate v2 replay ledger. Do not reuse the legacy Inbox state or accept
/// entries from another binding after the first successful delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundInboxV2 {
    // Required field: legacy Inbox serialization must NOT decode as v2.
    ledger_version: u16,
    binding_hash: Option<[u8; 32]>,
    seen: BTreeSet<(ParticipantId, u32, u64)>,
}

impl Default for BoundInboxV2 {
    fn default() -> Self {
        Self {
            ledger_version: BOUND_WIRE_VERSION,
            binding_hash: None,
            seen: BTreeSet::new(),
        }
    }
}

impl BoundInboxV2 {
    pub fn new() -> Self { Self::default() }
    pub fn len(&self) -> usize { self.seen.len() }

    /// Persist the entire modified ledger atomically BEFORE acknowledging or
    /// acting upon a message; the core provides no distributed transaction.
    pub fn accept(
        &mut self,
        binding: &CeremonyBindingV2,
        local_recipient: &[u8],
        authenticated_sender: &[u8],
        envelope: &BoundEnvelopeV2,
    ) -> Result<(), PrimitiveError> {
        envelope.validate_received(binding, local_recipient, authenticated_sender)?;
        if self.ledger_version != BOUND_WIRE_VERSION ||
            (self.binding_hash.is_none() && !self.seen.is_empty()) {
            return Err(PrimitiveError::InvalidEnvelope("ambiguous or legacy replay ledger"));
        }
        if self.binding_hash.is_some_and(|previous| previous != envelope.binding_hash) {
            return Err(PrimitiveError::InvalidEnvelope("inbox bound to another ceremony"));
        }
        let key = (envelope.sender.clone(), envelope.round, envelope.sequence);
        if self.seen.contains(&key) {
            return Err(PrimitiveError::Replay);
        }
        if self.seen.len() >= MAX_MESSAGES_PER_SESSION {
            return Err(PrimitiveError::InboxFull);
        }
        self.seen.insert(key);
        self.binding_hash = Some(envelope.binding_hash);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Envelope, WIRE_VERSION};

    fn id(b: u8) -> Vec<u8> { vec![b; 39] }
    fn binding() -> CeremonyBindingV2 {
        CeremonyBindingV2 {
            dna_hash: id(91),
            proposal_action: id(92),
            spec: SessionSpec {
                session_id: [9; 32],
                application_id: "org.example.application-a".into(),
                protocol_id: "opaque-demo".into(),
                protocol_version: 1,
                context_hash: [7; 32],
                participants: vec![id(1), id(2), id(3)],
                threshold: 2,
                max_round: 8,
            },
        }
    }
    fn msg(binding: &CeremonyBindingV2) -> BoundEnvelopeV2 {
        BoundEnvelopeV2::new(binding, id(1), Some(id(2)), 1, 1, b"opaque-round".to_vec()).unwrap()
    }

    /// Current v1 vulnerability reproduced, not a security guarantee.
    #[test]
    fn legacy_v1_cross_application_acceptance_is_reproduced() {
        let a = binding();
        let mut b = a.clone();
        b.spec.application_id = "org.example.application-b".into();
        b.spec.context_hash = [8; 32];
        let legacy = Envelope::new(&a.spec, id(1), Some(id(2)), 1, 1, vec![99]).unwrap();
        assert_eq!(legacy.wire_version, WIRE_VERSION);
        assert!(legacy.validate_received(&b.spec, &id(2), &id(1)).is_ok());
    }

    #[test]
    fn cross_application_envelope_replay_is_rejected() {
        let a = binding();
        let envelope = msg(&a);
        let mut b = a.clone();
        b.spec.application_id = "org.example.application-b".into();
        assert!(envelope.validate_received(&b, &id(2), &id(1)).is_err());
        b = a.clone();
        b.spec.context_hash = [8; 32];
        assert!(envelope.validate_received(&b, &id(2), &id(1)).is_err());
        b.spec.application_id = "org.example.application-b".into();
        assert!(envelope.validate_received(&b, &id(2), &id(1)).is_err());
    }

    #[test]
    fn cross_proposal_envelope_replay_is_rejected() {
        let a = binding();
        let envelope = msg(&a);
        let mut b = a.clone();
        b.proposal_action = id(93);
        assert!(envelope.validate_received(&b, &id(2), &id(1)).is_err());
        b = a.clone();
        b.dna_hash = id(94);
        assert!(envelope.validate_received(&b, &id(2), &id(1)).is_err());
        let mut second_ledger = BoundInboxV2::new();
        let second = msg(&b);
        second_ledger.accept(&b, &id(2), &id(1), &second).unwrap();
        assert!(second_ledger.accept(&a, &id(2), &id(1), &envelope).is_err());
    }

    #[test]
    fn same_proposal_valid_envelope_still_delivers() {
        let a = binding();
        let envelope = msg(&a);
        let mut inbox = BoundInboxV2::new();
        inbox.accept(&a, &id(2), &id(1), &envelope).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox.accept(&a, &id(2), &id(1), &envelope), Err(PrimitiveError::Replay));
        assert_eq!(envelope.validate_received(&a, &id(2), &id(3)),
                   Err(PrimitiveError::AuthenticatedSenderMismatch));
    }

    #[test]
    fn legacy_wire_version_and_mutations_fail_closed() {
        let a = binding();
        let mut envelope = msg(&a);
        envelope.wire_version = WIRE_VERSION;
        assert!(envelope.validate_against(&a).is_err());
        envelope = msg(&a);
        envelope.binding_hash = [44; 32];
        assert!(envelope.validate_against(&a).is_err());
        envelope = msg(&a);
        envelope.payload.push(42);
        assert_eq!(envelope.validate_against(&a), Err(PrimitiveError::PayloadDigestMismatch));
        let mut legacy_ledger = BoundInboxV2::new();
        legacy_ledger.ledger_version = WIRE_VERSION;
        assert!(legacy_ledger.accept(&a, &id(2), &id(1), &msg(&a)).is_err());
        let mut malformed = a;
        malformed.proposal_action = vec![3; 38];
        assert!(malformed.digest().is_err());
    }
}
