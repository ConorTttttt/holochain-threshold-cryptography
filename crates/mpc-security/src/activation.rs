//! Group activation and signing authorisation. These state machines consume
//! identities already authenticated by Holochain/RPC. Votes are NOT portable
//! signatures: their transport evidence must be retained or signed separately.
//! No caller can deserialize a forged `ActivatedGroup` or `ApprovedIntent`.
use std::collections::{BTreeMap, BTreeSet};
use serde::{Serialize, Deserialize};
use holochain_mpc_core::{commitment, ParticipantId, SessionSpec};
use crate::SecurityError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDescriptor {
    pub proposal_action: Vec<u8>,
    pub spec: SessionSpec,
    pub epoch: u64,
    pub dkg_transcript_hash: [u8;32],
    /// Hash of the EXACT canonical FROST PublicKeyPackage encoding.
    pub public_key_package_hash: [u8;32],
    pub group_verifying_key: Vec<u8>,
    /// Author-signed entry-action hashes, sorted in SessionSpec participant order.
    pub encryption_key_binding_actions: Vec<Vec<u8>>,
}
impl GroupDescriptor {
    pub fn validate(&self) -> Result<(), SecurityError> {
        self.spec.validate().map_err(|_| SecurityError::Invalid("invalid group session"))?;
        if self.proposal_action.len() != 39 || self.dkg_transcript_hash == [0;32] ||
           self.public_key_package_hash == [0;32] || self.group_verifying_key.len() != 32 ||
           self.encryption_key_binding_actions.len() != self.spec.participants.len() ||
           self.encryption_key_binding_actions.iter().any(|h| h.len()!=39) ||
           self.encryption_key_binding_actions.iter().collect::<BTreeSet<_>>().len() != self.spec.participants.len() {
            return Err(SecurityError::Invalid("missing or ambiguous group commitments"));
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8;32], SecurityError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|_| SecurityError::Crypto)?;
        Ok(commitment("group-activation-v1", &encoded))
    }
}

pub struct GroupActivation {
    proposal: GroupDescriptor,
    votes: BTreeMap<ParticipantId,[u8;32]>,
    halted: bool,
}
/// Only issued after every session member has independently attested to the
/// identical, canonical public key package and group descriptor. It is LOCAL
/// verified evidence, not independently portable signature proof.
#[derive(Clone, Debug)]
pub struct ActivatedGroup { descriptor: GroupDescriptor, certificate_digest: [u8;32] }
impl ActivatedGroup {
    pub fn descriptor(&self) -> &GroupDescriptor { &self.descriptor }
    pub fn digest(&self) -> [u8;32] { self.certificate_digest }
}
impl GroupActivation {
    pub fn new(descriptor: GroupDescriptor) -> Result<Self, SecurityError> {
        descriptor.validate()?;
        Ok(Self { proposal: descriptor, votes: BTreeMap::new(), halted:false })
    }
    pub fn expected_digest(&self) -> Result<[u8;32], SecurityError> { self.proposal.digest() }
    /// `authenticated_sender` is from verified call provenance/author-signed DHT
    /// record, never from user-supplied payload metadata.
    pub fn attest(&mut self, authenticated_sender: &[u8], claimed: [u8;32]) -> Result<(), SecurityError> {
        if self.halted { return Err(SecurityError::Aborted); }
        if !self.proposal.spec.contains(authenticated_sender) { return Err(SecurityError::Unauthorized); }
        if claimed != self.expected_digest()? {
            self.halted = true;
            return Err(SecurityError::AttestationMismatch);
        }
        match self.votes.get(authenticated_sender) {
            Some(previous) if *previous != claimed => { self.halted=true; Err(SecurityError::Equivocation) },
            Some(_) => Ok(()),
            None => { self.votes.insert(authenticated_sender.to_vec(), claimed); Ok(()) },
        }
    }
    pub fn finalize(self) -> Result<ActivatedGroup, SecurityError> {
        if self.halted { return Err(SecurityError::Aborted); }
        if self.votes.len() != self.proposal.spec.participants.len() { return Err(SecurityError::NotReady); }
        let digest = self.proposal.digest()?;
        if self.votes.values().any(|v| *v != digest) { return Err(SecurityError::AttestationMismatch); }
        Ok(ActivatedGroup { descriptor: self.proposal, certificate_digest: digest })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningProfile { ContextBoundV1, ExternalExactBytesV1 }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningIntent {
    pub proposal_action: Vec<u8>,
    pub group_epoch: u64,
    pub group_certificate_digest: [u8;32],
    pub operation_id: [u8;32],
    pub message_hash: [u8;32],
    pub profile: SigningProfile,
    /// Exact selected signer roster, in canonical identity order.
    pub selected: Vec<ParticipantId>,
}
impl SigningIntent {
    pub fn new(group: &ActivatedGroup, operation_id: [u8;32], message: &[u8],
               selected: Vec<ParticipantId>, profile: SigningProfile) -> Result<Self, SecurityError> {
        let spec = &group.descriptor.spec;
        if operation_id == [0;32] || operation_id == spec.session_id || message.is_empty() ||
           selected.len() < spec.threshold as usize || selected.len() > spec.participants.len() ||
           selected.windows(2).any(|s| s[0]>=s[1]) || selected.iter().any(|p| !spec.contains(p)) {
            return Err(SecurityError::Invalid("invalid signer roster or message"));
        }
        Ok(Self { proposal_action: group.descriptor.proposal_action.clone(),
            group_epoch: group.descriptor.epoch, group_certificate_digest: group.digest(),
            operation_id, message_hash: commitment("signing-intent-message", message), profile, selected })
    }
    pub fn digest(&self) -> Result<[u8;32], SecurityError> {
        let bytes = serde_json::to_vec(self).map_err(|_| SecurityError::Crypto)?;
        Ok(commitment("signing-intent-v1", &bytes))
    }
}

pub struct IntentApprovals {
    intent: SigningIntent,
    approved: BTreeSet<ParticipantId>,
    aborted: bool,
}
/// Local token created only after every selected signer explicitly approves.
/// Not a substitute for an application-specific policy/consent UX.
#[derive(Clone, Debug)]
pub struct ApprovedIntent { intent: SigningIntent, digest: [u8;32] }
impl ApprovedIntent {
    pub fn intent(&self) -> &SigningIntent { &self.intent }
    pub fn digest(&self) -> [u8;32] { self.digest }
}
impl IntentApprovals {
    pub fn new(intent: SigningIntent) -> Self {
        Self { intent, approved:BTreeSet::new(), aborted:false }
    }
    pub fn expected_digest(&self) -> Result<[u8;32], SecurityError> { self.intent.digest() }
    pub fn approve(&mut self, authenticated_signer: &[u8], approved_hash: [u8;32]) -> Result<(), SecurityError> {
        if self.aborted { return Err(SecurityError::Aborted); }
        if !self.intent.selected.iter().any(|p| p==authenticated_signer) { return Err(SecurityError::Unauthorized); }
        if approved_hash != self.intent.digest()? {
            self.aborted=true;
            return Err(SecurityError::AttestationMismatch);
        }
        self.approved.insert(authenticated_signer.to_vec());
        Ok(())
    }
    pub fn finalize(self) -> Result<ApprovedIntent, SecurityError> {
        if self.aborted { return Err(SecurityError::Aborted); }
        if self.approved.len() != self.intent.selected.len() { return Err(SecurityError::NotReady); }
        Ok(ApprovedIntent { digest:self.intent.digest()?, intent:self.intent })
    }
}

/// Fail closed on key rollback. This is a *local* view; conflicting authored
/// forks can exist in the DHT. A running session must pin binding action hashes.
#[derive(Clone, Debug)]
pub struct PinnedKeyChain {
    pub member: ParticipantId,
    pub epoch: u64,
    pub binding_action: Vec<u8>,
    pub public_key: [u8;32],
}
impl PinnedKeyChain {
    pub fn rotate(&self, authenticated_author: &[u8], previous_action: &[u8],
                  new_epoch: u64, new_action: Vec<u8>, new_key: [u8;32]) -> Result<Self, SecurityError> {
        if authenticated_author != self.member.as_slice() || previous_action != self.binding_action.as_slice() ||
           new_epoch != self.epoch.checked_add(1).ok_or(SecurityError::Invalid("epoch overflow"))? ||
           new_action.len() != 39 || new_key == [0;32] || new_key == self.public_key {
            return Err(SecurityError::Invalid("key-chain rollback, fork or wrong author"));
        }
        Ok(Self { member: self.member.clone(), epoch:new_epoch, binding_action:new_action, public_key:new_key })
    }
}
