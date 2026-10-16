//! Public, deterministic policy for the generic MPC session coordination DNA.
//! NO protocol shares or secret payloads are published on the DHT.
use hdi::prelude::*;
use holochain_mpc_core::{ResultCommitment, SessionSpec};

const MAX_VERIFICATION_ARTIFACT: usize = 16 * 1024;

#[derive(Clone, PartialEq)]
#[hdk_entry_helper]
pub struct SessionProposal {
    pub spec: SessionSpec,
}

#[derive(Clone, PartialEq)]
#[hdk_entry_helper]
pub struct SessionAcceptance {
    pub proposal: ActionHash,
    pub session_id: [u8; 32],
}

/// A public, *unverified* output commitment; never assert computation correctness.
#[derive(Clone, PartialEq)]
#[hdk_entry_helper]
pub struct OutputProposal {
    pub proposal: ActionHash,
    pub commitment: ResultCommitment,
    /// Opaque public verifier material. v0.2 does NOT check it cryptographically.
    pub verification_artifact: Vec<u8>,
}

/// Author-signed, immutable per-session X25519 public-key registration.
/// Consumers MUST pin an exact entry ActionHash; if multiple valid keys exist,
/// never silently choose "latest" by DHT timestamp.
#[derive(Clone, PartialEq)]
#[hdk_entry_helper]
pub struct EncryptionKeyBinding {
    pub proposal: ActionHash,
    pub public_key: [u8; 32],
}

/// Optional author-signed echo-transcript attestation. DHT presence is only
/// audit evidence: validators cannot establish whether the echo protocol ran.
#[derive(Clone, PartialEq)]
#[hdk_entry_helper]
pub struct TranscriptCheckpoint {
    pub proposal: ActionHash,
    pub transcript_hash: [u8; 32],
}

/// Append-only author-controlled key epochs. An action signature authenticates
/// the Holochain agent, but X25519 proof-of-possession requires native challenge.
#[derive(Clone, PartialEq)]
#[hdk_entry_helper]
pub struct EncryptionKeyEpoch {
    pub proposal: ActionHash,
    pub epoch: u64,
    pub public_key: [u8;32],
    pub previous_binding: Option<ActionHash>,
}

/// Public, author-signed DKG finalisation declaration. Network validators
/// only check structure and membership; a native FROST participant must check
/// the agreed public key package and verified broadcast before publishing.
#[derive(Clone, PartialEq)]
#[hdk_entry_helper]
pub struct GroupActivationAttestation {
    pub proposal: ActionHash,
    pub epoch: u64,
    pub descriptor_hash: [u8;32],
    pub dkg_transcript_hash: [u8;32],
    pub public_key_package_hash: [u8;32],
}

/// Optional public consent digest. Do not put an application plaintext message
/// in the DHT; the native controller approves the full canonical intent.
#[derive(Clone, PartialEq)]
#[hdk_entry_helper]
pub struct SigningApprovalAttestation {
    pub proposal: ActionHash,
    pub operation_id: [u8;32],
    pub group_descriptor_hash: [u8;32],
    pub intent_hash: [u8;32],
}

/// The actual envelope is private to the recipient's source chain.
#[derive(Clone, PartialEq)]
#[hdk_entry_helper]
pub struct InboxEvent {
    pub proposal: ActionHash,
    pub envelope: holochain_mpc_core::Envelope,
}

#[derive(Serialize, Deserialize)]
#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
pub enum EntryTypes {
    SessionProposal(SessionProposal),
    SessionAcceptance(SessionAcceptance),
    OutputProposal(OutputProposal),
    #[entry_type(visibility = "private")]
    InboxEvent(InboxEvent),
    EncryptionKeyBinding(EncryptionKeyBinding),
    TranscriptCheckpoint(TranscriptCheckpoint),
    // Append only: preserve historical entry indices (Holochain DNA break).
    EncryptionKeyEpoch(EncryptionKeyEpoch),
    GroupActivationAttestation(GroupActivationAttestation),
    SigningApprovalAttestation(SigningApprovalAttestation),
}

#[derive(Serialize, Deserialize)]
#[hdk_link_types]
pub enum LinkTypes {
    SessionToAcceptances,
    SessionToOutputs,
    AgentToSessions,
    SessionToEncryptionKeys,
    SessionToTranscripts,
    SessionToKeyEpochs,
    SessionToGroupAttestations,
    SessionToSigningApprovals,
}

fn invalid(message: &str) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Invalid(message.into()))
}

// Decode using the action's registered entry type, not by merely attempting
// to deserialize arbitrary entry bytes as a SessionProposal.
fn typed_public_entry(record: &Record) -> ExternResult<Option<EntryTypes>> {
    let (zome_index, entry_index) = match record.action().entry_type() {
        Some(EntryType::App(AppEntryDef { zome_index, entry_index, .. })) => (*zome_index, *entry_index),
        _ => return Ok(None),
    };
    let Some(entry) = record.entry().as_option() else { return Ok(None); };
    EntryTypes::deserialize_from_type(zome_index, entry_index, entry)
}

fn proposal_at(hash: ActionHash) -> ExternResult<(SessionProposal, AgentPubKey)> {
    let record = must_get_valid_record(hash)?;
    let author = record.action().author().clone();
    match typed_public_entry(&record)? {
        Some(EntryTypes::SessionProposal(p)) => Ok((p, author)),
        _ => Err(wasm_error!(WasmErrorInner::Guest("Expected SessionProposal action".into()))),
    }
}

fn validate_entry(entry: EntryTypes, author: &AgentPubKey) -> ExternResult<ValidateCallbackResult> {
    match entry {
        EntryTypes::SessionProposal(p) => {
            if let Err(error) = p.spec.validate() { return invalid(&error.to_string()); }
            if !p.spec.contains(author.get_raw_39()) {
                return invalid("Proposer must be a session participant");
            }
            // Holochain agent IDs are exact 39-byte public keys, not arbitrary IDs.
            if p.spec.participants.iter().any(|id| AgentPubKey::try_from_raw_39(id.clone()).is_err()) {
                return invalid("Invalid Holochain participant key bytes");
            }
            Ok(ValidateCallbackResult::Valid)
        }
        EntryTypes::SessionAcceptance(a) => {
            let (p, _) = proposal_at(a.proposal)?;
            if p.spec.session_id != a.session_id { return invalid("Acceptance session mismatch"); }
            if !p.spec.contains(author.get_raw_39()) { return invalid("Accepting author not a member"); }
            Ok(ValidateCallbackResult::Valid)
        }
        EntryTypes::OutputProposal(o) => {
            let (p, _) = proposal_at(o.proposal)?;
            if !p.spec.contains(author.get_raw_39()) { return invalid("Output author not a member"); }
            if o.commitment.session_id != p.spec.session_id
                || o.commitment.protocol_id != p.spec.protocol_id
                || o.commitment.protocol_version != p.spec.protocol_version
                || o.commitment.result_hash == [0; 32]
                || o.verification_artifact.len() > MAX_VERIFICATION_ARTIFACT
            { return invalid("Invalid output commitment or verification material"); }
            Ok(ValidateCallbackResult::Valid)
        }
        EntryTypes::EncryptionKeyBinding(k) => {
            let (proposal, _) = proposal_at(k.proposal)?;
            if !proposal.spec.contains(author.get_raw_39()) || k.public_key == [0;32] {
                return invalid("Encryption key must be registered by a session member");
            }
            Ok(ValidateCallbackResult::Valid)
        }
        EntryTypes::EncryptionKeyEpoch(k) => {
            let (proposal,_) = proposal_at(k.proposal.clone())?;
            if !proposal.spec.contains(author.get_raw_39()) || k.public_key == [0;32] {
                return invalid("Only a session member can bind a nonzero encryption key");
            }
            if k.epoch == 0 {
                if k.previous_binding.is_some() { return invalid("Epoch zero cannot have a predecessor"); }
            } else {
                let Some(parent) = k.previous_binding else { return invalid("Rotation must identify predecessor action"); };
                let record = must_get_valid_record(parent)?;
                if record.action().author() != author { return invalid("Key rotation must preserve author"); }
                match typed_public_entry(&record)? {
                    Some(EntryTypes::EncryptionKeyEpoch(old)) if old.proposal == k.proposal &&
                        old.epoch.checked_add(1) == Some(k.epoch) && old.public_key != k.public_key => (),
                    _ => return invalid("Key rotation must advance exactly one epoch of same session"),
                }
            }
            Ok(ValidateCallbackResult::Valid)
        }
        EntryTypes::GroupActivationAttestation(a) => {
            let (proposal,_) = proposal_at(a.proposal)?;
            if !proposal.spec.contains(author.get_raw_39()) || a.descriptor_hash == [0;32] ||
                a.dkg_transcript_hash == [0;32] || a.public_key_package_hash == [0;32] {
                return invalid("Invalid group activation declaration");
            }
            Ok(ValidateCallbackResult::Valid)
        }
        EntryTypes::SigningApprovalAttestation(a) => {
            let (proposal,_) = proposal_at(a.proposal)?;
            if !proposal.spec.contains(author.get_raw_39()) || a.intent_hash == [0;32] ||
                a.group_descriptor_hash == [0;32] || a.operation_id == [0;32] ||
                a.operation_id == proposal.spec.session_id {
                return invalid("Invalid signing approval declaration");
            }
            Ok(ValidateCallbackResult::Valid)
        }
        EntryTypes::TranscriptCheckpoint(c) => {
            let (proposal, _) = proposal_at(c.proposal)?;
            if !proposal.spec.contains(author.get_raw_39()) || c.transcript_hash == [0;32] {
                return invalid("Checkpoint requires a member author and a nonzero transcript hash");
            }
            Ok(ValidateCallbackResult::Valid)
        }
        // Private entry contents are invisible to network validators. The
        // recipient coordinator checks envelopes and persists them locally.
        EntryTypes::InboxEvent(_) => Ok(ValidateCallbackResult::Valid),
    }
}

fn validate_link(action: TypedAction<CreateLinkData>, kind: LinkTypes) -> ExternResult<ValidateCallbackResult> {
    let is_acceptance = matches!(&kind, LinkTypes::SessionToAcceptances);
    let base = action.data.base_address.clone();
    let target = action.data.target_address.clone();
    match kind {
        LinkTypes::SessionToAcceptances | LinkTypes::SessionToOutputs | LinkTypes::SessionToEncryptionKeys |
        LinkTypes::SessionToTranscripts | LinkTypes::SessionToKeyEpochs |
        LinkTypes::SessionToGroupAttestations | LinkTypes::SessionToSigningApprovals => {
            let Some(base_hash) = base.into_action_hash() else { return invalid("Link base must be a proposal action"); };
            let Some(target_hash) = target.into_action_hash() else { return invalid("Link target must be an entry action"); };
            let (_proposal, _) = proposal_at(base_hash.clone())?;
            let record = must_get_valid_record(target_hash)?;
            if action.author() != record.action().author() { return invalid("Only entry author may index it"); }
            if is_acceptance {
                match typed_public_entry(&record)? {
                    Some(EntryTypes::SessionAcceptance(a)) if a.proposal == base_hash => Ok(ValidateCallbackResult::Valid),
                    _ => invalid("Acceptance link must point at its proposal"),
                }
            } else if matches!(kind, LinkTypes::SessionToOutputs) {
                match typed_public_entry(&record)? {
                    Some(EntryTypes::OutputProposal(o)) if o.proposal == base_hash => Ok(ValidateCallbackResult::Valid),
                    _ => invalid("Output link must point at its proposal"),
                }
            } else if matches!(kind, LinkTypes::SessionToEncryptionKeys) {
                match typed_public_entry(&record)? {
                    Some(EntryTypes::EncryptionKeyBinding(k)) if k.proposal == base_hash => Ok(ValidateCallbackResult::Valid),
                    _ => invalid("Encryption key link must point at its proposal"),
                }
            } else if matches!(kind, LinkTypes::SessionToKeyEpochs) {
                match typed_public_entry(&record)? {
                    Some(EntryTypes::EncryptionKeyEpoch(k)) if k.proposal == base_hash => Ok(ValidateCallbackResult::Valid),
                    _ => invalid("Key epoch link must point at its own proposal"),
                }
            } else if matches!(kind, LinkTypes::SessionToGroupAttestations) {
                match typed_public_entry(&record)? {
                    Some(EntryTypes::GroupActivationAttestation(a)) if a.proposal == base_hash => Ok(ValidateCallbackResult::Valid),
                    _ => invalid("Group attestation link must point at its own proposal"),
                }
            } else if matches!(kind, LinkTypes::SessionToSigningApprovals) {
                match typed_public_entry(&record)? {
                    Some(EntryTypes::SigningApprovalAttestation(a)) if a.proposal == base_hash => Ok(ValidateCallbackResult::Valid),
                    _ => invalid("Signing approval link must point at its own proposal"),
                }
            } else {
                match typed_public_entry(&record)? {
                    Some(EntryTypes::TranscriptCheckpoint(c)) if c.proposal == base_hash => Ok(ValidateCallbackResult::Valid),
                    _ => invalid("Transcript link must point at its proposal"),
                }
            }
        }
        LinkTypes::AgentToSessions => {
            let Some(base_agent) = base.into_agent_pub_key() else { return invalid("Base must be agent"); };
            let Some(target_hash) = target.into_action_hash() else { return invalid("Target must be proposal"); };
            let (p, _) = proposal_at(target_hash)?;
            if &base_agent != action.author() || !p.spec.contains(base_agent.get_raw_39()) {
                return invalid("Agent index must be authored by participant");
            }
            Ok(ValidateCallbackResult::Valid)
        }
    }
}

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    match op.flattened::<EntryTypes, LinkTypes>()? {
        FlatOp::CreateEntry(op) => match op {
            OpEntry::CreateEntry { app_entry, action } => validate_entry(app_entry, action.author()),
            OpEntry::UpdateEntry { .. } => invalid("MPC records are immutable"),
            _ => Ok(ValidateCallbackResult::Valid),
        },
        FlatOp::CreateRecord(op) => match op {
            OpRecord::CreateEntry { app_entry, action } => validate_entry(app_entry, action.author()),
            OpRecord::UpdateEntry { .. } | OpRecord::DeleteEntry { .. } => invalid("MPC records are append-only"),
            OpRecord::CreateLink { link_type, action } => validate_link(action, link_type),
            OpRecord::DeleteLink { .. } => invalid("MPC index links are append-only"),
            _ => Ok(ValidateCallbackResult::Valid),
        },
        FlatOp::Update(update) => match update {
            OpUpdate::Entry { .. } => invalid("MPC app entries are immutable"),
            // Capability grant and claim updates remain permitted.
            _ => Ok(ValidateCallbackResult::Valid),
        },
        FlatOp::Delete(OpDelete { action }) => {
            let original = must_get_valid_record(action.deletes_address.clone())?;
            // Do not interfere with revocation of a private CapGrant or CapClaim.
            match original.action().entry_type() {
                Some(EntryType::App(_)) => invalid("MPC app entries are append-only"),
                _ => Ok(ValidateCallbackResult::Valid),
            }
        },
        FlatOp::Link(OpLink::CreateLink { link_type, action }) => validate_link(action, link_type),
        FlatOp::Link(OpLink::DeleteLink { .. }) => invalid("MPC links cannot be deleted"),
        _ => Ok(ValidateCallbackResult::Valid),
    }
}
