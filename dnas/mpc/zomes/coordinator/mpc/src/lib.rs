//! Reusable MPC coordination zome for Holochain 0.7.
//! v0.2 deliberately DOES NOT execute any cryptographic protocol effects.
use hdk::prelude::*;
use holochain_mpc_core::{Envelope, ResultCommitment, SessionSpec, SealedPacket, MAX_MESSAGES_PER_SESSION};
use holochain_mpc_adapter::{authenticate_incoming, ensure_local_member};
use mpc_integrity::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};

fn guest(message: impl Into<String>) -> WasmError {
    wasm_error!(WasmErrorInner::Guest(message.into()))
}
fn local_agent() -> ExternResult<AgentPubKey> { Ok(agent_info()?.agent_initial_pubkey) }

/// Binds membership to the *actual* valid proposal action, not caller-supplied metadata.
fn load_proposal(proposal_hash: &ActionHash) -> ExternResult<SessionProposal> {
    let record = get(proposal_hash.clone(), GetOptions::default())?
        .ok_or_else(|| guest("Session proposal unavailable"))?;
    let (zome_index, entry_index) = match record.action().entry_type() {
        Some(EntryType::App(AppEntryDef { zome_index, entry_index, .. })) => (*zome_index, *entry_index),
        _ => return Err(guest("Not an application entry")),
    };
    let entry = record.entry().as_option().ok_or_else(|| guest("Missing public proposal"))?;
    match EntryTypes::deserialize_from_type(zome_index, entry_index, entry)? {
        Some(EntryTypes::SessionProposal(p)) => Ok(p),
        _ => Err(guest("Expected SessionProposal record")),
    }
}

fn require_local_member(proposal_hash: &ActionHash) -> ExternResult<SessionSpec> {
    let spec = load_proposal(proposal_hash)?.spec;
    ensure_local_member(&spec)?;
    Ok(spec)
}

fn acceptance_records(proposal_hash: &ActionHash) -> ExternResult<BTreeMap<AgentPubKey, ActionHash>> {
    let spec = load_proposal(proposal_hash)?.spec;
    let mut accepted = BTreeMap::new();
    let links = get_links(
        LinkQuery::try_new(proposal_hash.clone(), LinkTypes::SessionToAcceptances)?,
        GetStrategy::default(),
    )?;
    for link in links {
        let Some(hash) = link.target.into_action_hash() else { continue; };
        let Some(record) = get(hash.clone(), GetOptions::default())? else { continue; };
        let entry: Option<SessionAcceptance> = record.entry().to_app_option().map_err(|e| guest(e.to_string()))?;
        if let Some(entry) = entry {
            if entry.proposal == *proposal_hash
                && entry.session_id == spec.session_id
                && spec.contains(record.action().author().get_raw_39())
            {
                accepted.entry(record.action().author().clone()).or_insert(hash);
            }
        }
    }
    Ok(accepted)
}

fn require_fully_accepted(proposal_hash: &ActionHash, spec: &SessionSpec) -> ExternResult<()> {
    let accepted = acceptance_records(proposal_hash)?;
    if !spec.participants.iter().all(|p| accepted.keys().any(|a| a.get_raw_39() == p.as_slice())) {
        return Err(guest("Session requires acceptance from ALL listed participants"));
    }
    if !accepted.contains_key(&local_agent()?) {
        return Err(guest("Local agent has not accepted the exact proposal"));
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionStatus {
    pub spec: SessionSpec,
    pub accepted: Vec<AgentPubKey>,
    /// Observed locally at query time, NOT distributed consensus/finality.
    pub ready_observed: bool,
}

#[hdk_extern]
pub fn propose_session(spec: SessionSpec) -> ExternResult<ActionHash> {
    ensure_local_member(&spec)?;
    if spec.participants.iter().any(|p| AgentPubKey::try_from_raw_39(p.clone()).is_err()) {
        return Err(guest("Expected valid Holochain AgentPubKeys (39 bytes)"));
    }
    let action = create_entry(&EntryTypes::SessionProposal(SessionProposal { spec }))?;
    create_link(local_agent()?, action.clone(), LinkTypes::AgentToSessions, ())?;
    Ok(action)
}

#[hdk_extern]
pub fn accept_session(proposal: ActionHash) -> ExternResult<ActionHash> {
    let spec = require_local_member(&proposal)?;
    if let Some(previous) = acceptance_records(&proposal)?.get(&local_agent()?) {
        return Ok(previous.clone());
    }
    let action = create_entry(&EntryTypes::SessionAcceptance(SessionAcceptance {
        proposal: proposal.clone(),
        session_id: spec.session_id,
    }))?;
    create_link(proposal.clone(), action.clone(), LinkTypes::SessionToAcceptances, ())?;
    create_link(local_agent()?, proposal, LinkTypes::AgentToSessions, ())?;
    Ok(action)
}

#[hdk_extern]
pub fn get_session_status(proposal: ActionHash) -> ExternResult<SessionStatus> {
    let spec = load_proposal(&proposal)?.spec;
    let accepted = acceptance_records(&proposal)?.into_keys().collect::<Vec<_>>();
    let ready_observed = spec.participants.iter().all(|p| {
        accepted.iter().any(|a| a.get_raw_39() == p.as_slice())
    });
    Ok(SessionStatus { spec, accepted, ready_observed })
}

/// Assigned grant for the single inbound RPC function. The returned secret
/// MUST be supplied only over a protected, authenticated provisioning channel.
/// No unrestricted grant is installed by init().
#[derive(Serialize, Deserialize, Debug)]
pub struct PreparedGrant {
    pub grant_hash: ActionHash,
    pub cap_secret: CapSecret,
}

#[hdk_extern]
pub fn prepare_inbox_grant(proposal: ActionHash) -> ExternResult<PreparedGrant> {
    let spec = require_local_member(&proposal)?;
    let local = local_agent()?;
    if !acceptance_records(&proposal)?.contains_key(&local) {
        return Err(guest("Accept the proposal before provisioning inbound access"));
    }
    let assignees: BTreeSet<AgentPubKey> = spec.participants.iter()
        .filter(|p| p.as_slice() != local.get_raw_39())
        .map(|p| AgentPubKey::try_from_raw_39(p.clone()).map_err(|e| guest(e.to_string())))
        .collect::<ExternResult<BTreeSet<_>>>()?;
    let secret = generate_cap_secret()?;
    let functions: HashSet<(ZomeName, FunctionName)> =
        [(zome_info()?.name, "receive_protocol_message".into())].into_iter().collect();
    let grant_hash = create_cap_grant(CapGrant::new_zome_call_grant(
        format!("mpc-session-{:02x?}", &spec.session_id[..4]),
        GrantConstraint::Assigned { secret: secret.clone(), assignees },
        GrantedFunctions::Listed(functions),
    ))?;
    Ok(PreparedGrant { grant_hash, cap_secret: secret })
}

/// Immutable locally authored inbound event. Read over *private local chain*;
/// NEVER index or broadcast this entry on the DHT.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ReceiptStatus { Stored, AlreadyStored }

#[derive(Serialize, Deserialize, Debug)]
pub struct DeliveryReceipt {
    pub status: ReceiptStatus,
    pub storage_action: ActionHash,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingMessage {
    pub proposal: ActionHash,
    pub envelope: Envelope,
}

fn inbox_records(proposal: &ActionHash) -> ExternResult<Vec<(ActionHash, InboxEvent)>> {
    let records = query(ChainQueryFilter::new()
        .entry_type(EntryType::App(UnitEntryTypes::InboxEvent.try_into()?))
        .include_entries(true))?;
    let mut output = Vec::new();
    for record in records {
        let Some(event) = record.entry().to_app_option::<InboxEvent>().map_err(|e| guest(e.to_string()))? else { continue; };
        if &event.proposal == proposal {
            output.push((record.action_address().clone(), event));
        }
    }
    Ok(output)
}

/// Strictly forbid accidental plaintext DKG Round-2 transport for FROST.
/// Round number 3 corresponds to `Message::DkgRound2` in the native provider.
/// This validates the *ciphertext container*, NOT MAC authenticity; the native
/// receiver must independently check trusted encryption keys and decrypt.
fn require_sealed_dkg(spec: &SessionSpec, round: u32, payload: &[u8]) -> ExternResult<()> {
    if spec.protocol_id == "frost-ed25519" && spec.protocol_version == 1 && round == 3 {
        let sealed: SealedPacket = serde_json::from_slice(payload)
            .map_err(|_| guest("FROST DKG Round 2 requires a sealed packet"))?;
        if !sealed.structurally_valid() {
            return Err(guest("Invalid encrypted FROST DKG Round-2 packet"));
        }
    }
    Ok(())
}

#[hdk_extern]
pub fn receive_protocol_message(input: IncomingMessage) -> ExternResult<DeliveryReceipt> {
    let spec = require_local_member(&input.proposal)?;
    require_fully_accepted(&input.proposal, &spec)?;
    // Never trust the sender identity in the untrusted envelope.
    authenticate_incoming(&spec, &input.envelope)?;
    require_sealed_dkg(&spec, input.envelope.round, &input.envelope.payload)?;
    let recorded = inbox_records(&input.proposal)?;
    let current = &input.envelope;
    for (hash, stored) in &recorded {
        let old = &stored.envelope;
        if old.sender == current.sender && old.round == current.round && old.sequence == current.sequence {
            if old == current {
                return Ok(DeliveryReceipt { status: ReceiptStatus::AlreadyStored, storage_action: hash.clone() });
            }
            return Err(guest("Conflicting payload for an existing sender/round/sequence"));
        }
    }
    if recorded.len() >= MAX_MESSAGES_PER_SESSION {
        return Err(guest("Inbox capacity reached"));
    }
    // The zome has no cryptographic side effects. Persist BEFORE success reply.
    // Concurrent calls can race on read-before-write: get_inbox deduplicates
    // logically, while strict once-only crypto effects need a transactional
    // local sidecar in v0.3 (see SECURITY.md).
    let action = create_entry(&EntryTypes::InboxEvent(InboxEvent {
        proposal: input.proposal,
        envelope: input.envelope,
    }))?;
    Ok(DeliveryReceipt { status: ReceiptStatus::Stored, storage_action: action })
}

/// Caller supplies its existing recipient capability secret; it is never
/// included in DHT entries. The receiver verifies actual caller provenance.
#[derive(Serialize, Deserialize, Debug)]
pub struct SendMessage {
    pub proposal: ActionHash,
    pub recipient: AgentPubKey,
    pub round: u32,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub recipient_cap_secret: CapSecret,
}

#[hdk_extern]
pub fn send_protocol_message(input: SendMessage) -> ExternResult<DeliveryReceipt> {
    let spec = require_local_member(&input.proposal)?;
    require_fully_accepted(&input.proposal, &spec)?;
    if input.recipient == local_agent()? { return Err(guest("Cannot send to self")); }
    require_sealed_dkg(&spec, input.round, &input.payload)?;
    let env = Envelope::new(
        &spec, local_agent()?.get_raw_39().to_vec(),
        Some(input.recipient.get_raw_39().to_vec()),
        input.round, input.sequence, input.payload,
    ).map_err(|e| guest(e.to_string()))?;
    let response = call_remote(
        input.recipient,
        zome_info()?.name,
        "receive_protocol_message".into(),
        Some(input.recipient_cap_secret),
        IncomingMessage { proposal: input.proposal, envelope: env },
    )?;
    match response {
        ZomeCallResponse::Ok(io) => io.decode().map_err(|e| guest(e.to_string())),
        // Do not print `ZomeCallResponse::Unauthorized` Debug output: some
        // Holochain versions carry the capability secret inside that variant.
        // The client can retry safely with the SAME message ID after resolving
        // an authorization, connectivity, or remote validation failure.
        _ => Err(guest("Remote delivery not acknowledged; retry with the same round/sequence")),
    }
}

/// Returns one logical envelope per ID, even if concurrent local writes raced.
/// Does NOT execute the cryptographic protocol on the message.
#[hdk_extern]
pub fn get_inbox(proposal: ActionHash) -> ExternResult<Vec<Envelope>> {
    require_local_member(&proposal)?;
    let spec = require_local_member(&proposal)?;
    let mut distinct: BTreeMap<(Vec<u8>, u32, u64), Envelope> = BTreeMap::new();
    for (_, event) in inbox_records(&proposal)? {
        event.envelope.validate_against(&spec).map_err(|e| guest(e.to_string()))?;
        let key = (event.envelope.sender.clone(), event.envelope.round, event.envelope.sequence);
        if let Some(previous) = distinct.get(&key) {
            if previous != &event.envelope {
                return Err(guest("Equivocation: conflicting messages with the same ID"));
            }
        } else {
            distinct.insert(key, event.envelope);
        }
    }
    Ok(distinct.into_values().collect())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublishResult {
    pub proposal: ActionHash,
    pub result_bytes: Vec<u8>,
    pub verification_artifact: Vec<u8>,
}

#[hdk_extern]
pub fn publish_result_commitment(input: PublishResult) -> ExternResult<ActionHash> {
    let spec = require_local_member(&input.proposal)?;
    require_fully_accepted(&input.proposal, &spec)?;
    if input.verification_artifact.len() > 16 * 1024 || input.result_bytes.len() > 64 * 1024 {
        return Err(guest("Output size exceeds limit"));
    }
    let commitment = ResultCommitment::new(&spec, &input.result_bytes)
        .map_err(|e| guest(e.to_string()))?;
    let output = OutputProposal {
        proposal: input.proposal.clone(), commitment,
        verification_artifact: input.verification_artifact,
    };
    let action = create_entry(&EntryTypes::OutputProposal(output))?;
    create_link(input.proposal, action.clone(), LinkTypes::SessionToOutputs, ())?;
    Ok(action)
}

#[hdk_extern]
pub fn get_output_commitments(proposal: ActionHash) -> ExternResult<Vec<OutputProposal>> {
    let mut output = Vec::new();
    for link in get_links(LinkQuery::try_new(proposal.clone(), LinkTypes::SessionToOutputs)?, GetStrategy::default())? {
        let Some(hash) = link.target.into_action_hash() else { continue; };
        if let Some(record) = get(hash, GetOptions::default())? {
            if let Some(value) = record.entry().to_app_option::<OutputProposal>().map_err(|e| guest(e.to_string()))? {
                if value.proposal == proposal { output.push(value); }
            }
        }
    }
    Ok(output)
}

/// Local agent registers a native-controller public X25519 key under its
/// authenticated Holochain source-chain author identity. No secrets published.
#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterEncryptionKey {
    pub proposal: ActionHash,
    pub public_key: [u8; 32],
}
#[hdk_extern]
pub fn register_encryption_key(input: RegisterEncryptionKey) -> ExternResult<ActionHash> {
    let spec = require_local_member(&input.proposal)?;
    require_fully_accepted(&input.proposal, &spec)?;
    if input.public_key == [0; 32] { return Err(guest("Cannot register a zero encryption key")); }
    let action = create_entry(&EntryTypes::EncryptionKeyBinding(EncryptionKeyBinding {
        proposal: input.proposal.clone(), public_key: input.public_key,
    }))?;
    create_link(input.proposal, action.clone(), LinkTypes::SessionToEncryptionKeys, ())?;
    Ok(action)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionKeyRecord {
    pub action: ActionHash,
    pub author: AgentPubKey,
    pub public_key: [u8; 32],
}

/// Returns all registrations including rotations; no implicit key selection.
/// Applications MUST independently pin the intended `action` and `author`.
#[hdk_extern]
pub fn get_encryption_key_bindings(proposal: ActionHash) -> ExternResult<Vec<EncryptionKeyRecord>> {
    let spec = load_proposal(&proposal)?.spec;
    let mut records = Vec::new();
    for link in get_links(
        LinkQuery::try_new(proposal.clone(), LinkTypes::SessionToEncryptionKeys)?,
        GetStrategy::default(),
    )? {
        let Some(hash) = link.target.into_action_hash() else { continue; };
        let Some(record) = get(hash.clone(), GetOptions::default())? else { continue; };
        let Some(entry) = record.entry().to_app_option::<EncryptionKeyBinding>().map_err(|e| guest(e.to_string()))? else { continue; };
        if entry.proposal == proposal && spec.contains(record.action().author().get_raw_39()) &&
           entry.public_key != [0; 32] {
            records.push(EncryptionKeyRecord { action: hash, author: record.action().author().clone(),
                                               public_key: entry.public_key });
        }
    }
    Ok(records)
}

/// Public audit checkpoint only. Native security gate remains the source of
/// protocol completion; neither the zome nor DHT validates its correctness.
#[derive(Serialize, Deserialize, Debug)]
pub struct PublishTranscriptCheckpoint {
    pub proposal: ActionHash,
    pub transcript_hash: [u8; 32],
}
#[hdk_extern]
pub fn publish_transcript_checkpoint(input: PublishTranscriptCheckpoint) -> ExternResult<ActionHash> {
    let spec = require_local_member(&input.proposal)?;
    require_fully_accepted(&input.proposal, &spec)?;
    if input.transcript_hash == [0;32] { return Err(guest("Missing transcript digest")); }
    let action = create_entry(&EntryTypes::TranscriptCheckpoint(TranscriptCheckpoint {
        proposal: input.proposal.clone(), transcript_hash: input.transcript_hash,
    }))?;
    create_link(input.proposal, action.clone(), LinkTypes::SessionToTranscripts, ())?;
    Ok(action)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TranscriptCheckpointRecord {
    pub author: AgentPubKey,
    pub action: ActionHash,
    pub transcript_hash: [u8; 32],
}
#[hdk_extern]
pub fn get_transcript_checkpoints(proposal: ActionHash) -> ExternResult<Vec<TranscriptCheckpointRecord>> {
    let spec = load_proposal(&proposal)?.spec;
    let mut result = Vec::new();
    for link in get_links(LinkQuery::try_new(proposal.clone(), LinkTypes::SessionToTranscripts)?,
                          GetStrategy::default())? {
        let Some(hash) = link.target.into_action_hash() else { continue; };
        let Some(record) = get(hash.clone(), GetOptions::default())? else { continue; };
        let Some(c) = record.entry().to_app_option::<TranscriptCheckpoint>().map_err(|e| guest(e.to_string()))? else { continue; };
        if c.proposal == proposal && spec.contains(record.action().author().get_raw_39()) &&
           c.transcript_hash != [0;32] {
            result.push(TranscriptCheckpointRecord {
                author: record.action().author().clone(), action: hash,
                transcript_hash: c.transcript_hash,
            });
        }
    }
    Ok(result)
}

/// Revoke a grant created on this agent's own chain. Existing other grants
/// remain valid; applications must track every emitted grant_hash.
#[hdk_extern]
pub fn revoke_inbox_grant(grant_hash: ActionHash) -> ExternResult<ActionHash> {
    delete_cap_grant(grant_hash)
}

// v0.3.2 public evidence APIs. These are author-signed Holochain actions,
// NOT proofs of cryptographic key possession or native DKG completion.
#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterKeyEpoch {
    pub proposal: ActionHash,
    pub epoch: u64,
    pub public_key: [u8;32],
    pub previous_binding: Option<ActionHash>,
}
#[hdk_extern]
pub fn register_encryption_key_epoch(input: RegisterKeyEpoch) -> ExternResult<ActionHash> {
    let spec = require_local_member(&input.proposal)?;
    require_fully_accepted(&input.proposal, &spec)?;
    if input.public_key == [0;32] { return Err(guest("Missing X25519 key")); }
    if input.epoch == 0 && input.previous_binding.is_some() ||
       input.epoch > 0 && input.previous_binding.is_none() {
        return Err(guest("Rotation must link predecessor; first epoch cannot"));
    }
    if let Some(previous) = &input.previous_binding {
        let record = get(previous.clone(),GetOptions::default())?
            .ok_or_else(||guest("Predecessor not found"))?;
        if record.action().author() != &local_agent()? { return Err(guest("Wrong rotation author")); }
        let old: Option<EncryptionKeyEpoch> = record.entry().to_app_option().map_err(|e| guest(e.to_string()))?;
        let old = old.ok_or_else(||guest("Predecessor is not a key epoch"))?;
        if old.proposal != input.proposal || old.epoch.checked_add(1) != Some(input.epoch) ||
           old.public_key == input.public_key { return Err(guest("Invalid key epoch sequence")); }
    }
    let action = create_entry(&EntryTypes::EncryptionKeyEpoch(EncryptionKeyEpoch {
        proposal:input.proposal.clone(),epoch:input.epoch,
        public_key:input.public_key,previous_binding:input.previous_binding
    }))?;
    create_link(input.proposal,action.clone(),LinkTypes::SessionToKeyEpochs,())?;
    Ok(action)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyEpochRecord {
    pub action: ActionHash,
    pub author: AgentPubKey,
    pub entry: EncryptionKeyEpoch,
}
#[hdk_extern]
pub fn get_encryption_key_epochs(proposal: ActionHash) -> ExternResult<Vec<KeyEpochRecord>> {
    require_local_member(&proposal)?;
    let mut result=Vec::new();
    for link in get_links(LinkQuery::try_new(proposal.clone(),LinkTypes::SessionToKeyEpochs)?,GetStrategy::default())? {
        let Some(hash)=link.target.into_action_hash() else { continue; };
        let Some(record)=get(hash.clone(),GetOptions::default())? else { continue; };
        let Some(entry)=record.entry().to_app_option::<EncryptionKeyEpoch>().map_err(|e| guest(e.to_string()))? else { continue; };
        if entry.proposal == proposal {
            result.push(KeyEpochRecord { action:hash,author:record.action().author().clone(),entry });
        }
    }
    // Consumers detect forks and pin exact actions; NEVER choose last timestamp.
    Ok(result)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublishGroupAttestation {
    pub proposal: ActionHash,
    pub epoch: u64,
    pub descriptor_hash: [u8;32],
    pub dkg_transcript_hash: [u8;32],
    pub public_key_package_hash: [u8;32],
}
#[hdk_extern]
pub fn publish_group_activation_attestation(input: PublishGroupAttestation) -> ExternResult<ActionHash> {
    let spec=require_local_member(&input.proposal)?;
    require_fully_accepted(&input.proposal,&spec)?;
    if input.descriptor_hash==[0;32] || input.dkg_transcript_hash==[0;32] ||
       input.public_key_package_hash==[0;32] { return Err(guest("Missing activation digest")); }
    let hash=create_entry(&EntryTypes::GroupActivationAttestation(GroupActivationAttestation {
        proposal:input.proposal.clone(),epoch:input.epoch,descriptor_hash:input.descriptor_hash,
        dkg_transcript_hash:input.dkg_transcript_hash,public_key_package_hash:input.public_key_package_hash,
    }))?;
    create_link(input.proposal,hash.clone(),LinkTypes::SessionToGroupAttestations,())?;
    Ok(hash)
}
#[derive(Serialize, Deserialize, Debug)]
pub struct GroupAttestationRecord {
    pub action: ActionHash,
    pub author: AgentPubKey,
    pub attestation: GroupActivationAttestation,
}
#[hdk_extern]
pub fn get_group_activation_attestations(proposal: ActionHash) -> ExternResult<Vec<GroupAttestationRecord>> {
    require_local_member(&proposal)?;
    let mut out=Vec::new();
    for link in get_links(LinkQuery::try_new(proposal.clone(),LinkTypes::SessionToGroupAttestations)?,GetStrategy::default())? {
        let Some(hash)=link.target.into_action_hash() else { continue; };
        let Some(record)=get(hash.clone(),GetOptions::default())? else { continue; };
        let Some(entry)=record.entry().to_app_option::<GroupActivationAttestation>().map_err(|e| guest(e.to_string()))? else { continue; };
        if entry.proposal==proposal {
            out.push(GroupAttestationRecord {action:hash,author:record.action().author().clone(),attestation:entry});
        }
    }
    Ok(out)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublishSigningApproval {
    pub proposal: ActionHash,
    pub operation_id: [u8;32],
    pub group_descriptor_hash: [u8;32],
    pub intent_hash: [u8;32],
}
#[hdk_extern]
pub fn publish_signing_approval(input: PublishSigningApproval) -> ExternResult<ActionHash> {
    let spec=require_local_member(&input.proposal)?;
    require_fully_accepted(&input.proposal,&spec)?;
    if input.operation_id==[0;32] || input.operation_id==spec.session_id ||
       input.group_descriptor_hash==[0;32] || input.intent_hash==[0;32] {
        return Err(guest("Invalid signing approval hashes"));
    }
    let hash=create_entry(&EntryTypes::SigningApprovalAttestation(SigningApprovalAttestation {
        proposal:input.proposal.clone(),operation_id:input.operation_id,
        group_descriptor_hash:input.group_descriptor_hash,intent_hash:input.intent_hash
    }))?;
    create_link(input.proposal,hash.clone(),LinkTypes::SessionToSigningApprovals,())?;
    Ok(hash)
}
#[derive(Serialize, Deserialize, Debug)]
pub struct SigningApprovalRecord {
    pub action: ActionHash,
    pub author: AgentPubKey,
    pub approval: SigningApprovalAttestation,
}
#[hdk_extern]
pub fn get_signing_approvals(proposal: ActionHash) -> ExternResult<Vec<SigningApprovalRecord>> {
    require_local_member(&proposal)?;
    let mut out=Vec::new();
    for link in get_links(LinkQuery::try_new(proposal.clone(),LinkTypes::SessionToSigningApprovals)?,GetStrategy::default())? {
        let Some(hash)=link.target.into_action_hash() else { continue; };
        let Some(record)=get(hash.clone(),GetOptions::default())? else { continue; };
        let Some(entry)=record.entry().to_app_option::<SigningApprovalAttestation>().map_err(|e| guest(e.to_string()))? else { continue; };
        if entry.proposal==proposal {
            out.push(SigningApprovalRecord {action:hash,author:record.action().author().clone(),approval:entry});
        }
    }
    Ok(out)
}
