//! Reusable MPC coordination zome for Holochain 0.7.
//! v0.2 deliberately DOES NOT execute any cryptographic protocol effects.
use hdk::prelude::*;
use holochain_mpc_core::{Envelope, PrimitiveError, ResultCommitment, SessionSpec, SealedPacket, MAX_MESSAGES_PER_SESSION};
use holochain_mpc_adapter::ensure_local_member;
use mpc_integrity::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};

fn guest(message: impl Into<String>) -> WasmError {
    wasm_error!(WasmErrorInner::Guest(message.into()))
}
fn local_agent() -> ExternResult<AgentPubKey> { Ok(agent_info()?.agent_initial_pubkey) }

const PROPOSAL_UNAVAILABLE: &str = "Session proposal unavailable";

/// Binds membership to the *actual* valid proposal action, not caller-supplied metadata.
fn load_proposal(proposal_hash: &ActionHash) -> ExternResult<SessionProposal> {
    let record = get(proposal_hash.clone(), GetOptions::default())?
        .ok_or_else(|| guest(PROPOSAL_UNAVAILABLE))?;
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

/// Stable failure kinds of the inbox externs. Every inbox refusal is a guest
/// error whose text starts with `<code>: `, so a caller that only sees text
/// (a remote sender always does) can still tell the conditions apart. No kind
/// is advice to resend; see `send_protocol_message`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboxFailure {
    /// The slot already holds a different payload from this sender.
    Conflict,
    /// The authenticated sender has used its share of this inbox.
    SenderQuota,
    /// The inbox holds `MAX_MESSAGES_PER_SESSION` records.
    Capacity,
    /// The caller, sender, recipient or local agent is not entitled.
    Unauthorized,
    /// A malformed or out-of-context argument.
    InvalidArgument,
    /// The proposal is not available to this agent.
    Missing,
    /// The recipient's commit lost a chain-head race (`HeadMoved`).
    WriteConflict,
    /// A stored inbox record no longer validates against its session.
    StoredRecordInvalid,
    /// Storage, network or decoding failure.
    Transport,
}

impl InboxFailure {
    pub const ALL: [InboxFailure; 9] = [
        Self::Conflict, Self::SenderQuota, Self::Capacity, Self::Unauthorized, Self::InvalidArgument,
        Self::Missing, Self::WriteConflict, Self::StoredRecordInvalid, Self::Transport,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Self::Conflict => "inbox_conflict",
            Self::SenderQuota => "inbox_sender_quota",
            Self::Capacity => "inbox_capacity",
            Self::Unauthorized => "inbox_unauthorized",
            Self::InvalidArgument => "inbox_invalid_argument",
            Self::Missing => "inbox_missing",
            Self::WriteConflict => "inbox_write_conflict",
            Self::StoredRecordInvalid => "inbox_stored_record_invalid",
            Self::Transport => "inbox_transport",
        }
    }

    /// The first kind named in an error text, and the byte offset of its code.
    pub fn find(text: &str) -> Option<(Self, usize)> {
        Self::ALL.iter()
            .filter_map(|kind| text.find(&format!("{}: ", kind.code())).map(|at| (*kind, at)))
            .min_by_key(|(_, at)| *at)
    }
}

fn fail(kind: InboxFailure, detail: impl std::fmt::Display) -> WasmError {
    guest(format!("{}: {detail}", kind.code()))
}

fn detail(error: &WasmError) -> String {
    match &error.error {
        WasmErrorInner::Guest(message) => message.clone(),
        other => format!("{other:?}"),
    }
}

fn envelope_failure(error: PrimitiveError) -> WasmError {
    let kind = match error {
        PrimitiveError::SenderNotMember | PrimitiveError::RecipientNotMember |
        PrimitiveError::WrongRecipient | PrimitiveError::AuthenticatedSenderMismatch => InboxFailure::Unauthorized,
        _ => InboxFailure::InvalidArgument,
    };
    fail(kind, error)
}

/// `require_local_member` (and, if asked, `require_fully_accepted`) with each
/// failure tagged by kind.
fn inbox_session(proposal: &ActionHash, accepted: bool) -> ExternResult<SessionSpec> {
    let spec = load_proposal(proposal).map_err(|e| match &e.error {
        WasmErrorInner::Guest(message) if message == PROPOSAL_UNAVAILABLE => fail(InboxFailure::Missing, message),
        WasmErrorInner::Guest(message) => fail(InboxFailure::InvalidArgument, message),
        _ => fail(InboxFailure::Transport, detail(&e)),
    })?.spec;
    ensure_local_member(&spec).map_err(|e| fail(InboxFailure::Unauthorized, detail(&e)))?;
    if accepted {
        require_fully_accepted(proposal, &spec).map_err(|e| match &e.error {
            WasmErrorInner::Guest(message) => fail(InboxFailure::Unauthorized, message),
            _ => fail(InboxFailure::Transport, detail(&e)),
        })?;
    }
    Ok(spec)
}

/// Largest `get_inbox` response the native clients accept: both
/// `conductor_client.rs` and the DKG relay refuse more than 4,096 envelopes.
pub const MAX_SERVED_INBOX: usize = 4_096;
/// Ceiling on one sender's share, whatever the session size.
pub const MAX_INBOX_PER_SENDER: usize = 4_096;

/// One authenticated sender's share of one recipient's inbox for one
/// proposal: `MAX_SERVED_INBOX` split evenly between the other members, at
/// most `MAX_INBOX_PER_SENDER`. 2,048 for a three-member session. The shares
/// add up to at most `MAX_SERVED_INBOX`, so no sender can push a response past
/// the clients' limit. Inbox records are never deleted, so the share is a
/// budget for the life of the proposal, not a window.
pub fn sender_quota(spec: &SessionSpec) -> usize {
    let peers = spec.participants.len().saturating_sub(1).max(1);
    (MAX_SERVED_INBOX / peers).clamp(1, MAX_INBOX_PER_SENDER)
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

/// One distinct stored payload of a slot, with every action that stores it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct StoredVariant {
    pub envelope: Envelope,
    pub storage_actions: Vec<ActionHash>,
}

/// A (sender, round, sequence) slot that `get_inbox` does not serve.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct WithheldSlot {
    pub sender: Vec<u8>,
    pub round: u32,
    pub sequence: u64,
    pub variants: Vec<StoredVariant>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct InboxSlots {
    /// Exactly what `get_inbox` returns: one envelope per served slot.
    pub envelopes: Vec<Envelope>,
    /// Slots holding two or more distinct payloads: equivocation evidence.
    /// A consumer whose operation reads one of these slots MUST abort it.
    pub conflicts: Vec<WithheldSlot>,
    /// Single-payload slots stored beyond the sender's share by concurrent
    /// deliveries. Never served; a consumer waiting on one MUST abort.
    pub over_quota: Vec<WithheldSlot>,
}

/// Splits inbox records, given in source-chain order, by slot. A slot with
/// one distinct payload is served if its first record is among its sender's
/// first `quota` records. Nothing is chosen between conflicting payloads, and
/// no sender can have more than `quota` slots served. Both rules hold however
/// the records were written, so the races in `receive_protocol_message`
/// cannot reach a consumer.
pub fn partition_inbox(records: impl IntoIterator<Item = (ActionHash, Envelope)>, quota: usize) -> InboxSlots {
    struct Slot { first: usize, variants: Vec<StoredVariant> }
    let mut per_sender: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    let mut slots: BTreeMap<(Vec<u8>, u32, u64), Slot> = BTreeMap::new();
    for (action, envelope) in records {
        let count = per_sender.entry(envelope.sender.clone()).or_insert(0);
        let index = *count;
        *count += 1;
        let slot = slots.entry((envelope.sender.clone(), envelope.round, envelope.sequence))
            .or_insert_with(|| Slot { first: index, variants: Vec::new() });
        match slot.variants.iter_mut().find(|v| v.envelope == envelope) {
            Some(variant) => variant.storage_actions.push(action),
            None => slot.variants.push(StoredVariant { envelope, storage_actions: vec![action] }),
        }
    }
    let mut inbox = InboxSlots::default();
    for ((sender, round, sequence), mut slot) in slots {
        if slot.variants.len() == 1 && slot.first < quota {
            inbox.envelopes.push(slot.variants.remove(0).envelope);
        } else if slot.variants.len() > 1 {
            inbox.conflicts.push(WithheldSlot { sender, round, sequence, variants: slot.variants });
        } else {
            inbox.over_quota.push(WithheldSlot { sender, round, sequence, variants: slot.variants });
        }
    }
    inbox
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
    let spec = inbox_session(&input.proposal, true)?;
    // Never trust the sender identity in the untrusted envelope. This is
    // `holochain_mpc_adapter::authenticate_incoming`, inline so that the
    // refusal keeps its kind.
    let caller = call_info().map_err(|e| fail(InboxFailure::Transport, detail(&e)))?.provenance;
    let local = local_agent()?;
    input.envelope.validate_received(&spec, local.get_raw_39(), caller.get_raw_39())
        .map_err(envelope_failure)?;
    require_sealed_dkg(&spec, input.envelope.round, &input.envelope.payload)
        .map_err(|e| fail(InboxFailure::InvalidArgument, detail(&e)))?;
    let recorded = inbox_records(&input.proposal).map_err(|e| fail(InboxFailure::Transport, detail(&e)))?;
    let current = &input.envelope;
    let mut from_caller = 0;
    let mut conflicting = false;
    for (hash, stored) in &recorded {
        let old = &stored.envelope;
        // The share belongs to the authenticated caller, which
        // `validate_received` has just matched to the envelope sender.
        if old.sender.as_slice() == caller.get_raw_39() { from_caller += 1; }
        if old.sender == current.sender && old.round == current.round && old.sequence == current.sequence {
            if old == current {
                return Ok(DeliveryReceipt { status: ReceiptStatus::AlreadyStored, storage_action: hash.clone() });
            }
            conflicting = true;
        }
    }
    if conflicting {
        return Err(fail(InboxFailure::Conflict,
            "Conflicting payload for an existing sender/round/sequence; get_inbox withholds the slot"));
    }
    let quota = sender_quota(&spec);
    if from_caller >= quota {
        return Err(fail(InboxFailure::SenderQuota, format!(
            "the sender already has {from_caller} messages in this inbox for this proposal; its share is {quota}")));
    }
    if recorded.len() >= MAX_MESSAGES_PER_SESSION {
        return Err(fail(InboxFailure::Capacity, "Inbox capacity reached"));
    }
    // The zome has no cryptographic side effects. Persist BEFORE success reply.
    // The checks above read the chain before this call writes, so concurrent
    // calls can all pass them: a conflicting pair can both be stored, and a
    // sender can exceed its share by about as many deliveries as it has in
    // flight. `partition_inbox` applies both rules again on read, so neither
    // reaches a consumer. Strict once-only crypto effects need a transactional
    // local sidecar in v0.3 (see SECURITY.md).
    //
    // Relaxed chain-top ordering: peers deliver concurrently (every DKG round
    // fans in), and strict ordering failed all but one with HeadMoved. The
    // private InboxEvent's validation does not depend on chain position. The
    // accepted cost: a delivery authorised just before a concurrent grant
    // revocation may be committed after it.
    let entry = EntryTypes::InboxEvent(InboxEvent { proposal: input.proposal, envelope: input.envelope });
    let ScopedEntryDefIndex { zome_index, zome_type } = (&entry).try_into()?;
    let action = create(CreateInput::new(EntryDefLocation::app(zome_index, zome_type),
        EntryVisibility::from(&entry), entry.try_into()?, ChainTopOrdering::Relaxed))
        .map_err(|e| fail(InboxFailure::Transport, detail(&e)))?;
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

/// Text for a remote delivery that came back as `NetworkError`. Holochain
/// returns both a guest error from the recipient's zome and a commit that
/// lost a chain-head race this way. Either means nothing was stored. Any
/// other network text leaves the outcome unknown. Each text keeps the Stage 2B
/// wording after the kind, for callers that match on it.
pub fn remote_failure_message(network: &str) -> String {
    if let Some((kind, at)) = InboxFailure::find(network) {
        // The remote text is nested in escaped Debug output; stop at its end.
        let remote: String = network[at + kind.code().len() + 2..].chars()
            .take_while(|c| *c != '"' && *c != '\\').take(300).collect();
        return format!("{}: Remote delivery not acknowledged: rejected by the recipient, not stored: {remote}",
            kind.code());
    }
    // Holochain forwards the remote `CellError` in Debug form
    // (`SourceChainError(HeadMoved(…`); match its Display text as well.
    if network.contains("SourceChainError(HeadMoved(") || network.contains("source chain head has moved") {
        return format!("{}: Remote delivery not acknowledged: the recipient's commit lost a chain-head race \
            (HeadMoved), not stored", InboxFailure::WriteConflict.code());
    }
    format!("{}: Remote delivery not acknowledged: network: {}; outcome unknown",
        InboxFailure::Transport.code(), network.chars().take(300).collect::<String>())
}

#[hdk_extern]
pub fn send_protocol_message(input: SendMessage) -> ExternResult<DeliveryReceipt> {
    let spec = inbox_session(&input.proposal, true)?;
    let local = local_agent()?;
    if input.recipient == local { return Err(fail(InboxFailure::InvalidArgument, "Cannot send to self")); }
    require_sealed_dkg(&spec, input.round, &input.payload)
        .map_err(|e| fail(InboxFailure::InvalidArgument, detail(&e)))?;
    let env = Envelope::new(
        &spec, local.get_raw_39().to_vec(),
        Some(input.recipient.get_raw_39().to_vec()),
        input.round, input.sequence, input.payload,
    ).map_err(|e| fail(InboxFailure::InvalidArgument, e))?;
    let response = call_remote(
        input.recipient,
        zome_info()?.name,
        "receive_protocol_message".into(),
        Some(input.recipient_cap_secret),
        IncomingMessage { proposal: input.proposal, envelope: env },
    ).map_err(|e| fail(InboxFailure::Transport, format!("remote call failed; outcome unknown: {}", detail(&e))))?;
    // Name the failure kind and whether anything was stored, but never print
    // `Unauthorized` Debug output: in Holochain 0.7.1 that variant carries the
    // capability secret. The same message ID is idempotent at the recipient
    // (AlreadyStored), but whether to resend is the caller's policy, not this
    // function's.
    match response {
        ZomeCallResponse::Ok(io) => io.decode().map_err(|e| fail(InboxFailure::Transport,
            format!("undecodable delivery receipt; outcome unknown: {e}"))),
        ZomeCallResponse::Unauthorized(..) => Err(fail(InboxFailure::Unauthorized,
            "Remote delivery not acknowledged: unauthorized (capability rejected); not stored")),
        ZomeCallResponse::AuthenticationFailed(..) => Err(fail(InboxFailure::Unauthorized,
            "Remote delivery not acknowledged: call signature not authenticated; not stored")),
        ZomeCallResponse::NetworkError(e) => Err(guest(remote_failure_message(&e))),
        ZomeCallResponse::CountersigningSession(_) => Err(fail(InboxFailure::Transport,
            "Remote delivery not acknowledged: countersigning session; outcome unknown")),
    }
}

fn inbox_slots(proposal: &ActionHash) -> ExternResult<InboxSlots> {
    let spec = inbox_session(proposal, false)?;
    let local = local_agent()?;
    let mut records = Vec::new();
    for (action, event) in inbox_records(proposal).map_err(|e| fail(InboxFailure::Transport, detail(&e)))? {
        // Every record passed `receive_protocol_message`, whose sender was
        // authenticated then. One that no longer validates means the chain or
        // the coordinator changed under it: refuse rather than guess.
        let sender = event.envelope.sender.clone();
        event.envelope.validate_received(&spec, local.get_raw_39(), &sender)
            .map_err(|e| fail(InboxFailure::StoredRecordInvalid, e))?;
        records.push((action, event.envelope));
    }
    Ok(partition_inbox(records, sender_quota(&spec)))
}

/// One envelope per served slot, ordered by (sender, round, sequence).
/// Conflicting slots and slots beyond a sender's share are withheld, never
/// chosen between: a consumer waiting on one sees nothing and fails at its
/// deadline, and every other slot stays readable. `get_inbox_slots` returns
/// the withheld slots as evidence. Does NOT execute the cryptographic protocol.
#[hdk_extern]
pub fn get_inbox(proposal: ActionHash) -> ExternResult<Vec<Envelope>> {
    Ok(inbox_slots(&proposal)?.envelopes)
}

/// The served envelopes plus every withheld slot with all its stored variants.
#[hdk_extern]
pub fn get_inbox_slots(proposal: ActionHash) -> ExternResult<InboxSlots> {
    inbox_slots(&proposal)
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

#[cfg(test)]
mod inbox_tests {
    use super::*;
    use holochain_mpc_core::commitment;

    fn member(i: u8) -> Vec<u8> { AgentPubKey::from_raw_36(vec![i; 36]).get_raw_39().to_vec() }
    fn action(i: u8) -> ActionHash { ActionHash::from_raw_36(vec![i; 36]) }

    fn spec(size: u8) -> SessionSpec {
        let mut participants: Vec<Vec<u8>> = (1..=size).map(member).collect();
        participants.sort();
        SessionSpec {
            session_id: commitment("unit", b"inbox"), application_id: "org.example.unit".into(),
            protocol_id: "opaque-rounds".into(), protocol_version: 1,
            context_hash: commitment("unit", b"context"), participants, threshold: 2, max_round: 8,
        }
    }

    fn env(sender: u8, round: u32, sequence: u64, payload: &[u8]) -> Envelope {
        Envelope::new(&spec(3), member(sender), Some(member(2)), round, sequence, payload.to_vec()).unwrap()
    }

    #[test]
    fn a_conflict_withholds_only_its_own_slot() {
        let inbox = partition_inbox(vec![
            (action(1), env(1, 1, 1, b"a")), (action(2), env(3, 1, 1, b"c")),
            (action(3), env(1, 2, 1, b"left")), (action(4), env(1, 2, 1, b"right")),
            (action(5), env(1, 3, 1, b"later")),
        ], 2048);
        assert_eq!(inbox.envelopes, vec![env(1, 1, 1, b"a"), env(1, 3, 1, b"later"), env(3, 1, 1, b"c")]);
        assert_eq!(inbox.conflicts, vec![WithheldSlot { sender: member(1), round: 2, sequence: 1, variants: vec![
            StoredVariant { envelope: env(1, 2, 1, b"left"), storage_actions: vec![action(3)] },
            StoredVariant { envelope: env(1, 2, 1, b"right"), storage_actions: vec![action(4)] },
        ] }]);
        assert!(inbox.over_quota.is_empty());
    }

    #[test]
    fn identical_copies_are_one_slot_and_keep_every_action() {
        let inbox = partition_inbox(vec![
            (action(1), env(1, 1, 1, b"a")), (action(2), env(1, 1, 1, b"a")), (action(3), env(1, 1, 1, b"b")),
        ], 2048);
        assert!(inbox.envelopes.is_empty());
        assert_eq!(inbox.conflicts[0].variants[0].storage_actions, vec![action(1), action(2)]);
        assert_eq!(partition_inbox(vec![(action(1), env(1, 1, 1, b"a")), (action(2), env(1, 1, 1, b"a"))], 2048)
            .envelopes, vec![env(1, 1, 1, b"a")]);
    }

    #[test]
    fn the_share_is_counted_per_sender_in_chain_order() {
        let inbox = partition_inbox(vec![
            (action(1), env(1, 1, 3, b"x")), (action(2), env(3, 1, 1, b"c")), (action(3), env(1, 1, 1, b"x")),
            (action(4), env(1, 1, 2, b"x")), (action(5), env(3, 1, 2, b"c")),
        ], 2);
        // Alice's third record (sequence 2) is over her share; Carol's are not.
        assert_eq!(inbox.envelopes, vec![env(1, 1, 1, b"x"), env(1, 1, 3, b"x"), env(3, 1, 1, b"c"), env(3, 1, 2, b"c")]);
        assert_eq!(inbox.over_quota.len(), 1);
        assert_eq!((inbox.over_quota[0].sequence, &inbox.over_quota[0].variants[0].storage_actions), (2, &vec![action(4)]));
        // A duplicate past the share still serves the slot it duplicates.
        let dup = partition_inbox(vec![(action(1), env(1, 1, 1, b"x")), (action(2), env(1, 1, 1, b"x"))], 1);
        assert_eq!((dup.envelopes.len(), dup.over_quota.len()), (1, 0));
    }

    #[test]
    fn a_variant_beyond_the_share_still_marks_a_conflict() {
        let inbox = partition_inbox(vec![(action(1), env(1, 1, 1, b"a")), (action(2), env(1, 1, 1, b"b"))], 1);
        assert!(inbox.envelopes.is_empty() && inbox.over_quota.is_empty());
        assert_eq!(inbox.conflicts.len(), 1);
    }

    #[test]
    fn shares_never_exceed_what_clients_accept() {
        assert_eq!(sender_quota(&spec(2)), 4096);
        assert_eq!(sender_quota(&spec(3)), 2048);
        assert_eq!(sender_quota(&spec(5)), 1024);
        assert_eq!(sender_quota(&spec(64)), 65);
        for size in 2..=64 {
            let quota = sender_quota(&spec(size));
            assert!(quota >= 1 && quota <= MAX_INBOX_PER_SENDER);
            assert!((size as usize - 1) * quota <= MAX_SERVED_INBOX);
            assert!((size as usize - 1) * quota <= MAX_MESSAGES_PER_SESSION);
        }
    }

    #[test]
    fn kind_codes_are_distinct_and_found_in_text() {
        let codes: BTreeSet<&str> = InboxFailure::ALL.iter().map(|k| k.code()).collect();
        assert_eq!(codes.len(), InboxFailure::ALL.len());
        for kind in InboxFailure::ALL {
            let text = format!("Guest(\"{}: detail\")", kind.code());
            assert_eq!(InboxFailure::find(&text).map(|(k, _)| k), Some(kind));
            assert_eq!(InboxFailure::find(&detail(&fail(kind, "x"))).map(|(k, _)| k), Some(kind));
        }
        assert_eq!(InboxFailure::find("inbox_conflict without a colon"), None);
    }

    #[test]
    fn remote_failures_keep_their_kind_and_never_advise_resending() {
        // The shape Holochain 0.7.1 produced in the Stage 2B run (baseline-run2 log).
        let conflict = remote_failure_message("Other: invalid response to call_remote: ErrorRes { msg_id: 115, \
            error: \"Other(WorkflowError(RibosomeError(WasmRuntimeError(RuntimeError { source: Sys(User(WasmError { \
            module_path: \\\"mpc\\\", line: 10, error: Guest(\\\"inbox_conflict: Conflicting payload for an \
            existing sender/round/sequence; get_inbox withholds the slot\\\") })), wasm_trace: [] }))))\" }");
        assert_eq!(conflict, "inbox_conflict: Remote delivery not acknowledged: rejected by the recipient, not stored: \
            Conflicting payload for an existing sender/round/sequence; get_inbox withholds the slot");
        let quota = remote_failure_message("... inbox_sender_quota: the sender already has 2048 messages ...");
        assert!(quota.starts_with("inbox_sender_quota: Remote delivery not acknowledged: rejected by the recipient, not stored"));
        // As the 17 October coordinator's fan-in failed (test-inbox-hardening-strict log).
        let head = remote_failure_message("Other: invalid response to call_remote: ErrorRes { msg_id: 7, error: \
            \"Other(WorkflowError(SourceChainError(HeadMoved([SignedHashed { hashed: HoloHashed { … }]))))\" }");
        assert!(head.starts_with("inbox_write_conflict: Remote delivery not acknowledged: the recipient's commit lost"));
        assert!(head.ends_with("(HeadMoved), not stored"));
        let display = remote_failure_message("Attempted to commit a bundle to the source chain, but the source chain head has moved since the bundle began.");
        assert_eq!(display, head);
        let unknown = remote_failure_message("timeout waiting for response");
        assert!(unknown.starts_with("inbox_transport: Remote delivery not acknowledged: network: timeout"));
        assert!(unknown.ends_with("; outcome unknown"));
        for text in [conflict, quota, head, unknown] {
            assert!(!text.to_lowercase().contains("retry") && !text.to_lowercase().contains("resend"), "{text}");
        }
    }
}
