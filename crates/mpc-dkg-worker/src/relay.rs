//! v0.4.0 Phase 3: fail-closed, ceremony-scoped automatic DKG relay engine.
//!
//! Only a *trusted* local Holochain app-client may implement `MpcTransport`.
//! Inbox provenance and key-record authorship MUST come from authenticated
//! zome responses, never from arbitrary HTTP/JSON or a remote peer's assertion.
//! This engine does not sign for a Holochain agent or hold agent credentials.
//! It owns no FROST secrets; one native node process owns each party's secrets.
//!
//! Each pending send is attempted exactly once. An uncertain delivery result,
//! transport error, equivocation, or IPC error ABORTS the entire relay. Do not
//! resume the same ceremony, retry old signed bytes or reuse DKG randomness.
use crate::conductor_bridge::{ConductorBridge, KeyEvidence};
use crate::inbox_slots::InboxSlots;
use holochain_mpc_core::{Envelope, SealedPacket};
use holochain_mpc_frost_ed25519::Binding;
use holochain_mpc_security::{BroadcastMessage, BoundBroadcastV2, Ceremony, EchoBroadcast};
use holochain_mpc_security::activation::GroupDescriptor;
use std::collections::{BTreeMap, BTreeSet};

const MAX_INBOX: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase { New, Echo, Attest, Shares, Complete, Aborted }

#[derive(Debug)]
pub struct TickReport {
    pub phase: Phase,
    pub delivered: usize,
    pub published: usize,
}

/// Result from a zome's acknowledged `send_protocol_message` call.
#[derive(Clone, Debug)]
pub struct SendReceipt {
    pub action: Vec<u8>,
    pub already_stored: bool,
}

/// True only when every visible record is from a distinct ceremony member
/// and some members are simply not visible yet (eventual consistency).
fn key_roster_incomplete(binding: &Binding, keys: &[KeyEvidence]) -> bool {
    let authors: BTreeSet<&Vec<u8>> = keys.iter().map(|k| &k.author).collect();
    authors.len() == keys.len() && authors.len() < binding.spec.participants.len() &&
        keys.iter().all(|k| binding.spec.contains(&k.author))
}

/// Implement ONLY with a conductor-authenticated, cell-pinned app transport.
/// The transport is responsible for fresh authorised signatures for EVERY
/// zome RPC, including separate signatures if a later RPC is attempted.
#[allow(async_fn_in_trait)]
pub trait MpcTransport {
    async fn register_key(&mut self, public_key: [u8;32]) -> Result<Vec<u8>, String>;
    async fn get_inbox_slots(&mut self) -> Result<InboxSlots, String>;
    async fn get_encryption_keys(&mut self) -> Result<Vec<KeyEvidence>, String>;
    async fn publish(&mut self, envelope: &Envelope) -> Result<SendReceipt, String>;
}

/// A private, authenticated worker interface. Production uses the Unix-socket
/// `ConductorBridge`; test doubles MUST NOT be treated as secure node services.
pub trait LocalDkgNode {
    fn initialize(&mut self) -> Result<([u8;32], Vec<Envelope>), String>;
    fn deliver(&mut self, envelope: Envelope) -> Result<Vec<Envelope>, String>;
    fn attest(&mut self) -> Result<Vec<Envelope>, String>;
    fn round_two(&mut self, evidence: &[KeyEvidence], my_key: [u8;32])
        -> Result<([u8;32], Vec<Envelope>), String>;
    fn finalize(&mut self) -> Result<GroupDescriptor, String>;
    fn validate_outbound(&self, outgoing: &[Envelope]) -> Result<(), String>;
    /// Stop the associated worker on any unrecoverable transport failure.
    /// The real IPC implementation closes its connection; tests may use a
    /// different terminal mechanism. Do not retry ambiguous writes.
    fn abort(&mut self) -> Result<(), String>;
}

impl LocalDkgNode for ConductorBridge {
    fn initialize(&mut self) -> Result<([u8;32], Vec<Envelope>), String> { ConductorBridge::initialize(self) }
    fn deliver(&mut self, envelope: Envelope) -> Result<Vec<Envelope>, String> {
        ConductorBridge::deliver_from_local_inbox(self, envelope)
    }
    fn attest(&mut self) -> Result<Vec<Envelope>, String> { ConductorBridge::attest(self) }
    fn round_two(&mut self, evidence: &[KeyEvidence], my_key: [u8;32])
        -> Result<([u8;32], Vec<Envelope>), String> { ConductorBridge::round_two(self, evidence, my_key) }
    fn finalize(&mut self) -> Result<GroupDescriptor, String> { ConductorBridge::finalize(self) }
    fn validate_outbound(&self, outgoing: &[Envelope]) -> Result<(), String> {
        ConductorBridge::validate_outbound(self, outgoing)
    }
    fn abort(&mut self) -> Result<(), String> { ConductorBridge::abort_connection(self) }
}

pub struct RelayEngine<N, T> {
    node: N,
    transport: T,
    binding: Binding,
    local: Vec<u8>,
    phase: Phase,
    mirror: EchoBroadcast,
    public_key: Option<[u8;32]>,
    transcript: Option<[u8;32]>,
    complete: Option<GroupDescriptor>,
    seen: BTreeMap<(Vec<u8>,u32,u64), Envelope>,
    attesters: BTreeSet<Vec<u8>>,
    sharers: BTreeSet<Vec<u8>>,
}

impl<N: LocalDkgNode, T: MpcTransport> RelayEngine<N, T> {
    pub fn new(node: N, transport: T, binding: Binding, local: Vec<u8>) -> Result<Self, String> {
        Binding::new(binding.proposal_action.clone(), binding.spec.clone())
            .map_err(|e| e.to_string())?;
        if !binding.spec.contains(&local) { return Err("relay agent is not a member".into()); }
        let mirror = EchoBroadcast::new(Ceremony {
            proposal_action: binding.proposal_action.clone(), spec: binding.spec.clone(),
        }, local.clone()).map_err(|e| e.to_string())?;
        Ok(Self { node, transport, binding, local, phase: Phase::New, mirror,
            public_key: None, transcript: None, complete: None,
            seen: BTreeMap::new(), attesters: BTreeSet::new(), sharers: BTreeSet::new() })
    }

    pub fn phase(&self) -> Phase { self.phase }
    pub fn transport_key(&self) -> Option<[u8;32]> { self.public_key }
    pub fn descriptor(&self) -> Option<&GroupDescriptor> { self.complete.as_ref() }

    /// Irrevocably stop this relay and its native worker on a timeout,
    /// shutdown, cancellation, partition, or protocol failure. This is also
    /// valid when `start` was cancelled mid-await before the phase advanced.
    pub fn abort(&mut self) -> Result<(), String> {
        if self.phase == Phase::Complete {
            return Err("cannot abort a locally completed DKG".into());
        }
        self.phase = Phase::Aborted;
        self.complete = None;
        self.node.abort()
    }

    fn poison(&mut self, why: String) -> Result<TickReport, String> {
        if let Err(close) = self.abort() {
            return Err(format!("{why}; worker abort/disconnect failed: {close}"));
        }
        Err(why)
    }

    fn validate_envelope(&self, env: &Envelope, outbound: bool) -> Result<(), String> {
        if outbound {
            if env.sender != self.local || env.recipient.as_deref() == Some(self.local.as_slice()) ||
                env.recipient.is_none() {
                return Err("relay outbound sender/recipient mismatch".into());
            }
            env.validate_against(&self.binding.spec).map_err(|e| e.to_string())?;
        } else {
            env.validate_received(&self.binding.spec, &self.local, &env.sender)
                .map_err(|e| e.to_string())?;
            if env.sender == self.local ||
               env.recipient.as_deref() != Some(self.local.as_slice()) {
                return Err("relay inbox sender/recipient mismatch".into());
            }
        }
        if env.round == 3 {
            let packet: SealedPacket = serde_json::from_slice(&env.payload)
                .map_err(|_| "DKG Round-2 share is not encrypted")?;
            if !packet.structurally_valid() {
                return Err("malformed encrypted Round-2 share".into());
            }
        }
        Ok(())
    }

    fn expected_recipients(&self) -> BTreeSet<Option<Vec<u8>>> {
        self.binding.spec.participants.iter()
            .filter(|p| *p != &self.local).cloned().map(Some).collect()
    }

    async fn publish_all(&mut self, outbound: Vec<Envelope>) -> Result<usize, String> {
        if outbound.len() > 4096 { return Err("worker produced too many messages".into()); }
        self.node.validate_outbound(&outbound)?;
        let mut ids = BTreeSet::new();
        for env in &outbound {
            self.validate_envelope(env, true)?;
            if !ids.insert((env.sender.clone(), env.round, env.sequence, env.recipient.clone())) {
                return Err("duplicate worker-generated outbound message".into());
            }
        }
        let count = outbound.len();
        for env in &outbound {
            // No optimistic success or automatic retry on uncertain result.
            let receipt = self.transport.publish(env).await?;
            if receipt.action.len() != 39 || receipt.action.iter().all(|b| *b == 0) {
                return Err("conductor returned invalid delivery action".into());
            }
        }
        Ok(count)
    }

    /// Starts the worker ONCE. Publish all own announcements before accepting
    /// any inbound messages. Failure poisons this instance and the original
    /// durable DKG journal prevents ceremony re-entry after process restart.
    pub async fn start(&mut self) -> Result<TickReport, String> {
        if self.phase != Phase::New { return self.poison("relay already started".into()); }
        let result: Result<usize, String> = async {
            let (key, outbound) = self.node.initialize()?;
            if outbound.len() != self.binding.spec.participants.len() - 1 {
                return Err("own DKG announcement was not sent to each peer".into());
            }
            let first = outbound.first().ok_or("missing own DKG announcement")?;
            let encoded: BoundBroadcastV2 = serde_json::from_slice(&first.payload)
                .map_err(|_| "malformed own DKG announcement")?;
            if encoded.version != 2 ||
               encoded.proposal_action != self.binding.proposal_action ||
               encoded.ceremony_hash != self.mirror.ceremony().fingerprint()
                   .map_err(|e| e.to_string())? {
                return Err("own announcement belongs to another DKG proposal".into());
            }
            let BroadcastMessage::Announce { package } = encoded.message else {
                return Err("worker did not start with a DKG announcement".into());
            };
            self.mirror.begin(package).map_err(|e| e.to_string())?;
            let mut recipients = BTreeSet::new();
            for env in &outbound {
                if env.round != 1 || env.sequence != 1 || env.payload != first.payload ||
                   !recipients.insert(env.recipient.clone()) {
                    return Err("inconsistent local DKG announcements".into());
                }
            }
            if recipients != self.expected_recipients() {
                return Err("initial DKG announcements omit or duplicate a peer".into());
            }
            // Registration must be committed on the local author chain before
            // the secret-share phase can discover the complete public roster.
            let action = self.transport.register_key(key).await?;
            if action.len() != 39 || action.iter().all(|b| *b == 0) {
                return Err("invalid own encryption-key registration action".into());
            }
            self.public_key = Some(key);
            self.publish_all(outbound).await
        }.await;
        match result {
            Ok(published) => {
                self.phase = Phase::Echo;
                Ok(TickReport { phase: self.phase, delivered: 0, published })
            }
            Err(err) => self.poison(err),
        }
    }

    /// One bounded, authenticated inbox poll. Round-1 echoes, Round-2
    /// attestations, and encrypted shares are processed ONLY in their phase.
    /// Future rounds remain unread from the cumulative inbox until ready.
    /// The peer unanimity gates are enforced by a second independent
    /// `EchoBroadcast` verifier before asking the secret-owning worker.
    pub async fn poll_once(&mut self) -> Result<TickReport, String> {
        if !matches!(self.phase, Phase::Echo | Phase::Attest | Phase::Shares) {
            return Err("relay is not in an active polling phase".into());
        }
        let result: Result<(usize,usize),String> = async {
            let slots = self.transport.get_inbox_slots().await?;
            // Detect new conflicts even for IDs already accepted on a prior poll.
            for slot in &slots.conflicts {
                if self.binding.spec.contains(&slot.sender) && slot.sender != self.local
                    && (1..=3).contains(&slot.round) {
                    return Err("conflicting authenticated DKG inbox slot".into());
                }
            }
            for slot in &slots.over_quota {
                if self.binding.spec.contains(&slot.sender) && slot.sender != self.local
                    && (1..=3).contains(&slot.round) {
                    return Err("required DKG inbox slot withheld over sender quota".into());
                }
            }
            let messages = slots.envelopes;
            if messages.len() > MAX_INBOX { return Err("inbox exceeds relay limit".into()); }
            let mut batch = BTreeMap::new();
            for env in messages {
                self.validate_envelope(&env, false)?;
                let id = (env.sender.clone(),env.round,env.sequence);
                if let Some(previous) = self.seen.get(&id) {
                    if previous != &env { return Err("conflicting previously delivered inbox ID".into()); }
                }
                if let Some(previous) = batch.insert(id, env.clone()) {
                    if previous != env { return Err("conflicting inbox records in same poll".into()); }
                }
            }
            let mut delivered = 0;
            let mut published = 0;
            for (id, env) in batch {
                if self.seen.contains_key(&id) { continue; }
                let applicable = matches!((self.phase, env.round),
                    (Phase::Echo,1) | (Phase::Attest,2) | (Phase::Shares,3));
                if !applicable { continue; }
                if env.round <= 2 {
                    self.mirror.receive_envelope(&self.local, &env.sender, &env)
                        .map_err(|e| e.to_string())?;
                }
                let outbound = self.node.deliver(env.clone())?;
                published += self.publish_all(outbound).await?;
                if env.round == 2 { self.attesters.insert(env.sender.clone()); }
                if env.round == 3 {
                    if !self.sharers.insert(env.sender.clone()) {
                        return Err("multiple encrypted shares from one member".into());
                    }
                }
                self.seen.insert(id, env);
                delivered += 1;
            }
            match self.phase {
                Phase::Echo if self.mirror.echoes_complete() => {
                    let own = self.mirror.attest().map_err(|e| e.to_string())?;
                    let BroadcastMessage::Attest { transcript_hash } = own else {
                        return Err("unexpected local attestation".into());
                    };
                    let outbound = self.node.attest()?;
                    if outbound.len() != self.binding.spec.participants.len()-1 ||
                       outbound.iter().any(|env| {
                           if env.round != 2 { return true; }
                           match serde_json::from_slice::<BoundBroadcastV2>(&env.payload) {
                               Ok(wire) => !matches!(wire.message, BroadcastMessage::Attest { transcript_hash: got } if got == transcript_hash),
                               Err(_) => true,
                           }
                       }) {
                        return Err("worker attestation differs from locally verified transcript".into());
                    }
                    if outbound.iter().map(|env| env.recipient.clone())
                        .collect::<BTreeSet<_>>() != self.expected_recipients() {
                        return Err("attestation not addressed to all peers".into());
                    }
                    published += self.publish_all(outbound).await?;
                    self.transcript = Some(transcript_hash);
                    self.phase = Phase::Attest;
                }
                Phase::Attest if self.attesters.len() == self.binding.spec.participants.len()-1 => {
                    // A peer's key registration can reach this conductor after
                    // its attestation. While the roster is merely incomplete,
                    // wait for a later poll: no randomness is consumed and
                    // nothing is published. Duplicate, forked, foreign or
                    // malformed records still fail closed in `round_two`.
                    let keys = self.transport.get_encryption_keys().await?;
                    if key_roster_incomplete(&self.binding, &keys) {
                        return Ok((delivered, published));
                    }
                    let verified = self.mirror.finalize().map_err(|e| e.to_string())?;
                    let my_key = self.public_key.ok_or("own transport key missing")?;
                    let (transcript, outbound) = self.node.round_two(&keys,my_key)?;
                    if transcript != verified.hash() || self.transcript != Some(transcript) {
                        return Err("worker Round-2 transcript mismatch".into());
                    }
                    if outbound.len() != self.binding.spec.participants.len()-1 ||
                       outbound.iter().any(|env| env.round != 3) {
                        return Err("missing encrypted share to a peer".into());
                    }
                    if outbound.iter().map(|env| env.recipient.clone())
                        .collect::<BTreeSet<_>>() != self.expected_recipients() {
                        return Err("encrypted shares not addressed to all peers".into());
                    }
                    published += self.publish_all(outbound).await?;
                    self.phase = Phase::Shares;
                }
                Phase::Shares if self.sharers.len() == self.binding.spec.participants.len()-1 => {
                    let descriptor = self.node.finalize()?;
                    if Some(descriptor.dkg_transcript_hash) != self.transcript {
                        return Err("completed key package transcript mismatch".into());
                    }
                    self.complete = Some(descriptor);
                    self.phase = Phase::Complete;
                }
                _ => {}
            }
            Ok((delivered,published))
        }.await;
        match result {
            Ok((delivered,published)) => Ok(TickReport {
                phase:self.phase,delivered,published,
            }),
            Err(err) => self.poison(err),
        }
    }
}
