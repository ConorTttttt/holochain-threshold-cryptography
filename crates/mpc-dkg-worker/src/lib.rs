//! EXPERIMENTAL v0.3.7 process-isolated, optional durable DKG controller.
//!
//! All secret FROST packages and X25519 private keys remain inside the child
//! process. The host exchanges only PUBLIC envelopes, authenticated ciphertext
//! and final PUBLIC group descriptors over a line-framed JSON protocol.
//!
//! SECURITY BOUNDARY: The host/test harness MUST obtain the `authenticated_sender`
//! from Holochain conductor-authenticated private inbox records, verify every
//! key binding's AUTHOR and ACTION, and keep the child's stdio pipes private.
//! Arbitrary callers can LIE on this IPC channel: it is NOT a production
//! authenticated sidecar API. Child state is volatile: a crash ABORTS DKG;
//! there is NO key recovery, live signing, OS secret provisioning or rollback
//! protection in this release. Never use it with valuable keys.
use std::collections::{BTreeMap, BTreeSet};
pub mod ipc;
#[cfg(unix)]
pub mod node_service;
use ipc::{AuthChannel, AuthFrame, ChannelContext, Role};
use holochain_mpc_core::Envelope;
use holochain_mpc_frost_ed25519 as frost;
use holochain_mpc_security::{BroadcastMessage, Ceremony, EchoBroadcast, VerifiedTranscript};
use holochain_mpc_security::activation::GroupDescriptor;
use holochain_mpc_security::sealed::NativeChannelKey;
use serde::{Deserialize, Serialize};
use holochain_mpc_runtime::{MasterKey, RuntimeStore};
use holochain_mpc_core::commitment;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag="op", rename_all="snake_case", deny_unknown_fields)]
pub enum Command {
    Init { binding: frost::Binding, local: Vec<u8> },
    Deliver { authenticated_sender: Vec<u8>, envelope: Envelope },
    Attest,
    BeginRoundTwo { pinned_keys: Vec<PeerKeyBinding> },
    Finalize,
}

/// The host asserts it has checked the exact agent-authored Holochain action,
/// and it must reject forks/duplicates before submitting the full pinned set.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyBinding {
    pub member: Vec<u8>,
    pub public_key: [u8; 32],
    pub action: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag="result", rename_all="snake_case", deny_unknown_fields)]
pub enum Reply {
    Initialized { local_public_key: [u8; 32], outbound: Vec<Envelope> },
    Delivered { outbound: Vec<Envelope> },
    Attesting { outbound: Vec<Envelope> },
    RoundTwo { transcript_hash: [u8; 32], outbound: Vec<Envelope> },
    Completed { descriptor: GroupDescriptor },
    Error { reason: String },
}

struct Active {
    binding: frost::Binding,
    local: Vec<u8>,
    party: frost::DkgParty,
    broadcast: EchoBroadcast,
    transport_key: NativeChannelKey,
    echo_sequence: u64,
    seen: BTreeSet<(Vec<u8>, u32, u64)>,
    peer_keys: BTreeMap<Vec<u8>, PeerKeyBinding>,
    gate: Option<VerifiedTranscript>,
    round_one: Option<BTreeMap<frost::Identifier, frost::RoundOne>>,
    incoming_shares: BTreeMap<frost::Identifier, frost::RoundTwo>,
    phase: Phase,
    // Deliberately never exported. Dropped when worker exits.
    completed_key: Option<frost::KeyPackage>,
}
#[derive(PartialEq, Eq)]
enum Phase { Broadcast, CollectShares, Completed }

pub struct Controller { active: Option<Active>, poisoned: bool }
impl Default for Controller {
    fn default() -> Self { Self { active: None, poisoned: false } }
}

fn invalid(reason: &'static str) -> String { reason.to_owned() }

impl Controller {
    pub fn handle(&mut self, command: Command) -> Result<Reply, String> {
        if self.poisoned { return Err(invalid("ceremony aborted; start a fresh process and fresh proposal")); }
        let result = self.process(command);
        // Fail closed. Any error destroys in-process secrets and permanently
        // poisons this controller; the CLI also exits with a failing status.
        if result.is_err() {
            self.poisoned = true;
            self.active = None;
        }
        result
    }
    fn process(&mut self, command: Command) -> Result<Reply, String> {
        match command {
            Command::Init { binding, local } => {
                if self.active.is_some() { return Err(invalid("already initialized")); }
                if !binding.spec.contains(&local) { return Err(invalid("not a ceremony member")); }
                let ceremony = Ceremony { spec: binding.spec.clone(), proposal_action: binding.proposal_action.clone() };
                let (party, public) = frost::DkgParty::begin(binding.clone(), &local).map_err(|e| e.to_string())?;
                let mut broadcast = EchoBroadcast::new(ceremony, local.clone()).map_err(|e| e.to_string())?;
                let announce = broadcast.begin(serde_json::to_vec(&public).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
                let outbound = to_peers(&broadcast, &binding, &local, 1, &announce)?;
                let transport_key = NativeChannelKey::generate();
                let local_public_key = transport_key.public_key();
                self.active = Some(Active { binding, local, party, broadcast, transport_key,
                    echo_sequence: 2, seen: BTreeSet::new(), peer_keys: BTreeMap::new(),
                    gate: None, round_one: None, incoming_shares: BTreeMap::new(),
                    phase: Phase::Broadcast, completed_key: None });
                Ok(Reply::Initialized { local_public_key, outbound })
            }
            Command::Deliver { authenticated_sender, envelope } => {
                let state = self.active.as_mut().ok_or_else(|| invalid("initialize first"))?;
                if envelope.sender != authenticated_sender ||
                   !state.binding.spec.contains(&authenticated_sender) ||
                   authenticated_sender == state.local {
                    return Err(invalid("sender not authenticated"));
                }
                if !state.seen.insert((authenticated_sender.clone(), envelope.round, envelope.sequence)) {
                    return Err(invalid("duplicate logical delivery"));
                }
                match (state.phase == Phase::Broadcast, envelope.round) {
                    (true, 1 | 2) => {
                        let echo = state.broadcast.receive_envelope(&state.local, &authenticated_sender, &envelope)
                            .map_err(|e| e.to_string())?;
                        let mut outbound = Vec::new();
                        if let Some(message) = echo {
                            if !matches!(&message, BroadcastMessage::EchoDigest { .. }) {
                                return Err(invalid("expected compact echo"));
                            }
                            outbound = to_peers(&state.broadcast, &state.binding, &state.local,
                                state.echo_sequence, &message)?;
                            state.echo_sequence += 1;
                        }
                        Ok(Reply::Delivered { outbound })
                    }
                    (false, 3) if state.phase == Phase::CollectShares => {
                        let pin = state.peer_keys.get(&authenticated_sender)
                            .ok_or_else(|| invalid("missing pinned sender key"))?;
                        let frame = frost::open_dkg_round_two(&state.binding, &envelope,
                            &state.local, &authenticated_sender, &state.transport_key, pin.public_key)
                            .map_err(|e| e.to_string())?;
                        let frost::Message::DkgRound2(share) = frame.message else {
                            return Err(invalid("expected a Round-2 FROST share"));
                        };
                        let id = state.binding.id_of(&authenticated_sender).map_err(|e| e.to_string())?;
                        if state.incoming_shares.insert(id, share).is_some() {
                            return Err(invalid("duplicate share"));
                        }
                        Ok(Reply::Delivered { outbound: vec![] })
                    }
                    _ => Err(invalid("message for incorrect DKG phase")),
                }
            }
            Command::Attest => {
                let state = self.active.as_mut().ok_or_else(|| invalid("initialize first"))?;
                if state.phase != Phase::Broadcast { return Err(invalid("not in broadcast phase")); }
                // Protocol gate checks all echoes were received.
                let msg = state.broadcast.attest().map_err(|e| e.to_string())?;
                let outbound = to_peers(&state.broadcast, &state.binding, &state.local, 1, &msg)?;
                Ok(Reply::Attesting { outbound })
            }
            Command::BeginRoundTwo { pinned_keys } => {
                let state = self.active.as_mut().ok_or_else(|| invalid("initialize first"))?;
                if state.phase != Phase::Broadcast { return Err(invalid("not in broadcast phase")); }
                if pinned_keys.len() != state.binding.spec.participants.len() {
                    return Err(invalid("key pin set not complete"));
                }
                let mut keys = BTreeMap::new();
                for pin in pinned_keys {
                    if !state.binding.spec.contains(&pin.member) || pin.public_key == [0;32] ||
                       pin.action.len() != 39 || keys.insert(pin.member.clone(), pin).is_some() {
                        return Err(invalid("invalid or duplicate key binding"));
                    }
                }
                if keys.get(&state.local).map(|p| p.public_key) != Some(state.transport_key.public_key()) {
                    return Err(invalid("our own key pin disagrees with local secret"));
                }
                let gate = state.broadcast.finalize().map_err(|e| e.to_string())?;
                let mut packages = BTreeMap::new();
                for member in &state.binding.spec.participants {
                    let public: frost::RoundOne = serde_json::from_slice(gate.package(member)
                        .ok_or_else(|| invalid("missing agreed Round-1 package"))?)
                        .map_err(|e| e.to_string())?;
                    packages.insert(state.binding.id_of(member).map_err(|e| e.to_string())?, public);
                }
                let outgoing = state.party.part2(&packages, &gate).map_err(|e| e.to_string())?;
                let mut outbound = Vec::new();
                for member in &state.binding.spec.participants {
                    if member == &state.local { continue; }
                    let id = state.binding.id_of(member).map_err(|e| e.to_string())?;
                    let share = outgoing.get(&id).ok_or_else(|| invalid("missing outgoing encrypted share"))?;
                    let frame = frost::Frame { proposal_action: state.binding.proposal_action.clone(),
                        operation_id: state.binding.spec.session_id,
                        message: frost::Message::DkgRound2(share.clone()) };
                    let env = frost::seal_dkg_round_two(&state.binding, &frame, &state.local, member,
                        1, &state.transport_key, keys[member].public_key)
                        .map_err(|e| e.to_string())?;
                    outbound.push(env);
                }
                let transcript_hash = gate.hash();
                state.gate = Some(gate);
                state.round_one = Some(packages);
                state.peer_keys = keys;
                state.phase = Phase::CollectShares;
                Ok(Reply::RoundTwo { transcript_hash, outbound })
            }
            Command::Finalize => {
                let state = self.active.as_mut().ok_or_else(|| invalid("initialize first"))?;
                if state.phase != Phase::CollectShares ||
                   state.incoming_shares.len() != state.binding.spec.participants.len() - 1 {
                    return Err(invalid("missing encrypted shares or incorrect phase"));
                }
                let (secret, _public, evidence) = state.party.part3_with_evidence(
                    state.round_one.as_ref().ok_or_else(|| invalid("Round-1 packages absent"))?,
                    &state.incoming_shares,
                    state.gate.as_ref().ok_or_else(|| invalid("transcript gate absent"))?)
                    .map_err(|e| e.to_string())?;
                let actions = state.binding.spec.participants.iter().map(|member|
                    state.peer_keys.get(member).map(|pin| pin.action.clone())
                        .ok_or_else(|| invalid("missing member action")))
                    .collect::<Result<Vec<_>,_>>()?;
                let descriptor = evidence.group_descriptor(&state.binding, 0, actions)
                    .map_err(|e| e.to_string())?;
                state.completed_key = Some(secret);
                state.phase = Phase::Completed;
                Ok(Reply::Completed { descriptor })
            }
        }
    }
}


/// MAC-authenticated command gate. A failed authentication, sequence, binding,
/// or DKG check irrevocably aborts this worker instance.
///
/// This gate trusts bootstrap key provisioning and the local Holochain bridge's
/// authenticated_sender assertions; neither is verified independently here.
pub struct AuthenticatedController {
    gate: AuthChannel,
    context: ChannelContext,
    inner: Controller,
    dead: bool,
    initialized: bool,
    durable: Option<RuntimeStore>,
}
impl AuthenticatedController {
    pub fn new(secret: [u8; 32], context: ChannelContext) -> Result<Self, String> {
        let gate = AuthChannel::new(secret, context.clone(), Role::Worker)?;
        Ok(Self { gate, context, inner: Controller::default(), dead: false, initialized: false, durable: None })
    }
    /// A non-resumable, encrypted, SQLite-backed DKG. An existing checkpoint
    /// (even completed/aborted) blocks re-entry for the SAME proposal/agent.
    /// The state encryption key must come from a trusted external provisioner.
    pub fn new_durable(secret: [u8; 32], context: ChannelContext,
                       db_path: &Path, master_key: MasterKey) -> Result<Self, String> {
        let mut controller = Self::new(secret, context)?;
        let store = RuntimeStore::open(db_path, master_key).map_err(|e| e.to_string())?;
        if store.dkg_checkpoint(&controller.context.proposal_action,
                                &controller.context.worker_agent,
                                &controller.context.session_id)
            .map_err(|e| e.to_string())?.is_some() {
            return Err("existing DKG checkpoint; unsafe to restart; create a fresh proposal".into());
        }
        controller.durable = Some(store);
        Ok(controller)
    }

    pub fn handle(&mut self, frame: AuthFrame<Command>) -> Result<AuthFrame<Reply>, String> {
        if self.dead { return Err("authenticated controller is aborted".into()); }
        let result = self.try_handle(frame);
        if result.is_err() {
            self.dead = true;
            self.inner.poisoned = true;
            self.inner.active = None;
            // The live process is already dead-on-error. If the database fails,
            // refuse further replies; its existing running marker still blocks
            // recovery, so a crash cannot silently restart the old ceremony.
            if let Some(store) = self.durable.as_mut() {
                store.dkg_abort(&self.context.proposal_action, &self.context.worker_agent,
                    &self.context.session_id)
                    .map_err(|e| format!("cannot durably abort DKG: {e}"))?;
            }
        }
        result
    }
    fn try_handle(&mut self, frame: AuthFrame<Command>) -> Result<AuthFrame<Reply>, String> {
        let command = self.gate.open(frame)?;
        if let Command::Init { binding, local } = &command {
            if self.initialized || local != &self.context.worker_agent ||
               binding.proposal_action != self.context.proposal_action ||
               binding.spec.session_id != self.context.session_id {
                return Err("initial ceremony identity is not authorised by channel context".into());
            }
        } else if !self.initialized {
            return Err("authenticated Init required first".into());
        }
        let is_init = matches!(&command, Command::Init { .. });
        if is_init {
            // Persist the admission marker BEFORE FROST generates any secrets
            // or public announcements can be released.
            if let Some(store) = self.durable.as_mut() {
                store.dkg_begin(&self.context.proposal_action, &self.context.worker_agent,
                    &self.context.session_id).map_err(|e| e.to_string())?;
            }
        }
        let reply = self.inner.handle(command)?;
        if let Some(store) = self.durable.as_mut() {
            // Persist encrypted metadata and the digest of the *public*
            // response before any authenticated IPC output becomes visible.
            let bytes = serde_json::to_vec(&reply).map_err(|e| e.to_string())?;
            let digest = commitment("dkg-ipc-public-reply-v1", &bytes);
            let completed = matches!(&reply, Reply::Completed { .. });
            store.dkg_record_reply(&self.context.proposal_action,
                &self.context.worker_agent, &self.context.session_id,
                digest, completed).map_err(|e| e.to_string())?;
        }
        if is_init { self.initialized = true; }
        self.gate.seal(reply)
    }
}

fn to_peers(broadcast: &EchoBroadcast, binding: &frost::Binding, local: &[u8],
            sequence: u64, message: &BroadcastMessage) -> Result<Vec<Envelope>, String> {
    binding.spec.participants.iter().filter(|p| p.as_slice() != local)
        .map(|recipient| broadcast.outgoing(recipient, sequence, message).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use holochain_mpc_core::{commitment, SessionSpec};

    fn binding() -> frost::Binding {
        let spec = SessionSpec {
            session_id: commitment("v035-test-session", b"worker unit test"),
            application_id: "org.example.test".into(),
            protocol_id: frost::PROTOCOL_ID.into(),
            protocol_version: frost::PROTOCOL_VERSION,
            context_hash: commitment("v035-test-context", b"unit context"),
            participants: vec![vec![1; 39], vec![2; 39], vec![3; 39]],
            threshold: 2,
            max_round: 6,
        };
        frost::Binding::new(vec![9;39], spec).unwrap()
    }

    #[test]
    fn authenticated_controller_rejects_wrong_agent_and_does_not_resume() {
        let binding = binding();
        let ctx = ipc::ChannelContext { worker_agent: binding.spec.participants[0].clone(),
            proposal_action: binding.proposal_action.clone(), session_id: binding.spec.session_id,
            channel_id: [7; 32] };
        let mut host = ipc::AuthChannel::new([8;32], ctx.clone(), ipc::Role::Host).unwrap();
        let mut worker = AuthenticatedController::new([8;32], ctx).unwrap();
        let bad = host.seal(Command::Init { binding: binding.clone(),
            local: binding.spec.participants[1].clone() }).unwrap();
        assert!(worker.handle(bad).is_err());
        let good = host.seal(Command::Init { binding: binding.clone(),
            local: binding.spec.participants[0].clone() }).unwrap();
        assert!(worker.handle(good).is_err());
    }
    #[test]
    fn authenticated_controller_rejects_forgery_before_crypto_state_change() {
        let binding = binding();
        let ctx = ipc::ChannelContext { worker_agent: binding.spec.participants[0].clone(),
            proposal_action: binding.proposal_action.clone(), session_id: binding.spec.session_id,
            channel_id: [7;32] };
        let mut fake = ipc::AuthChannel::new([9;32], ctx.clone(), ipc::Role::Host).unwrap();
        let mut worker = AuthenticatedController::new([8;32], ctx).unwrap();
        assert!(worker.handle(fake.seal(Command::Init { binding: binding.clone(),
            local: binding.spec.participants[0].clone() }).unwrap()).is_err());
        assert!(worker.handle(fake.seal(Command::Attest).unwrap()).is_err());
    }
    #[test]
    fn incomplete_broadcast_fails_closed_and_stays_poisoned() {
        let binding = binding();
        let mut worker = Controller::default();
        let Reply::Initialized { local_public_key: _, outbound } = worker.handle(Command::Init {
            binding: binding.clone(), local: binding.spec.participants[0].clone(),
        }).unwrap() else { panic!("unexpected reply") };
        assert_eq!(outbound.len(), 2);
        // Without ALL announcements/echoes, no Round-2 transition is allowed.
        assert!(worker.handle(Command::BeginRoundTwo { pinned_keys: vec![] }).is_err());
        assert!(worker.handle(Command::Attest).is_err());
        assert!(worker.handle(Command::Init {
            binding: binding.clone(), local: binding.spec.participants[0].clone(),
        }).is_err());
    }

    #[test]
    fn impersonated_delivery_aborts_and_cannot_restart() {
        let binding = binding();
        let mut worker = Controller::default();
        let Reply::Initialized { outbound, .. } = worker.handle(Command::Init {
            binding: binding.clone(), local: binding.spec.participants[0].clone(),
        }).unwrap() else { panic!("unexpected reply") };
        let envelope = outbound.into_iter().next().unwrap();
        let impostor = binding.spec.participants[2].clone();
        assert!(worker.handle(Command::Deliver {
            authenticated_sender: impostor, envelope,
        }).is_err());
        assert!(worker.handle(Command::Attest).is_err());
    }
}
