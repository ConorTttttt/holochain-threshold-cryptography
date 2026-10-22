//! A bounded encrypted probe in its OWN protocol/proposal namespace.
//! No FROST controller, ceremony initialization or nonce API is invoked here.
//! Approved pins are operator input; observations are NEVER promoted to pins.
use crate::{
    capability_exchange::CeremonyRecord, conductor_bridge::KeyEvidence,
    key_pinning::verify_explicit_key_roster, node_service,
    transport_channel::DurableTransportChannel,
};
use holochain_mpc_core::{commitment, Envelope, SealedPacket};
use holochain_mpc_runtime::{transport_key::TransportKeyBinding, Received, RuntimeStore};
use holochain_mpc_security::{sealed::ChannelHeader, Ceremony};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

pub const PROTOCOL: &str = "mpc-transport-probe";
pub const DOMAIN: &str = "holochain-mpc/transport-probe/v1";
pub const MAX_CLEAR: usize = 128;
// Two nested JSON byte arrays expand the bounded 3 KiB sealed payload.
pub const MAX_PACKET: usize = 48 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbePlan {
    pub schema: u8,
    pub record: CeremonyRecord,
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub max_plaintext: usize,
    pub expected_payload_hash: [u8; 32],
    /// Independently reviewed exact public registration actions, sorted by author.
    pub approved_keys: Vec<KeyEvidence>,
}

impl ProbePlan {
    pub fn validate(&self) -> Result<(), String> {
        self.record.validate()?;
        let spec = &self.record.spec;
        if self.schema != 1
            || spec.protocol_id != PROTOCOL
            || spec.protocol_version != 1
            || spec.max_round != 1
            || spec.participants.len() != 2
            || spec.threshold != 2
            || !spec.contains(&self.sender)
            || !spec.contains(&self.recipient)
            || self.sender == self.recipient
            || self.max_plaintext == 0
            || self.max_plaintext > MAX_CLEAR
            || self.expected_payload_hash == [0; 32]
        {
            return Err("invalid isolated probe plan".into());
        }
        let members: BTreeSet<_> = spec.participants.iter().cloned().collect();
        let mut authors = BTreeSet::new();
        let mut actions = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for k in &self.approved_keys {
            use holochain_zome_types::prelude::{ActionHash, AgentPubKey};
            AgentPubKey::try_from_raw_39(k.author.clone())
                .map_err(|_| "invalid approved key author")?;
            ActionHash::try_from_raw_39(k.action.clone())
                .map_err(|_| "invalid approved key action")?;
            if !authors.insert(k.author.clone())
                || !actions.insert(k.action.clone())
                || !keys.insert(k.public_key)
                || k.public_key == [0; 32]
            {
                return Err("duplicate or invalid approved key evidence".into());
            }
        }
        if authors != members
            || self
                .approved_keys
                .windows(2)
                .any(|w| w[0].author >= w[1].author)
        {
            return Err("approved probe roster must exactly match members in author order".into());
        }
        Ok(())
    }
    pub fn ceremony(&self) -> Ceremony {
        Ceremony {
            spec: self.record.spec.clone(),
            proposal_action: self.record.proposal_action.clone(),
        }
    }
    pub fn digest(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        Ok(commitment(
            "mpc-transport-probe/plan/v1",
            &serde_json::to_vec(self).map_err(|_| "plan encoding")?,
        ))
    }
    pub fn message_id(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        let bytes = serde_json::to_vec(&(
            DOMAIN,
            &self.record.dna_hash,
            self.ceremony()
                .fingerprint()
                .map_err(|_| "invalid ceremony")?,
            &self.sender,
            &self.recipient,
            1_u32,
            1_u64,
        ))
        .map_err(|_| "identity encoding")?;
        Ok(commitment("mpc-transport-probe/message-id/v1", &bytes))
    }
    pub fn header(&self) -> ChannelHeader {
        ChannelHeader {
            sender: self.sender.clone(),
            recipient: self.recipient.clone(),
            round: 1,
            sequence: 1,
        }
    }
    pub fn key(&self, author: &[u8]) -> Result<[u8; 32], String> {
        self.approved_keys
            .iter()
            .find(|k| k.author == author)
            .map(|k| k.public_key)
            .ok_or_else(|| "no approved probe key for author".into())
    }
    pub fn validate_envelope(&self, env: &Envelope) -> Result<SealedPacket, String> {
        self.validate()?;
        env.validate_received(&self.record.spec, &self.recipient, &self.sender)
            .map_err(|_| "probe envelope binding refused")?;
        if env.recipient.as_deref() != Some(self.recipient.as_slice())
            || env.round != 1
            || env.sequence != 1
            || env.payload.len() > MAX_PACKET
        {
            return Err("probe identity or size refused".into());
        }
        let packet: SealedPacket =
            serde_json::from_slice(&env.payload).map_err(|_| "probe requires ciphertext")?;
        if !packet.structurally_valid()
            || packet.sender_key != self.key(&self.sender)?
            || packet.recipient_key != self.key(&self.recipient)?
        {
            return Err("probe packet does not match approved key evidence".into());
        }
        Ok(packet)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProbeBody {
    domain: String,
    dna: Vec<u8>,
    ceremony: [u8; 32],
    registrations: [u8; 32],
    plan: [u8; 32],
    message_id: [u8; 32],
    header: ChannelHeader,
    payload_hash: [u8; 32],
    payload: Vec<u8>,
}
impl Drop for ProbeBody {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.payload);
    }
}
fn body(plan: &ProbePlan, payload: &[u8]) -> Result<ProbeBody, String> {
    if payload.is_empty()
        || payload.len() > plan.max_plaintext
        || commitment("mpc-transport-probe/payload/v1", payload) != plan.expected_payload_hash
    {
        return Err("probe plaintext differs from approved digest/limit".into());
    }
    Ok(ProbeBody {
        domain: DOMAIN.into(),
        dna: plan.record.dna_hash.clone(),
        ceremony: plan
            .ceremony()
            .fingerprint()
            .map_err(|_| "ceremony encoding")?,
        registrations: commitment(
            "mpc-transport-probe/registrations/v1",
            &serde_json::to_vec(&plan.approved_keys).map_err(|_| "registration encoding")?,
        ),
        plan: plan.digest()?,
        message_id: plan.message_id()?,
        header: plan.header(),
        payload_hash: plan.expected_payload_hash,
        payload: payload.to_vec(),
    })
}

pub struct ProbeEndpoint {
    plan: ProbePlan,
    local: Vec<u8>,
    store: RuntimeStore,
    channel: DurableTransportChannel,
}
impl ProbeEndpoint {
    /// The observed records must come from the pinned local conductor. The
    /// full proposal spec must be checked separately before opening local state.
    pub fn new(
        plan: ProbePlan,
        local: Vec<u8>,
        store: RuntimeStore,
        binding: TransportKeyBinding,
        channel: DurableTransportChannel,
        observed: &[KeyEvidence],
    ) -> Result<Self, String> {
        plan.validate()?;
        if local != binding.agent
            || binding.dna.as_slice() != plan.record.dna_hash
            || !plan.record.spec.contains(&local)
        {
            return Err("probe node identity mismatch".into());
        }
        verify_explicit_key_roster(
            &plan.ceremony(),
            &binding,
            &channel,
            &plan.approved_keys,
            observed,
        )?;
        Ok(Self {
            plan,
            local,
            store,
            channel,
        })
    }
    pub fn open_node(
        plan: ProbePlan,
        node: &Path,
        observed: &[KeyEvidence],
    ) -> Result<Self, String> {
        plan.validate()?;
        let ctx =
            node_service::pinned_context(node).map_err(|_| "probe node context unavailable")?;
        if ctx.proposal_action != plan.record.proposal_action
            || ctx.session_id != plan.record.spec.session_id
            || !plan.record.spec.contains(&ctx.worker_agent)
        {
            return Err("node belongs to another proposal/session".into());
        }
        let dna = plan
            .record
            .dna_hash
            .as_slice()
            .try_into()
            .map_err(|_| "invalid probe DNA")?;
        let (store, binding, channel) = node_service::open_transport_channel(node, dna, false)
            .map_err(|_| "retained probe transport state unavailable")?;
        Self::new(plan, ctx.worker_agent, store, binding, channel, observed)
    }
    /// Commit immutable admission before exposing the ciphertext to a signer.
    pub fn admit(&mut self, payload: &[u8]) -> Result<Envelope, String> {
        if self.local != self.plan.sender {
            return Err("only pinned sender may admit probe".into());
        }
        let clear = zeroize::Zeroizing::new(
            serde_json::to_vec(&body(&self.plan, payload)?).map_err(|_| "probe encoding")?,
        );
        let packet = self
            .channel
            .native()
            .seal(
                &self.plan.ceremony(),
                self.plan.header(),
                self.plan.key(&self.plan.recipient)?,
                &clear,
            )
            .map_err(|_| "probe sealing failed")?;
        let env = Envelope::new(
            &self.plan.record.spec,
            self.plan.sender.clone(),
            Some(self.plan.recipient.clone()),
            1,
            1,
            serde_json::to_vec(&packet).map_err(|_| "packet encoding")?,
        )
        .map_err(|_| "probe envelope invalid")?;
        self.plan.validate_envelope(&env)?;
        self.store
            .probe_admit(
                &self.plan.record.proposal_action,
                self.plan.digest()?,
                self.plan.message_id()?,
                &env,
            )
            .map_err(|_| "probe admission refused: inspect previous attempt; never retry")?;
        Ok(env)
    }
    pub fn attempt(&self) -> Result<Option<holochain_mpc_runtime::probe::ProbeAttempt>, String> {
        let attempt = self
            .store
            .probe_attempt(
                &self.plan.record.proposal_action,
                &self.plan.sender,
                self.plan.digest()?,
                self.plan.message_id()?,
            )
            .map_err(|_| "probe ledger mismatch")?;
        if let Some(ref a) = attempt {
            self.plan.validate_envelope(&a.envelope)?;
        }
        Ok(attempt)
    }
    /// Publish at most once. Admission survives cancellation, panic and process
    /// death. Even definite signing failures burn the attempt conservatively.
    pub async fn send_once<T: crate::relay::MpcTransport>(
        &mut self,
        transport: &mut T,
        payload: &[u8],
    ) -> Result<crate::relay::SendReceipt, String> {
        let env = self.admit(payload)?;
        match tokio::time::timeout(std::time::Duration::from_secs(30), transport.publish(&env))
            .await
        {
            Ok(Ok(receipt))
                if receipt.action.len() == 39 && receipt.action.iter().any(|b| *b != 0) =>
            {
                if self
                    .store
                    .probe_acknowledge(
                        &self.plan.record.proposal_action,
                        &self.plan.sender,
                        self.plan.digest()?,
                        self.plan.message_id()?,
                        &receipt.action,
                    )
                    .is_err()
                {
                    let _ = self.mark_uncertain();
                    return Err(
                        "delivery acknowledged but local commit uncertain; inspect; never retry"
                            .into(),
                    );
                }
                Ok(receipt)
            }
            _ => {
                let _ = self.mark_uncertain();
                Err("probe delivery UNCERTAIN; inspect recipient; never retry".into())
            }
        }
    }
    fn mark_uncertain(&mut self) -> Result<(), String> {
        self.store
            .probe_uncertain(&self.plan.record.proposal_action, &self.plan.sender)
            .map_err(|_| "cannot mark uncertain; pending admission remains terminal".into())
    }
    /// env MUST originate in this node's authenticated conductor inbox, not
    /// arbitrary JSON. AEAD and all inner bindings precede durable replay admission.
    /// Returns no plaintext: the approved digest is the verification result.
    pub fn receive(&mut self, env: &Envelope) -> Result<Received, String> {
        if self.local != self.plan.recipient {
            return Err("only pinned recipient may open probe".into());
        }
        let packet = self.plan.validate_envelope(env)?;
        let clear = zeroize::Zeroizing::new(
            self.channel
                .native()
                .open(
                    &self.plan.ceremony(),
                    &self.plan.header(),
                    self.plan.key(&self.plan.sender)?,
                    &packet,
                )
                .map_err(|_| "probe authentication failed")?,
        );
        let decoded: ProbeBody =
            serde_json::from_slice(&clear).map_err(|_| "invalid encrypted probe body")?;
        if decoded != body(&self.plan, &decoded.payload)? {
            return Err("encrypted probe identity mismatch".into());
        }
        self.store
            .probe_accept(
                &self.plan.record.proposal_action,
                self.plan.digest()?,
                self.plan.message_id()?,
                env,
            )
            .map_err(|_| "probe replay/equivocation refused".into())
    }
}

/// Verify the real typed status against operator-pinned proposal contents.
/// accepted/ready are local observations, not network finality.
pub fn verify_status(
    record: &CeremonyRecord,
    spec: &holochain_mpc_core::SessionSpec,
    accepted: &[Vec<u8>],
    ready: bool,
) -> Result<(), String> {
    crate::probe_signer::validate_record(record)?;
    record.pin_spec(spec)?;
    let members: BTreeSet<_> = record.spec.participants.iter().cloned().collect();
    let observed: BTreeSet<_> = accepted.iter().cloned().collect();
    if !ready || observed != members || observed.len() != accepted.len() {
        return Err("probe proposal lacks exact unanimous observed acceptance".into());
    }
    Ok(())
}

/// Offline proposal builder. A real action hash/acceptance still requires
/// separately approved operator writes; this function performs no IO.
pub fn proposal_spec(
    app_id: &str,
    dna: &[u8],
    members: &[Vec<u8>],
    session: [u8; 32],
) -> Result<holochain_mpc_core::SessionSpec, String> {
    use holochain_zome_types::prelude::{AgentPubKey, DnaHash};
    DnaHash::try_from_raw_39(dna.to_vec()).map_err(|_| "invalid probe DNA")?;
    let mut members = members.to_vec();
    members.sort();
    if app_id.is_empty() || app_id.len() > 128 || members.len() != 2 || members[0] == members[1] {
        return Err("probe proposal requires app and two distinct members".into());
    }
    for member in &members {
        AgentPubKey::try_from_raw_39(member.clone()).map_err(|_| "invalid probe member")?;
    }
    let description = serde_json::to_vec(&(DOMAIN, app_id, dna, session, &members))
        .map_err(|_| "probe context encoding")?;
    let spec = holochain_mpc_core::SessionSpec {
        session_id: session,
        application_id: "org.holochain.mpc.transport-probe".into(),
        protocol_id: PROTOCOL.into(),
        protocol_version: 1,
        context_hash: commitment("mpc-transport-probe/proposal-context/v1", &description),
        participants: members,
        threshold: 2,
        max_round: 1,
    };
    spec.validate().map_err(|_| "invalid probe proposal")?;
    Ok(spec)
}
