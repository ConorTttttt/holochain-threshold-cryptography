//! v0.4.0 Phase 8: explicitly approved threshold signing across independent
//! nodes, after a completed and activated DKG.
//!
//! Each selected signer runs one `SigningSession` for one `SigningPlan`:
//! round 4 sends its commitments to every other selected signer; every signer
//! then builds the same signing package locally, signs once and sends its
//! share as round 6; every selected signer aggregates and verifies on its own.
//! There is no coordinator, and results must agree.
//!
//! Safety comes from existing pieces: `ControlledSigner` reserves and burns
//! the nonce in SQLite before a commitment leaves the process, signs only an
//! `ApprovedIntent` of an `ActivatedGroup`, and consumes the nonce on any
//! failure. Frame senders are the conductor-authenticated inbox provenance.
//! Any inconsistency aborts; a new attempt needs a NEW operation id.
use crate::ShareCustody;
use holochain_mpc_core::{commitment, Envelope};
use holochain_mpc_frost_ed25519::{self as frost, AuthenticatedShareCollector, Binding,
    ControlledSigner, Frame, Message, SignedArtifact};
use holochain_mpc_runtime::RuntimeStore;
use holochain_mpc_security::activation::{ActivatedGroup, ApprovedIntent, GroupActivation,
    GroupDescriptor, IntentApprovals, SigningIntent, SigningProfile};
use holochain_mpc_security::SecurityError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub const PLAN_SCHEMA: u16 = 1;
const MAX_MESSAGE: usize = 8 * 1024;
/// Compact-JSON bound for a whole plan. Every plan reader (CLI, `mpc-sign`,
/// and the signing signer policy that embeds the plan) refuses files above
/// 64 KiB, so a plan that validates must also fit inside those files.
const MAX_PLAN_BYTES: usize = 48 * 1024;
const PREVIEW_BYTES: usize = 512;

/// One author-signed `GroupActivationAttestation`, as the pinned conductor
/// returned it. `author` is the record's author, never a payload field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationEvidence {
    pub author: Vec<u8>,
    pub epoch: u64,
    pub descriptor_hash: [u8; 32],
    pub dkg_transcript_hash: [u8; 32],
    pub public_key_package_hash: [u8; 32],
}

/// One author-signed `SigningApprovalAttestation` from the pinned conductor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalEvidence {
    pub author: Vec<u8>,
    pub operation_id: [u8; 32],
    pub group_descriptor_hash: [u8; 32],
    pub intent_hash: [u8; 32],
}

/// The public signing request every operator reviews. The same bytes go to
/// every selected operator; nothing in it is secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningPlan {
    pub schema: u16,
    pub descriptor: GroupDescriptor,
    pub operation_id: [u8; 32],
    pub message: Vec<u8>,
    /// Exact signer roster, sorted, at least the threshold.
    pub selected: Vec<Vec<u8>>,
}
impl SigningPlan {
    pub fn validate(&self) -> Result<(), String> {
        self.descriptor.validate().map_err(|e| e.to_string())?;
        self.binding()?;
        let spec = &self.descriptor.spec;
        if self.schema != PLAN_SCHEMA || self.operation_id == [0; 32] ||
           self.operation_id == spec.session_id || self.message.is_empty() ||
           self.message.len() > MAX_MESSAGE ||
           self.selected.len() < spec.threshold as usize || self.selected.len() > spec.participants.len() ||
           self.selected.windows(2).any(|w| w[0] >= w[1]) ||
           self.selected.iter().any(|p| !spec.contains(p)) {
            return Err("invalid signing plan".into());
        }
        if serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > MAX_PLAN_BYTES {
            return Err("signing plan too large for its 64 KiB plan and policy files".into());
        }
        Ok(())
    }
    pub fn binding(&self) -> Result<Binding, String> {
        Binding::new(self.descriptor.proposal_action.clone(), self.descriptor.spec.clone())
            .map_err(|e| e.to_string())
    }
    /// One inbox slot per signer and round for this operation. Derived from
    /// the operation id, so two operations never share a slot.
    pub fn sequence(&self) -> u64 {
        let mut head = [0_u8; 8];
        head.copy_from_slice(&self.operation_id[..8]);
        u64::from_be_bytes(head) % (u64::MAX - 1) + 1
    }
    pub fn intent(&self, active: &ActivatedGroup) -> Result<SigningIntent, String> {
        if active.descriptor() != &self.descriptor {
            return Err("plan names a different group than the activated one".into());
        }
        SigningIntent::new(active, self.operation_id, &self.message, self.selected.clone(),
            SigningProfile::ContextBoundV1).map_err(|e| e.to_string())
    }
    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(commitment("signing-plan-v1", &serde_json::to_vec(self).map_err(|e| e.to_string())?))
    }
}

/// Plain SHA-256 of the message, so an operator can compare with `sha256sum`.
pub fn message_sha256(message: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(message).into()
}

/// What an operator must see before approving. The plan file is public and
/// travels between operators, so the operator supplies their OWN copy of the
/// exact message, obtained independently of the plan; approval is refused
/// unless the plan carries exactly those bytes. The preview is escaped, so
/// message bytes cannot drive the operator's terminal.
pub fn approval_review(plan: &SigningPlan, operator_message: &[u8]) -> Result<String, String> {
    plan.validate()?;
    if plan.message != operator_message {
        return Err("the plan's message differs from your --message-file; refusing to approve".into());
    }
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let preview: String = plan.message.iter().take(PREVIEW_BYTES)
        .flat_map(|b| std::ascii::escape_default(*b)).map(char::from).collect();
    let more = if plan.message.len() > PREVIEW_BYTES { " (truncated)" } else { "" };
    Ok(format!("operation_id={}\nmessage_sha256={} bytes={}\nmessage_preview=\"{preview}\"{more}\n\
        group_verifying_key={}\nselected_signers={}",
        hex(&plan.operation_id), hex(&message_sha256(&plan.message)), plan.message.len(),
        hex(&plan.descriptor.group_verifying_key), plan.selected.len()))
}

/// `Ok(None)` while some member has not attested yet (eventual consistency).
/// An attestation that disagrees with this node's descriptor, or a member
/// attesting two different values, fails closed.
pub fn activated_group(descriptor: &GroupDescriptor, evidence: &[ActivationEvidence])
    -> Result<Option<ActivatedGroup>, String> {
    let mut activation = GroupActivation::new(descriptor.clone()).map_err(|e| e.to_string())?;
    for e in evidence.iter().filter(|e| e.epoch == descriptor.epoch) {
        if e.dkg_transcript_hash != descriptor.dkg_transcript_hash ||
           e.public_key_package_hash != descriptor.public_key_package_hash {
            return Err("activation attestation names a different DKG result".into());
        }
        activation.attest(&e.author, e.descriptor_hash).map_err(|e| e.to_string())?;
    }
    match activation.finalize() {
        Ok(group) => Ok(Some(group)),
        Err(SecurityError::NotReady) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// `Ok(None)` until every selected signer has approved exactly this plan.
/// Approvals by non-selected members grant nothing and are ignored; a
/// selected signer approving anything else for this operation fails closed.
pub fn approved_intent(plan: &SigningPlan, active: &ActivatedGroup, evidence: &[ApprovalEvidence])
    -> Result<Option<ApprovedIntent>, String> {
    let mut approvals = IntentApprovals::new(plan.intent(active)?);
    for e in evidence.iter().filter(|e| e.operation_id == plan.operation_id) {
        if !plan.selected.contains(&e.author) { continue; }
        if e.group_descriptor_hash != active.digest() {
            return Err("approval names a different activated group".into());
        }
        approvals.approve(&e.author, e.intent_hash).map_err(|e| e.to_string())?;
    }
    match approvals.finalize() {
        Ok(approved) => Ok(Some(approved)),
        Err(SecurityError::NotReady) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

pub struct SigningSession {
    binding: Binding,
    local: Vec<u8>,
    plan: SigningPlan,
    active: ActivatedGroup,
    approved: ApprovedIntent,
    public: frost::PublicKeyPackage,
    signer: ControlledSigner,
    commitments: BTreeMap<frost::Identifier, frost::SigningCommitments>,
    package: Option<frost::SigningPackage>,
    collector: Option<AuthenticatedShareCollector>,
    early_shares: BTreeMap<Vec<u8>, frost::SignatureShare>,
    shares_from: BTreeSet<Vec<u8>>,
    artifact: Option<SignedArtifact>,
}

impl SigningSession {
    /// Registers the operation deadline, reserves and burns this signer's
    /// nonce slot, and returns the round-4 commitments for every other
    /// selected signer. A second attempt at the same operation is refused.
    pub fn begin(custody: ShareCustody, local: &[u8], plan: SigningPlan, active: ActivatedGroup,
                 approved: ApprovedIntent, store: &mut RuntimeStore, now_ms: i64, deadline_ms: i64)
        -> Result<(Self, Vec<Envelope>), String> {
        plan.validate()?;
        let binding = plan.binding()?;
        if custody.binding != binding || custody.descriptor != plan.descriptor ||
           !plan.selected.iter().any(|p| p == local) ||
           approved.intent() != &plan.intent(&active)? {
            return Err("share, plan, activation and approval do not describe one request".into());
        }
        let mut signer = ControlledSigner::new(binding.clone(), local, custody.key_package,
            &custody.public_key_package, active.clone()).map_err(|e| e.to_string())?;
        store.start_deadline(&binding.proposal_action, &plan.operation_id, deadline_ms)
            .map_err(|e| e.to_string())?;
        let own = signer.prepare(store, &approved, &plan.message, now_ms).map_err(|e| e.to_string())?;
        let mut commitments = BTreeMap::new();
        commitments.insert(binding.id_of(local).map_err(|e| e.to_string())?, own.clone());
        let session = Self { binding, local: local.to_vec(), plan, active, approved,
            public: custody.public_key_package, signer, commitments, package: None, collector: None,
            early_shares: BTreeMap::new(), shares_from: BTreeSet::new(), artifact: None };
        let outbound = session.to_others(Message::SigningCommitment(own))?;
        Ok((session, outbound))
    }

    pub fn artifact(&self) -> Option<&SignedArtifact> { self.artifact.as_ref() }
    pub fn plan(&self) -> &SigningPlan { &self.plan }

    fn to_others(&self, message: Message) -> Result<Vec<Envelope>, String> {
        let frame = Frame { proposal_action: self.binding.proposal_action.clone(),
            operation_id: self.plan.operation_id, message };
        self.plan.selected.iter().filter(|p| **p != self.local)
            .map(|peer| frame.encode(&self.binding, &self.local, peer, self.plan.sequence())
                .map_err(|e| e.to_string()))
            .collect()
    }

    /// Feed one conductor-authenticated inbox envelope. Envelopes of other
    /// rounds or operations are ignored, and so are senders outside the
    /// approved roster: they carry no authority here, and treating them as
    /// fatal would let any non-selected member veto the operation. Anything
    /// malformed or conflicting from a selected signer is an error and the
    /// caller must abort.
    pub fn ingest(&mut self, env: &Envelope, store: &mut RuntimeStore, now_ms: i64)
        -> Result<Vec<Envelope>, String> {
        if self.artifact.is_some() || !matches!(env.round, 4 | 6) || env.sequence != self.plan.sequence() {
            return Ok(vec![]);
        }
        let sender = env.sender.clone();
        if sender == self.local || !self.plan.selected.contains(&sender) {
            return Ok(vec![]);
        }
        let frame = Frame::decode(&self.binding, env, &self.local, &sender).map_err(|e| e.to_string())?;
        if frame.operation_id != self.plan.operation_id {
            return Err("signing frame for another operation in this slot".into());
        }
        let id = self.binding.id_of(&sender).map_err(|e| e.to_string())?;
        match frame.message {
            Message::SigningCommitment(c) => {
                if let Some(previous) = self.commitments.get(&id) {
                    return if previous == &c { Ok(vec![]) } else { Err("equivocating signing commitment".into()) };
                }
                self.commitments.insert(id, c);
                if self.commitments.len() < self.plan.selected.len() { return Ok(vec![]); }
                let package = frost::signing_package(&self.binding, self.plan.operation_id,
                    &self.plan.message, self.commitments.clone()).map_err(|e| e.to_string())?;
                let share = self.signer.sign(store, &self.approved, &self.plan.message, &package, now_ms)
                    .map_err(|e| e.to_string())?;
                let mut collector = AuthenticatedShareCollector::new(self.binding.clone(), &package)
                    .map_err(|e| e.to_string())?;
                collector.ingest(&self.local, share.clone(), &package).map_err(|e| e.to_string())?;
                self.shares_from.insert(self.local.clone());
                for (peer, early) in std::mem::take(&mut self.early_shares) {
                    collector.ingest(&peer, early, &package).map_err(|e| e.to_string())?;
                    self.shares_from.insert(peer);
                }
                self.package = Some(package);
                self.collector = Some(collector);
                let outbound = self.to_others(Message::SignatureShare(share))?;
                self.try_finish()?;
                Ok(outbound)
            }
            Message::SignatureShare(s) => {
                match (&self.package, self.collector.as_mut()) {
                    (Some(package), Some(collector)) => {
                        collector.ingest(&sender, s, package).map_err(|e| e.to_string())?;
                    }
                    _ => if self.early_shares.insert(sender.clone(), s).is_some() {
                        return Err("duplicate signature share before the signing package".into());
                    },
                }
                if self.package.is_some() { self.shares_from.insert(sender); }
                self.try_finish()?;
                Ok(vec![])
            }
            _ => Err("unexpected message in a signing round".into()),
        }
    }

    fn try_finish(&mut self) -> Result<(), String> {
        if self.shares_from.len() < self.plan.selected.len() { return Ok(()); }
        let (Some(package), Some(collector)) = (self.package.as_ref(), self.collector.take()) else {
            return Ok(());
        };
        let artifact = collector.aggregate(&self.binding, self.plan.operation_id, &self.plan.message,
            package, &self.public, &self.active).map_err(|e| e.to_string())?;
        frost::verify_activated_artifact(&self.binding, &self.plan.message, &artifact, &self.active)
            .map_err(|e| e.to_string())?;
        self.artifact = Some(artifact);
        Ok(())
    }
}

/// The exact bytes the group key signed: an RFC 8032 Ed25519 verifier checks
/// `artifact.signature` over these with `artifact.public_key`.
pub fn signed_message(plan: &SigningPlan) -> Result<Vec<u8>, String> {
    frost::signed_message(&plan.binding()?, plan.operation_id, &plan.message).map_err(|e| e.to_string())
}

/// Only a conductor-authenticated, cell-pinned app transport may implement this.
#[allow(async_fn_in_trait)]
pub trait SigningTransport {
    async fn activations(&mut self) -> Result<Vec<ActivationEvidence>, String>;
    async fn approvals(&mut self) -> Result<Vec<ApprovalEvidence>, String>;
    async fn inbox(&mut self) -> Result<Vec<Envelope>, String>;
    async fn publish(&mut self, envelope: &Envelope) -> Result<(), String>;
    async fn publish_result(&mut self, artifact: &SignedArtifact) -> Result<(), String>;
}

pub struct SigningPoll { pub interval: Duration, pub max_polls: u32 }

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Wait for full activation and every approval, sign once, exchange
/// commitments and shares, aggregate and verify, then publish the result.
/// Every publish is attempted exactly once; any failure aborts the operation.
/// A failure after the deadline was registered is journaled as an abort, so
/// the operation's durable state matches what happened.
pub async fn run_signing<T: SigningTransport>(transport: &mut T, store: &mut RuntimeStore,
    custody: ShareCustody, local: &[u8], plan: SigningPlan, poll: SigningPoll)
    -> Result<SignedArtifact, String> {
    plan.validate()?;
    let mut polls = 0_u32;
    let mut tick = |what: &str| -> Result<(), String> {
        polls += 1;
        if polls > poll.max_polls { return Err(format!("{what} not reached within the poll budget")); }
        Ok(())
    };
    let active = loop {
        tick("group activation")?;
        if let Some(group) = activated_group(&plan.descriptor, &transport.activations().await?)? { break group; }
        tokio::time::sleep(poll.interval).await;
    };
    let approved = loop {
        tick("signing approval")?;
        if let Some(a) = approved_intent(&plan, &active, &transport.approvals().await?)? { break a; }
        tokio::time::sleep(poll.interval).await;
    };
    let budget_ms = (poll.interval.as_millis() as i64).saturating_mul(i64::from(poll.max_polls));
    let start = now_ms();
    let (proposal, operation) = (plan.descriptor.proposal_action.clone(), plan.operation_id);
    let (mut session, outbound) = SigningSession::begin(custody, local, plan, active, approved,
        store, start, start.saturating_add(budget_ms).saturating_add(60_000))?;
    let result = async {
        for env in &outbound { transport.publish(env).await?; }
        let mut seen = BTreeSet::new();
        loop {
            if let Some(artifact) = session.artifact() {
                let artifact = artifact.clone();
                transport.publish_result(&artifact).await?;
                return Ok(artifact);
            }
            tick("signature")?;
            let mut inbox = transport.inbox().await?;
            inbox.sort_by(|a, b| (a.round, &a.sender).cmp(&(b.round, &b.sender)));
            for env in inbox {
                if !seen.insert((env.sender.clone(), env.round, env.sequence)) { continue; }
                for out in session.ingest(&env, store, now_ms())? { transport.publish(&out).await?; }
            }
            if session.artifact().is_none() { tokio::time::sleep(poll.interval).await; }
        }
    }.await;
    result.map_err(|e: String| {
        let reason: String = e.chars().take(200).collect();
        match store.record_abort(&proposal, &operation, &reason) {
            Ok(()) => e,
            Err(journal) => format!("{e}; and the abort could not be journaled: {journal}"),
        }
    })
}
