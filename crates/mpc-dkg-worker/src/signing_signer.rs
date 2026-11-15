//! Phase 8 opt-in signing signer profile, selected only by
//! `mpc-lair-signer --signing-profile`. It pins ONE operator-approved
//! `SigningPlan` and signs only what the `mpc-sign` service needs for it:
//! the three ceremony reads, round-4/6 frames of that operation to the other
//! selected signers, and publication of a result that verifies under the
//! group key. It can never approve, activate, register keys or provision.
//! The DKG-time FROST policy and the probe policy are not accepted here.
use crate::lair_signer::RecipientCapability;
use crate::signed_call_policy::{validate_signed_call, validate_signed_envelope, validate_signed_result, MpcCall};
use crate::signing::SigningPlan;
use crate::{connection_policy::ConductorPin, socket_signer::{SignerBinding, SignerRequest}};
use holochain_conductor_api::ZomeCallParamsSigned;
use holochain_keystore::{AgentPubKeyExt, MetaLairClient};
use holochain_mpc_core::Envelope;
use holochain_mpc_frost_ed25519::{verify_artifact, Binding, Frame, SignedArtifact};
use holochain_zome_types::prelude::*;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::{sync::Arc, time::Duration};

pub const PROFILE: &str = "mpc-frost-signing-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningSignerPolicyFile {
    pub profile: String,
    pub binding: SignerBinding,
    pub plan: SigningPlan,
    /// One capability for each OTHER selected signer, from 5C-B provisioning.
    pub recipients: Vec<RecipientCapability>,
}
pub struct SigningSignerPolicy {
    binding: SignerBinding,
    plan: SigningPlan,
    frost: Binding,
    recipients: BTreeMap<Vec<u8>, CapSecret>,
}

#[derive(Serialize)]
struct Send { proposal: ActionHash, recipient: AgentPubKey, round: u32, sequence: u64,
              payload: Vec<u8>, recipient_cap_secret: CapSecret }
impl std::fmt::Debug for Send {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("SigningSend{redacted}") }
}
#[derive(Serialize, Debug)]
struct PublishResult { proposal: ActionHash, result_bytes: Vec<u8>, verification_artifact: Vec<u8> }

impl SigningSignerPolicy {
    pub fn new(file: SigningSignerPolicyFile) -> Result<Self, String> {
        file.plan.validate()?;
        let frost = file.plan.binding()?;
        let b = &file.binding;
        crate::ipc::ChannelContext { worker_agent: b.agent.clone(), proposal_action: b.proposal_action.clone(),
            session_id: b.session_id, channel_id: b.channel_id }.validate()?;
        if file.profile != PROFILE || b.role != "mpc" || b.installed_app_id.is_empty() ||
           b.installed_app_id.len() > 128 || DnaHash::try_from_raw_39(b.dna_hash.clone()).is_err() ||
           b.proposal_action != frost.proposal_action || b.session_id != frost.spec.session_id ||
           !file.plan.selected.contains(&b.agent) {
            return Err("signing signer profile/identity refused".into());
        }
        let mut recipients = BTreeMap::new();
        for r in file.recipients {
            if r.agent == b.agent || !file.plan.selected.contains(&r.agent) ||
               r.cap_secret.as_ref().iter().all(|x| *x == 0) ||
               recipients.insert(r.agent, r.cap_secret).is_some() {
                return Err("signing capability recipient refused".into());
            }
        }
        if recipients.len() != file.plan.selected.len() - 1 {
            return Err("signing policy needs exactly one capability per other selected signer".into());
        }
        Ok(Self { binding: file.binding, plan: file.plan, frost, recipients })
    }

    pub fn pin(&self) -> ConductorPin {
        let b = &self.binding;
        ConductorPin { app_id: b.installed_app_id.clone(), role: b.role.clone(), dna_hash: b.dna_hash.clone(),
            node: crate::ipc::ChannelContext { worker_agent: b.agent.clone(),
                proposal_action: b.proposal_action.clone(), session_id: b.session_id, channel_id: b.channel_id } }
    }

    fn check_frame(&self, env: &Envelope) -> Result<AgentPubKey, String> {
        let recipient = env.recipient.clone().ok_or("signing frame has no recipient")?;
        if !matches!(env.round, 4 | 6) || env.sequence != self.plan.sequence() ||
           recipient == self.binding.agent || !self.recipients.contains_key(&recipient) ||
           env.payload.len() > 64 * 1024 {
            return Err("signing frame outside the approved operation".into());
        }
        let expected = Envelope::new(&self.frost.spec, self.binding.agent.clone(), Some(recipient.clone()),
            env.round, env.sequence, env.payload.clone()).map_err(|_| "signing frame violates the pinned spec")?;
        let frame: Frame = serde_json::from_slice(&env.payload).map_err(|_| "signing frame is malformed")?;
        if &expected != env || frame.proposal_action != self.frost.proposal_action ||
           frame.operation_id != self.plan.operation_id || frame.message.round() != env.round {
            return Err("signing frame does not belong to the approved operation".into());
        }
        AgentPubKey::try_from_raw_39(recipient).map_err(|_| "invalid recipient key".into())
    }

    pub fn authorize(&self, req: &SignerRequest) -> Result<(MpcCall, ZomeCallParams), String> {
        if req.version != 1 || req.binding != self.binding {
            return Err("request not bound to this signing ceremony".into());
        }
        let proposal = ActionHash::try_from_raw_39(self.binding.proposal_action.clone())
            .map_err(|_| "invalid pinned proposal")?;
        let (op, payload) = match req.operation.as_str() {
            "get_inbox_slots" | "get_group_activation_attestations" | "get_signing_approvals" => {
                if req.envelope.is_some() || req.public_key.is_some() || req.result.is_some() {
                    return Err("signing read carries write data".into());
                }
                let op = match req.operation.as_str() {
                    "get_inbox_slots" => MpcCall::GetInboxSlots,
                    "get_group_activation_attestations" => MpcCall::GetGroupActivationAttestations,
                    _ => MpcCall::GetSigningApprovals,
                };
                (op, ExternIO::encode(proposal).map_err(|_| "read encoding")?)
            }
            "send_protocol_message" => {
                if req.public_key.is_some() || req.result.is_some() {
                    return Err("signing send carries other write data".into());
                }
                let env = req.envelope.as_ref().ok_or("missing signing frame")?;
                let recipient = self.check_frame(env)?;
                let cap = self.recipients.get(&env.recipient.clone().unwrap_or_default())
                    .ok_or("no capability for recipient")?;
                (MpcCall::SendProtocolMessage, ExternIO::encode(Send { proposal, recipient,
                    round: env.round, sequence: env.sequence, payload: env.payload.clone(),
                    recipient_cap_secret: cap.clone() }).map_err(|_| "send encoding")?)
            }
            "publish_result_commitment" => {
                if req.envelope.is_some() || req.public_key.is_some() {
                    return Err("result publication carries other write data".into());
                }
                let result = req.result.as_ref().ok_or("missing signing result")?;
                let artifact: SignedArtifact = serde_json::from_slice(&result.verification_artifact)
                    .map_err(|_| "verification artifact is malformed")?;
                if result.verification_artifact.len() > 16 * 1024 || artifact.signature != result.result_bytes ||
                   artifact.operation_id != self.plan.operation_id {
                    return Err("result does not belong to the approved operation".into());
                }
                verify_artifact(&self.frost, &self.plan.message, &artifact, &self.plan.descriptor.group_verifying_key)
                    .map_err(|_| "result is not a valid group signature for the approved operation")?;
                (MpcCall::PublishResultCommitment, ExternIO::encode(PublishResult { proposal,
                    result_bytes: result.result_bytes.clone(),
                    verification_artifact: result.verification_artifact.clone() })
                    .map_err(|_| "result encoding")?)
            }
            _ => return Err("signing signer refused unlisted function".into()),
        };
        let agent = AgentPubKey::try_from_raw_39(self.binding.agent.clone()).map_err(|_| "invalid signer agent")?;
        let dna = DnaHash::try_from_raw_39(self.binding.dna_hash.clone()).map_err(|_| "invalid signer DNA")?;
        let mut nonce = vec![0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Ok((op, ZomeCallParams { provenance: agent.clone(), cell_id: CellId::new(dna, agent),
            zome_name: ZomeName::from("mpc"), fn_name: FunctionName::from(op.name()), cap_secret: None,
            payload, nonce: holochain_nonce::Nonce256Bits::try_from(nonce).map_err(|_| "nonce generation failed")?,
            expires_at: Timestamp::now().checked_add(&Duration::from_secs(30)).ok_or("expiry overflow")? }))
    }

    pub async fn sign(&self, req: &SignerRequest, lair: &MetaLairClient) -> Result<ZomeCallParamsSigned, String> {
        let (op, params) = self.authorize(req)?;
        let agent = params.provenance.clone();
        let (bytes, hash) = params.serialize_and_hash().map_err(|_| "call serialization failed")?;
        let signature = agent.sign_raw(lair, Arc::<[u8]>::from(hash)).await
            .map_err(|_| "Lair refused signing")?;
        let signed = ZomeCallParamsSigned::new(bytes, signature);
        let pin = self.pin();
        validate_signed_call(&pin, op, &signed)?;
        if let Some(env) = req.envelope.as_ref() { validate_signed_envelope(&pin, env, &signed)?; }
        if let Some(r) = req.result.as_ref() {
            validate_signed_result(&pin, &r.result_bytes, &r.verification_artifact, &signed)?;
        }
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::PLAN_SCHEMA;
    use crate::socket_signer::ResultRequest;
    use holochain_mpc_core::SessionSpec;
    use holochain_mpc_frost_ed25519::{Message, SignatureShare};
    use holochain_mpc_security::activation::GroupDescriptor;

    fn agent(n: u8) -> Vec<u8> { AgentPubKey::from_raw_32(vec![n; 32]).get_raw_39().to_vec() }
    fn plan() -> SigningPlan {
        let mut participants = vec![agent(1), agent(2), agent(3)];
        participants.sort();
        let spec = SessionSpec { session_id: [5; 32], application_id: "org.test.sign".into(),
            protocol_id: "frost-ed25519".into(), protocol_version: 1, context_hash: [6; 32],
            participants: participants.clone(), threshold: 2, max_round: 6 };
        let mut selected = vec![agent(1), agent(2)];
        selected.sort();
        SigningPlan { schema: PLAN_SCHEMA, operation_id: [7; 32], message: b"pay 1".to_vec(), selected,
            descriptor: GroupDescriptor { proposal_action: ActionHash::from_raw_32(vec![4; 32]).get_raw_39().to_vec(),
                spec, epoch: 0, dkg_transcript_hash: [8; 32], public_key_package_hash: [9; 32],
                group_verifying_key: vec![10; 32],
                encryption_key_binding_actions: (11..14).map(|n| ActionHash::from_raw_32(vec![n; 32]).get_raw_39().to_vec()).collect() } }
    }
    fn binding(p: &SigningPlan) -> SignerBinding {
        SignerBinding { installed_app_id: "app".into(), role: "mpc".into(),
            dna_hash: DnaHash::from_raw_32(vec![3; 32]).get_raw_39().to_vec(), agent: agent(1),
            proposal_action: p.descriptor.proposal_action.clone(), session_id: p.descriptor.spec.session_id,
            channel_id: [9; 32] }
    }
    fn file(p: SigningPlan) -> SigningSignerPolicyFile {
        SigningSignerPolicyFile { profile: PROFILE.into(), binding: binding(&p), plan: p,
            recipients: vec![RecipientCapability { agent: agent(2), cap_secret: CapSecret::from([12; 64]) }] }
    }
    fn req(p: &SigningPlan, op: &str, envelope: Option<Envelope>) -> SignerRequest {
        SignerRequest { version: 1, operation: op.into(), binding: binding(p), envelope, public_key: None, result: None }
    }
    fn share_frame(p: &SigningPlan, to: Vec<u8>, round: u32, op: [u8; 32], sequence: u64) -> Envelope {
        let mut scalar = [0_u8; 32];
        scalar[0] = 1;
        let frame = Frame { proposal_action: p.descriptor.proposal_action.clone(), operation_id: op,
            message: Message::SignatureShare(SignatureShare::deserialize(&scalar).unwrap()) };
        Envelope::new(&p.descriptor.spec, agent(1), Some(to), round, sequence, serde_json::to_vec(&frame).unwrap()).unwrap()
    }

    #[test]
    fn admits_reads_and_only_this_operations_frames() {
        let p = plan();
        let policy = SigningSignerPolicy::new(file(p.clone())).unwrap();
        for op in ["get_inbox_slots", "get_group_activation_attestations", "get_signing_approvals"] {
            assert!(policy.authorize(&req(&p, op, None)).is_ok(), "{op}");
        }
        for op in ["publish_signing_approval", "publish_group_activation_attestation", "register_encryption_key",
                   "accept_session", "prepare_inbox_grant", "get_encryption_key_bindings"] {
            assert!(policy.authorize(&req(&p, op, None)).is_err(), "{op} must be refused");
        }
        let good = share_frame(&p, agent(2), 6, p.operation_id, p.sequence());
        assert!(policy.authorize(&req(&p, "send_protocol_message", Some(good))).is_ok());
        for bad in [share_frame(&p, agent(2), 6, [8; 32], p.sequence()),
                    share_frame(&p, agent(3), 6, p.operation_id, p.sequence()),
                    share_frame(&p, agent(2), 6, p.operation_id, p.sequence() ^ 1)] {
            assert!(policy.authorize(&req(&p, "send_protocol_message", Some(bad))).is_err());
        }
        let mut relabelled = share_frame(&p, agent(2), 6, p.operation_id, p.sequence());
        relabelled.round = 3;
        assert!(policy.authorize(&req(&p, "send_protocol_message", Some(relabelled))).is_err());
        let mut forged = req(&p, "publish_result_commitment", None);
        forged.result = Some(ResultRequest { result_bytes: vec![1; 64], verification_artifact: b"{}".to_vec() });
        assert!(policy.authorize(&forged).is_err(), "only a verifying group signature may be published");
    }

    #[test]
    fn refuses_other_profiles_rosters_and_capabilities() {
        let mut f = file(plan());
        f.profile = "frost-ed25519".into();
        assert!(SigningSignerPolicy::new(f).is_err());
        let mut f = file(plan());
        f.binding.agent = agent(3); // not a selected signer
        assert!(SigningSignerPolicy::new(f).is_err());
        let mut f = file(plan());
        f.recipients.clear();
        assert!(SigningSignerPolicy::new(f).is_err(), "needs one capability per other signer");
        let mut f = file(plan());
        f.recipients.push(RecipientCapability { agent: agent(3), cap_secret: CapSecret::from([13; 64]) });
        assert!(SigningSignerPolicy::new(f).is_err(), "no capability for a non-selected member");
    }
}
