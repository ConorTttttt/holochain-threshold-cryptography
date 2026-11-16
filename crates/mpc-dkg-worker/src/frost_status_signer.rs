//! Separate, opt-in FROST ceremony STATUS signer. This profile cannot sign
//! DKG writes, signing rounds, key registrations or transport-probe traffic.
//! It signs one get_session_status call for an operator-approved, exact FROST
//! proposal and pin. The SDK independently compares the returned full spec.
use crate::connection_policy::ConductorPin;
use crate::ipc::ChannelContext;
use crate::signed_call_policy::{validate_signed_call, MpcCall};
use crate::socket_signer::{SignerBinding, SignerRequest};
use holochain_conductor_api::ZomeCallParamsSigned;
use holochain_keystore::{AgentPubKeyExt, MetaLairClient};
use holochain_mpc_core::SessionSpec;
use holochain_mpc_frost_ed25519::Binding;
use holochain_zome_types::prelude::*;
use rand::RngCore;
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

/// Distinct IPC operation name; the probe signer never accepts this intent.
pub const STATUS_INTENT: &str = "frost_ceremony_status_v1";
pub const PROFILE: &str = "mpc-frost-status-read-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrostStatusPolicyFile {
    pub profile: String,
    pub binding: SignerBinding,
    /// The complete, independently approved SessionProposal spec.
    pub spec: SessionSpec,
}

pub struct FrostStatusSignerPolicy {
    binding: SignerBinding,
    spec: SessionSpec,
}

impl FrostStatusSignerPolicy {
    pub fn new(file: FrostStatusPolicyFile) -> Result<Self, String> {
        let b = &file.binding;
        let context = ChannelContext {
            worker_agent: b.agent.clone(),
            proposal_action: b.proposal_action.clone(),
            session_id: b.session_id,
            channel_id: b.channel_id,
        };
        context.validate()?;
        if file.profile != PROFILE || b.role != "mpc" ||
           b.installed_app_id.is_empty() || b.installed_app_id.len() > 128 ||
           AgentPubKey::try_from_raw_39(b.agent.clone()).is_err() ||
           DnaHash::try_from_raw_39(b.dna_hash.clone()).is_err() ||
           ActionHash::try_from_raw_39(b.proposal_action.clone()).is_err() {
            return Err("FROST status signer profile or cell refused".into());
        }
        Binding::new(b.proposal_action.clone(), file.spec.clone())
            .map_err(|_| "FROST status signer needs valid approved FROST binding")?;
        if file.spec.session_id != b.session_id || !file.spec.contains(&b.agent) {
            return Err("FROST status signer session/agent differs from approved spec".into());
        }
        Ok(Self { binding: file.binding, spec: file.spec })
    }

    pub fn approved_spec(&self) -> &SessionSpec { &self.spec }

    pub fn pin(&self) -> ConductorPin {
        let b = &self.binding;
        ConductorPin {
            app_id: b.installed_app_id.clone(),
            role: b.role.clone(),
            dna_hash: b.dna_hash.clone(),
            node: ChannelContext {
                worker_agent: b.agent.clone(),
                proposal_action: b.proposal_action.clone(),
                session_id: b.session_id,
                channel_id: b.channel_id,
            },
        }
    }

    pub fn authorize(&self, request: &SignerRequest)
        -> Result<(MpcCall, ZomeCallParams), String>
    {
        if request.version != 1 || request.binding != self.binding ||
           request.operation != STATUS_INTENT ||
           request.envelope.is_some() || request.public_key.is_some() ||
           request.result.is_some() {
            return Err("FROST status signer refused unlisted or unpinned intent".into());
        }
        let agent = AgentPubKey::try_from_raw_39(self.binding.agent.clone())
            .map_err(|_| "invalid approved agent")?;
        let dna = DnaHash::try_from_raw_39(self.binding.dna_hash.clone())
            .map_err(|_| "invalid approved DNA")?;
        let proposal = ActionHash::try_from_raw_39(self.binding.proposal_action.clone())
            .map_err(|_| "invalid approved proposal")?;
        // Existing coordinator entry point. The capability-free signed payload
        // contains ONLY the exact pinned proposal ActionHash.
        let op = MpcCall::GetProbeSessionStatus;
        let payload = ExternIO::encode(proposal).map_err(|_| "cannot encode status read")?;
        let mut nonce = vec![0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let params = ZomeCallParams {
            provenance: agent.clone(),
            cell_id: CellId::new(dna, agent),
            zome_name: ZomeName::from("mpc"),
            fn_name: FunctionName::from(op.name()),
            cap_secret: None,
            payload,
            nonce: holochain_nonce::Nonce256Bits::try_from(nonce)
                .map_err(|_| "nonce generation failed")?,
            expires_at: Timestamp::now().checked_add(&Duration::from_secs(30))
                .ok_or("expiry overflow")?,
        };
        Ok((op, params))
    }

    pub async fn sign(&self, req: &SignerRequest, lair: &MetaLairClient)
        -> Result<ZomeCallParamsSigned, String>
    {
        let (op, params) = self.authorize(req)?;
        let agent = params.provenance.clone();
        let (bytes, hash) = params.serialize_and_hash()
            .map_err(|_| "status call serialization failed")?;
        let signature = agent.sign_raw(lair, Arc::<[u8]>::from(hash)).await
            .map_err(|_| "Lair refused FROST status signing")?;
        let signed = ZomeCallParamsSigned::new(bytes, signature);
        validate_signed_call(&self.pin(), op, &signed)?;
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn participant(n: u8) -> Vec<u8> {
        AgentPubKey::from_raw_32(vec![n;32]).get_raw_39().to_vec()
    }
    fn policy_file() -> FrostStatusPolicyFile {
        let agent = participant(1);
        let mut members = vec![agent.clone(), participant(2), participant(3)];
        members.sort();
        let spec = SessionSpec {
            session_id: [5;32], application_id: "org.example.app".into(),
            protocol_id: "frost-ed25519".into(), protocol_version: 1,
            context_hash: [9;32], participants: members,
            threshold: 2, max_round: 6,
        };
        FrostStatusPolicyFile {
            profile: PROFILE.into(),
            binding: SignerBinding {
                installed_app_id: "local-frost-cell".into(), role: "mpc".into(),
                dna_hash: DnaHash::from_raw_32(vec![4;32]).get_raw_39().to_vec(),
                agent, proposal_action: ActionHash::from_raw_32(vec![7;32]).get_raw_39().to_vec(),
                session_id: [5;32], channel_id: [6;32],
            },
            spec,
        }
    }
    fn request(policy: &FrostStatusSignerPolicy, operation: &str) -> SignerRequest {
        SignerRequest {
            version: 1, operation: operation.into(),
            binding: policy.binding.clone(), envelope: None,
            public_key: None, result: None,
        }
    }

    #[test]
    fn status_only_and_fresh_nonce_for_exact_proposal() {
        let p = FrostStatusSignerPolicy::new(policy_file()).unwrap();
        let (op, a) = p.authorize(&request(&p, STATUS_INTENT)).unwrap();
        assert_eq!(op.name(), "get_session_status");
        validate_signed_call(&p.pin(), op, &{
            let (bytes,_) = a.serialize_and_hash().unwrap();
            ZomeCallParamsSigned::new(bytes, Signature([0;64]))
        }).unwrap();
        let (_, b) = p.authorize(&request(&p, STATUS_INTENT)).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert!(a.cap_secret.is_none());
        for name in ["get_session_status", "get_inbox", "get_inbox_slots",
                     "send_protocol_message", "accept_session", "propose_session",
                     "register_encryption_key", "publish_result_commitment",
                     "frost_ceremony_status_v2", ""] {
            assert!(p.authorize(&request(&p, name)).is_err(), "{name}");
        }
    }
    #[test]
    fn wrong_app_cell_proposal_agent_and_extra_fields_refused() {
        let p = FrostStatusSignerPolicy::new(policy_file()).unwrap();
        let mut req = request(&p, STATUS_INTENT);
        req.binding.installed_app_id = "other-app".into();
        assert!(p.authorize(&req).is_err());
        req = request(&p, STATUS_INTENT); req.binding.dna_hash[5] ^= 1;
        assert!(p.authorize(&req).is_err());
        req = request(&p, STATUS_INTENT); req.binding.agent = participant(2);
        assert!(p.authorize(&req).is_err());
        req = request(&p, STATUS_INTENT); req.binding.proposal_action[5] ^= 1;
        assert!(p.authorize(&req).is_err());
        req = request(&p, STATUS_INTENT); req.public_key = Some([5;32]);
        assert!(p.authorize(&req).is_err());
        req = request(&p, STATUS_INTENT); req.result = Some(crate::socket_signer::ResultRequest {
            result_bytes: vec![], verification_artifact: vec![],
        });
        assert!(p.authorize(&req).is_err());
        req = request(&p, STATUS_INTENT); req.version = 0;
        assert!(p.authorize(&req).is_err());
    }
    #[test]
    fn policy_needs_exact_frost_protocol_context_and_membership() {
        let mut f=policy_file(); f.profile="mpc-transport-probe-v1".into();
        assert!(FrostStatusSignerPolicy::new(f).is_err());
        let mut f=policy_file(); f.spec.protocol_id="mpc-transport-probe".into(); f.spec.max_round=1;
        assert!(FrostStatusSignerPolicy::new(f).is_err());
        let mut f=policy_file(); f.spec.session_id=[1;32];
        assert!(FrostStatusSignerPolicy::new(f).is_err());
        let mut f=policy_file(); f.spec.participants.retain(|a| a!=&f.binding.agent);
        assert!(FrostStatusSignerPolicy::new(f).is_err());
        let mut f=policy_file(); f.spec.context_hash=[0;32];
        assert!(FrostStatusSignerPolicy::new(f).is_err());
    }
}
