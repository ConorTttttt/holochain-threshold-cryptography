//! Explicit probe-only signer profile. Existing FROST policy is not reused.
//! Separate capability provisioning is an operator trust boundary: Holochain
//! grants themselves do NOT cryptographically restrict one session/protocol.
use crate::signed_call_policy::{
    validate_signed_call, validate_signed_envelope, validate_signed_key_registration, MpcCall,
};
use crate::{
    capability_exchange::CeremonyRecord,
    connection_policy::ConductorPin,
    socket_signer::{SignerBinding, SignerRequest},
    transport_probe::{ProbePlan, PROTOCOL},
};
use holochain_conductor_api::ZomeCallParamsSigned;
use holochain_keystore::{AgentPubKeyExt, MetaLairClient};
use holochain_zome_types::prelude::*;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeCapability {
    pub purpose: String,
    pub proposal: Vec<u8>,
    pub grant_action: Vec<u8>,
    pub grantor: Vec<u8>,
    pub grantee: Vec<u8>,
    pub cap_secret: CapSecret,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeSignerPolicyFile {
    pub profile: String,
    pub binding: SignerBinding,
    pub record: CeremonyRecord,
    pub own_public_key: [u8; 32],
    /// None is registration/read-only mode. Sending needs reviewed final pins.
    pub send_plan: Option<ProbePlan>,
    /// Dedicated probe credential; never import a FROST policy as a fallback.
    pub capability: Option<ProbeCapability>,
}
pub struct ProbeSignerPolicy {
    file: ProbeSignerPolicyFile,
}

pub fn validate_record(r: &CeremonyRecord) -> Result<(), String> {
    r.validate()?;
    if r.spec.protocol_id != PROTOCOL
        || r.spec.protocol_version != 1
        || r.spec.max_round != 1
        || r.spec.participants.len() != 2
        || r.spec.threshold != 2
    {
        return Err("expected dedicated two-member transport-probe v1 proposal".into());
    }
    Ok(())
}
impl ProbeSignerPolicy {
    pub fn new(file: ProbeSignerPolicyFile) -> Result<Self, String> {
        validate_record(&file.record)?;
        let b = &file.binding;
        let ctx = crate::ipc::ChannelContext {
            worker_agent: b.agent.clone(),
            proposal_action: b.proposal_action.clone(),
            session_id: b.session_id,
            channel_id: b.channel_id,
        };
        ctx.validate()?;
        if file.profile != "mpc-transport-probe-v1"
            || b.role != "mpc"
            || b.installed_app_id != file.record.installed_app_id
            || b.dna_hash != file.record.dna_hash
            || b.proposal_action != file.record.proposal_action
            || b.session_id != file.record.spec.session_id
            || !file.record.spec.contains(&b.agent)
            || file.own_public_key == [0; 32]
        {
            return Err("probe signer profile/identity refused".into());
        }
        if let Some(plan) = &file.send_plan {
            plan.validate()?;
            if plan.record != file.record || plan.key(&b.agent)? != file.own_public_key {
                return Err("probe signer plan/key mismatch".into());
            }
        }
        if let Some(cap) = &file.capability {
            let plan = file
                .send_plan
                .as_ref()
                .ok_or("probe capability requires complete approved plan")?;
            ActionHash::try_from_raw_39(cap.grant_action.clone())
                .map_err(|_| "invalid approved probe grant action")?;
            if cap.cap_secret.as_ref().iter().all(|b| *b == 0)
                || cap.purpose != "mpc-transport-probe-v1"
                || cap.proposal != b.proposal_action
                || cap.grantee != b.agent
                || cap.grantee != plan.sender
                || cap.grantor != plan.recipient
            {
                return Err("probe capability purpose/provenance refused".into());
            }
        }
        Ok(Self { file })
    }
    pub fn pin(&self) -> ConductorPin {
        let b = &self.file.binding;
        ConductorPin {
            app_id: b.installed_app_id.clone(),
            role: b.role.clone(),
            dna_hash: b.dna_hash.clone(),
            node: crate::ipc::ChannelContext {
                worker_agent: b.agent.clone(),
                proposal_action: b.proposal_action.clone(),
                session_id: b.session_id,
                channel_id: b.channel_id,
            },
        }
    }
    pub fn authorize(&self, req: &SignerRequest) -> Result<(MpcCall, ZomeCallParams), String> {
        if req.version != 1 || req.binding != self.file.binding {
            return Err("probe signer binding refused".into());
        }
        let proposal = ActionHash::try_from_raw_39(self.file.binding.proposal_action.clone())
            .map_err(|_| "invalid proposal")?;
        #[derive(Serialize, Debug)]
        struct Registration {
            proposal: ActionHash,
            public_key: [u8; 32],
        }
        #[derive(Serialize)]
        struct Send {
            proposal: ActionHash,
            recipient: AgentPubKey,
            round: u32,
            sequence: u64,
            payload: Vec<u8>,
            recipient_cap_secret: CapSecret,
        }
        impl std::fmt::Debug for Send {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("ProbeSend{redacted}")
            }
        }
        let (op, payload) = match req.operation.as_str() {
            "get_session_status" | "get_inbox" | "get_encryption_key_bindings" => {
                if req.envelope.is_some() || req.public_key.is_some() {
                    return Err("probe read contains write data".into());
                }
                let op = match req.operation.as_str() {
                    "get_session_status" => MpcCall::GetProbeSessionStatus,
                    "get_inbox" => MpcCall::GetInbox,
                    _ => MpcCall::GetEncryptionKeyBindings,
                };
                (op, ExternIO::encode(proposal).map_err(|_| "read encoding")?)
            }
            "register_encryption_key" => {
                if req.envelope.is_some() || req.public_key != Some(self.file.own_public_key) {
                    return Err("probe signer only registers its exact retained public key".into());
                }
                (
                    MpcCall::RegisterEncryptionKey,
                    ExternIO::encode(Registration {
                        proposal,
                        public_key: self.file.own_public_key,
                    })
                    .map_err(|_| "registration encoding")?,
                )
            }
            "send_protocol_message" => {
                if req.public_key.is_some() {
                    return Err("probe send contains registration".into());
                }
                let plan = self
                    .file
                    .send_plan
                    .as_ref()
                    .ok_or("probe sending not explicitly enabled")?;
                let cap = self
                    .file
                    .capability
                    .as_ref()
                    .ok_or("no dedicated probe capability")?;
                let env = req.envelope.as_ref().ok_or("missing encrypted probe")?;
                plan.validate_envelope(env)?;
                if env.sender != self.file.binding.agent {
                    return Err("probe signer is not the sender".into());
                }
                (
                    MpcCall::SendProtocolMessage,
                    ExternIO::encode(Send {
                        proposal,
                        recipient: AgentPubKey::try_from_raw_39(plan.recipient.clone())
                            .map_err(|_| "invalid recipient")?,
                        round: 1,
                        sequence: 1,
                        payload: env.payload.clone(),
                        recipient_cap_secret: cap.cap_secret.clone(),
                    })
                    .map_err(|_| "send encoding")?,
                )
            }
            _ => return Err("probe signer refused unlisted function".into()),
        };
        let agent = AgentPubKey::try_from_raw_39(self.file.binding.agent.clone())
            .map_err(|_| "invalid agent")?;
        let dna = DnaHash::try_from_raw_39(self.file.binding.dna_hash.clone())
            .map_err(|_| "invalid DNA")?;
        let mut nonce = vec![0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Ok((
            op,
            ZomeCallParams {
                provenance: agent.clone(),
                cell_id: CellId::new(dna, agent),
                zome_name: ZomeName::from("mpc"),
                fn_name: FunctionName::from(op.name()),
                cap_secret: None,
                payload,
                nonce: holochain_nonce::Nonce256Bits::try_from(nonce)
                    .map_err(|_| "nonce generation")?,
                expires_at: Timestamp::now()
                    .checked_add(&Duration::from_secs(30))
                    .ok_or("expiry overflow")?,
            },
        ))
    }
    pub async fn sign(
        &self,
        req: &SignerRequest,
        lair: &MetaLairClient,
    ) -> Result<ZomeCallParamsSigned, String> {
        let (op, params) = self.authorize(req)?;
        let (bytes, hash) = params
            .serialize_and_hash()
            .map_err(|_| "probe call encoding")?;
        let signature = params
            .provenance
            .sign_raw(lair, Arc::<[u8]>::from(hash))
            .await
            .map_err(|_| "Lair refused probe signing")?;
        let signed = ZomeCallParamsSigned::new(bytes, signature);
        let pin = self.pin();
        validate_signed_call(&pin, op, &signed)?;
        if let Some(env) = &req.envelope {
            validate_signed_envelope(&pin, env, &signed)?;
        }
        if let Some(key) = req.public_key {
            validate_signed_key_registration(&pin, key, &signed)?;
        }
        Ok(signed)
    }
}

/// Bounded private file loader shared by public probe plans and secret policies.
/// Errors never include contents or serde diagnostics.
pub fn read_private_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    use std::{
        fs::{self, OpenOptions},
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    if !path.is_absolute() {
        return Err("probe input path must be absolute".into());
    }
    let before = fs::symlink_metadata(path).map_err(|_| "probe input unavailable")?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.uid() != unsafe { libc::geteuid() }
        || before.permissions().mode() & 0o777 != 0o600
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > 64 * 1024
    {
        return Err("probe input must be owned 0600 regular single-link file, <=64 KiB".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "cannot open probe input")?;
    let after = file.metadata().map_err(|_| "cannot stat probe input")?;
    if before.ino() != after.ino() || before.dev() != after.dev() {
        return Err("probe input changed while opening".into());
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "probe input read failed")?;
    if bytes.len() as u64 != before.len() {
        return Err("probe input size changed".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "probe input schema invalid".into())
}
