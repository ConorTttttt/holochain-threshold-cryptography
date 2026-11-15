//! Phase 5A: signer-side policy. The relay cannot choose a function, cell,
//! capability grant or agent key outside this operator-provisioned ceremony.
//! This module is compiled only when the `lair-signer` feature is enabled.
use crate::signed_call_policy::{validate_signed_call, validate_signed_envelope, validate_signed_key_registration, MpcCall};
use crate::socket_signer::{SignerBinding, SignerRequest};
use crate::connection_policy::ConductorPin;
use crate::ipc::ChannelContext;
use holochain_conductor_api::ZomeCallParamsSigned;
use holochain_mpc_core::{Envelope, SessionSpec};
use holochain_zome_types::prelude::{ActionHash, AgentPubKey, DnaHash, CellId, CapSecret, ExternIO, FunctionName, Timestamp, ZomeCallParams, ZomeName};
use holochain_nonce::Nonce256Bits;
use holochain_keystore::{AgentPubKeyExt, MetaLairClient};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const MAX_POLICY_BYTES: usize = 64 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientCapability {
    pub agent: Vec<u8>,
    pub cap_secret: CapSecret,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerPolicyFile {
    pub binding: SignerBinding,
    pub recipients: Vec<RecipientCapability>,
    /// The full FROST proposal spec, copied from the conductor-verified
    /// ceremony record. `SendMessage` signs neither protocol nor session, so
    /// the signer must know them independently of the relay's envelope label.
    /// Policies written before this field stay read-only: without it, any
    /// recipient capability or key registration is refused.
    #[serde(default)]
    pub spec: Option<SessionSpec>,
}

/// The secrets are not printed or returned to the relay; they are injected
/// only into the coordinator's local `send_protocol_message` arguments.
pub struct SignerPolicy {
    binding: SignerBinding,
    recipients: BTreeMap<Vec<u8>, CapSecret>,
    spec: Option<SessionSpec>,
}

pub fn read_private_policy(path: &Path) -> Result<SignerPolicy,String> {
    if !path.is_absolute() { return Err("signer policy path must be absolute".into()); }
    let before=fs::symlink_metadata(path).map_err(|_|"signer policy unavailable")?;
    if !before.is_file() || before.file_type().is_symlink() || before.nlink()!=1 ||
        before.uid()!=unsafe{libc::geteuid()} || before.permissions().mode() & 0o777 != 0o600 ||
        before.len()==0 || before.len() > MAX_POLICY_BYTES as u64 {
        return Err("signer policy must be an owned 0600 regular file".into());
    }
    let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW)
        .open(path).map_err(|_|"cannot open signer policy")?;
    let after=file.metadata().map_err(|_|"cannot stat signer policy")?;
    if before.ino()!=after.ino() || before.dev()!=after.dev() || before.len()!=after.len() {
        return Err("signer policy changed while opening".into());
    }
    let mut content=Zeroizing::new(Vec::new());
    file.take(MAX_POLICY_BYTES as u64+1).read_to_end(&mut content)
        .map_err(|_|"cannot read signer policy")?;
    if content.len()!=before.len() as usize { return Err("signer policy changed while reading".into()); }
    let config:SignerPolicyFile=serde_json::from_slice(&content)
        .map_err(|_|"invalid signer policy JSON")?;
    SignerPolicy::new(config)
}

impl SignerPolicy {
    pub fn new(file: SignerPolicyFile) -> Result<Self,String> {
        let b=&file.binding;
        let ctx=ChannelContext {worker_agent:b.agent.clone(),proposal_action:b.proposal_action.clone(),
            session_id:b.session_id,channel_id:b.channel_id};
        ctx.validate().map_err(|_|"invalid signing channel identity")?;
        if b.installed_app_id.is_empty() || b.installed_app_id.len()>128 || b.role!="mpc" ||
           DnaHash::try_from_raw_39(b.dna_hash.clone()).is_err() ||
           AgentPubKey::try_from_raw_39(b.agent.clone()).is_err() ||
           ActionHash::try_from_raw_39(b.proposal_action.clone()).is_err() {
            return Err("signer policy cell or proposal is invalid".into());
        }
        if let Some(spec)=&file.spec {
            holochain_mpc_frost_ed25519::Binding::new(b.proposal_action.clone(),spec.clone())
                .map_err(|_|"pinned session spec is not a valid FROST ceremony")?;
            if spec.session_id!=b.session_id || !spec.contains(&b.agent) {
                return Err("pinned session spec does not match the signer ceremony".into());
            }
        } else if !file.recipients.is_empty() {
            return Err("signer policy grants capabilities but pins no session spec; regenerate it".into());
        }
        if file.recipients.len()>64 {return Err("too many recipient capabilities".into());}
        let mut recipients=BTreeMap::new();
        for r in file.recipients {
            if r.agent==b.agent || AgentPubKey::try_from_raw_39(r.agent.clone()).is_err() ||
                !file.spec.as_ref().is_some_and(|s|s.contains(&r.agent)) ||
                recipients.insert(r.agent, r.cap_secret).is_some() {
                return Err("duplicate, self, non-member or invalid capability recipient".into());
            }
        }
        Ok(Self {binding:file.binding,recipients,spec:file.spec})
    }

    pub fn pin(&self) -> ConductorPin {
        ConductorPin {app_id:self.binding.installed_app_id.clone(),role:self.binding.role.clone(),
            dna_hash:self.binding.dna_hash.clone(),node:ChannelContext {
                worker_agent:self.binding.agent.clone(),proposal_action:self.binding.proposal_action.clone(),
                session_id:self.binding.session_id,channel_id:self.binding.channel_id}}
    }

    pub fn authorize(&self, req: &SignerRequest) -> Result<(MpcCall, ZomeCallParams), String> {
        if req.version!=1 || req.binding!=self.binding {return Err("request not bound to this signer ceremony".into());}
        let op=match req.operation.as_str() {
            "get_inbox_slots"=>MpcCall::GetInboxSlots,
            "get_encryption_key_bindings"=>MpcCall::GetEncryptionKeyBindings,
            "register_encryption_key"=>MpcCall::RegisterEncryptionKey,
            "send_protocol_message"=>MpcCall::SendProtocolMessage,
            _=>return Err("signer refused unlisted function".into()),
        };
        let proposal=ActionHash::try_from_raw_39(self.binding.proposal_action.clone())
            .map_err(|_|"invalid pinned proposal")?;
        let payload=match op {
            MpcCall::GetInbox | MpcCall::GetProbeSessionStatus | MpcCall::GetGroupActivationAttestations |
            MpcCall::GetSigningApprovals | MpcCall::PublishResultCommitment =>
                return Err("FROST DKG signer refuses probe- and signing-profile operations".into()),
            MpcCall::GetInboxSlots | MpcCall::GetEncryptionKeyBindings => {
                if req.envelope.is_some() || req.public_key.is_some() {
                    return Err("read request carries outbound data".into());
                }
                ExternIO::encode(proposal).map_err(|_|"cannot encode read request")?
            }
            MpcCall::RegisterEncryptionKey => {
                if self.spec.is_none() {return Err("key registration needs a policy pinned to the full session spec".into());}
                if req.envelope.is_some() {return Err("key registration contains envelope".into());}
                let key=req.public_key.ok_or("missing worker encryption key")?;
                if key==[0;32] {return Err("zero worker encryption key".into());}
                ExternIO::encode(KeyRegistration {proposal,public_key:key})
                    .map_err(|_|"cannot encode key registration")?
            }
            MpcCall::SendProtocolMessage => {
                if req.public_key.is_some() {return Err("send request contains public key".into());}
                let env=req.envelope.as_ref().ok_or("missing worker envelope")?;
                let recipient=env.recipient.as_ref().ok_or("outbound envelope has no recipient")?;
                // DKG rounds only (1 announce, 2 attest, 3 sealed share).
                // Signing rounds 4..6 belong to the separate signing profile,
                // which checks them against one operator-approved plan.
                if env.sender!=self.binding.agent || env.session_id!=self.binding.session_id ||
                    recipient==&self.binding.agent || env.protocol_id!="frost-ed25519" ||
                    env.protocol_version!=1 || env.wire_version!=1 ||
                    env.round==0 || env.round>3 || env.sequence==u64::MAX ||
                    env.payload.len()==0 || env.payload.len()>128*1024 ||
                    env.payload_hash!=holochain_mpc_core::commitment("envelope-payload",&env.payload) {
                    return Err("outbound envelope violates signer ceremony bounds".into());
                }
                // The coordinator rebuilds the stored envelope from the on-chain
                // proposal, so authorise exactly that envelope, never the label.
                let spec=self.spec.as_ref().ok_or("send needs a policy pinned to the full session spec")?;
                let expected=Envelope::new(spec,self.binding.agent.clone(),Some(recipient.clone()),
                    env.round,env.sequence,env.payload.clone())
                    .map_err(|_|"outbound envelope violates the pinned session spec")?;
                if &expected!=env {return Err("outbound envelope differs from the pinned session spec".into());}
                if env.round == 3 && !serde_json::from_slice::<holochain_mpc_core::SealedPacket>(&env.payload)
                    .map(|sealed|sealed.structurally_valid()).unwrap_or(false) {
                    return Err("outbound Round-2 ciphertext is not sealed".into());
                }
                let cap=self.recipients.get(recipient).ok_or("no authorised capability for recipient")?;
                let agent=AgentPubKey::try_from_raw_39(recipient.clone())
                    .map_err(|_|"invalid recipient key")?;
                ExternIO::encode(OutboundCall {proposal,recipient:agent,round:env.round,
                    sequence:env.sequence,payload:env.payload.clone(),recipient_cap_secret:cap.clone()})
                    .map_err(|_|"cannot encode outbound message")?
            }
        };
        let agent=AgentPubKey::try_from_raw_39(self.binding.agent.clone())
            .map_err(|_|"invalid signer agent")?;
        let dna=DnaHash::try_from_raw_39(self.binding.dna_hash.clone())
            .map_err(|_|"invalid signer DNA")?;
        let mut nonce_bytes=vec![0_u8;32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce=Nonce256Bits::try_from(nonce_bytes).map_err(|_|"nonce generation failed")?;
        let expires_at=Timestamp::now().checked_add(&Duration::from_secs(30))
            .ok_or("expiry overflow")?;
        let params=ZomeCallParams {provenance:agent.clone(),cell_id:CellId::new(dna,agent),
            zome_name:ZomeName::from("mpc"),fn_name:FunctionName::from(op.name()),
            cap_secret:None,payload,nonce,expires_at};
        Ok((op,params))
    }

    /// Sign the canonical **hash**, never raw MsgPack bytes. The conductor
    /// verifies this Ed25519 signature and handles nonce replay admission.
    pub async fn sign(&self, req:&SignerRequest, lair:&MetaLairClient) -> Result<ZomeCallParamsSigned,String> {
        let (op,params)=self.authorize(req)?;
        let agent=params.provenance.clone();
        let (bytes,hash)=params.serialize_and_hash().map_err(|_|"call serialization failed")?;
        let signature=agent.sign_raw(lair,Arc::<[u8]>::from(hash))
            .await.map_err(|_|"Lair refused signing")?;
        let signed=ZomeCallParamsSigned::new(bytes,signature);
        let pin=self.pin();
        validate_signed_call(&pin,op,&signed)?;
        if let Some(env)=req.envelope.as_ref() {validate_signed_envelope(&pin,env,&signed)?;}
        if let Some(key)=req.public_key {validate_signed_key_registration(&pin,key,&signed)?;}
        Ok(signed)
    }
}

/// Read the Lair `connectionUrl` from `<lair_root>/lair-keystore-config.yaml`
/// so it never appears in argv (`/proc/*/cmdline`), environment, or logs.
/// Its `k=` query is the Lair SERVER public key (verified in `hello`), not
/// the client credential; the passphrase is. It is still kept out of output.
/// Requires an owned 0700 root, an owned 0600 single-link config, and a
/// `unix://` socket inside that root.
pub fn lair_url_from_root(root: &Path) -> Result<Zeroizing<String>,String> {
    if !root.is_absolute() { return Err("Lair root must be an absolute path".into()); }
    let dir=fs::symlink_metadata(root).map_err(|_|"Lair root unavailable")?;
    if !dir.is_dir() || dir.file_type().is_symlink() || dir.uid()!=unsafe{libc::geteuid()} ||
        dir.permissions().mode() & 0o077 != 0 {
        return Err("Lair root must be an owned directory without group/other access".into());
    }
    let path=root.join("lair-keystore-config.yaml");
    let info=fs::symlink_metadata(&path).map_err(|_|"Lair config unavailable")?;
    if !info.is_file() || info.file_type().is_symlink() || info.nlink()!=1 ||
        info.uid()!=unsafe{libc::geteuid()} || info.permissions().mode() & 0o077 != 0 ||
        info.len()==0 || info.len()>MAX_POLICY_BYTES as u64 {
        return Err("Lair config must be an owned private regular file".into());
    }
    let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW)
        .open(&path).map_err(|_|"cannot open Lair config")?;
    let mut text=Zeroizing::new(String::new());
    file.take(MAX_POLICY_BYTES as u64).read_to_string(&mut text).map_err(|_|"cannot read Lair config")?;
    let mut found=None;
    for line in text.lines() {
        if let Some(value)=line.strip_prefix("connectionUrl:") {
            if found.is_some() {return Err("Lair config has more than one connectionUrl".into());}
            found=Some(Zeroizing::new(value.trim().trim_matches(|c|c=='\''||c=='"').to_owned()));
        }
    }
    let url=found.ok_or("Lair config has no connectionUrl")?;
    let socket=url.strip_prefix("unix://").ok_or("Lair connectionUrl is not a unix:// socket")?
        .split('?').next().unwrap_or_default();
    if url.len()>1024 || Path::new(socket).parent()!=Some(root) {
        return Err("Lair socket is not inside the given Lair root".into());
    }
    Ok(url)
}

/// Prompt on the terminal for the Lair passphrase (never argv/env), unlock
/// the IPC client and return it. The ordinary string copy is zeroized.
pub async fn connect_lair_interactive(url: &str) -> Result<MetaLairClient,String> {
    use lair_keystore_api::dependencies::sodoken;
    if url.len()>1024 || !url.starts_with("unix://") {return Err("only a local unix:// Lair URL is supported".into());}
    let mut phrase=rpassword::prompt_password("Lair unlock passphrase: ")
        .map_err(|_|"cannot read Lair unlock passphrase")?;
    if phrase.is_empty() || phrase.len()>4096 {zeroize::Zeroize::zeroize(&mut phrase);return Err("invalid passphrase length".into());}
    let mut locked=sodoken::LockedArray::new(phrase.len()).map_err(|_|"cannot allocate locked passphrase")?;
    locked.lock().copy_from_slice(phrase.as_bytes());
    zeroize::Zeroize::zeroize(&mut phrase);
    let client=tokio::time::timeout(Duration::from_secs(20),
        lair_keystore_api::ipc_keystore::ipc_keystore_connect(url2::Url2::parse(url).into(),
            Arc::new(std::sync::Mutex::new(locked))))
        .await.map_err(|_|"Lair connection timed out")?
        .map_err(|_|"Lair authentication failed")?;
    MetaLairClient::from_client(client).await.map_err(|_|"Lair client setup failed".into())
}

#[derive(Serialize,Debug)]
struct KeyRegistration {proposal:ActionHash,public_key:[u8;32]}
#[derive(Serialize,Debug)]
struct OutboundCall {
    proposal:ActionHash,recipient:AgentPubKey,round:u32,sequence:u64,
    payload:Vec<u8>,recipient_cap_secret:CapSecret,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding()->SignerBinding {
        SignerBinding {installed_app_id:"org.test.mpc".into(),role:"mpc".into(),
            dna_hash:DnaHash::from_raw_32(vec![8;32]).get_raw_39().to_vec(),
            agent:AgentPubKey::from_raw_32(vec![9;32]).get_raw_39().to_vec(),
            proposal_action:ActionHash::from_raw_32(vec![7;32]).get_raw_39().to_vec(),
            session_id:[3;32],channel_id:[4;32]}
    }
    fn req(op:&str)->SignerRequest {SignerRequest {version:1,operation:op.into(),binding:binding(),envelope:None,public_key:None,result:None}}
    fn policy()->SignerPolicy {SignerPolicy::new(SignerPolicyFile {binding:binding(),recipients:vec![],spec:None}).unwrap()}
    fn peer()->Vec<u8> {AgentPubKey::from_raw_32(vec![21;32]).get_raw_39().to_vec()}
    fn spec()->SessionSpec {
        let mut participants=vec![binding().agent,peer()];participants.sort();
        SessionSpec {session_id:[3;32],application_id:"org.test.mpc".into(),protocol_id:"frost-ed25519".into(),
            protocol_version:1,context_hash:[1;32],participants,threshold:2,max_round:6}
    }
    fn cap(agent:Vec<u8>)->Vec<RecipientCapability> {vec![RecipientCapability {agent,cap_secret:CapSecret::from([6;64])}]}
    fn pinned()->SignerPolicy {
        SignerPolicy::new(SignerPolicyFile {binding:binding(),recipients:cap(peer()),spec:Some(spec())}).unwrap()
    }
    fn env_to(to:Vec<u8>,round:u32,payload:&[u8])->Envelope {
        Envelope {wire_version:1,session_id:[3;32],protocol_id:"frost-ed25519".into(),protocol_version:1,
            sender:binding().agent,recipient:Some(to),round,sequence:1,
            payload_hash:holochain_mpc_core::commitment("envelope-payload",payload),payload:payload.to_vec()}
    }
    #[test]
    fn exact_ceremony_and_allowlist_required() {
        let p=policy();
        assert!(p.authorize(&req("get_inbox_slots")).is_ok());
        assert!(p.authorize(&req("get_encryption_key_bindings")).is_ok());
        assert!(p.authorize(&req("delete_entry")).is_err());
        let mut wrong=req("get_inbox_slots");wrong.binding.session_id=[8;32];
        assert!(p.authorize(&wrong).is_err());
        wrong=req("get_inbox_slots");wrong.binding.installed_app_id="other".into();
        assert!(p.authorize(&wrong).is_err());
        wrong=req("get_inbox_slots");wrong.envelope=Some(holochain_mpc_core::Envelope {
            wire_version:1,session_id:[3;32],protocol_id:"frost-ed25519".into(),protocol_version:1,
            sender:binding().agent,recipient:None,round:1,sequence:1,
            payload_hash:holochain_mpc_core::commitment("envelope-payload",b"a"),payload:b"a".to_vec()});
        assert!(p.authorize(&wrong).is_err());
    }
    #[test]
    fn fresh_nonce_and_bounded_expiry() {
        let p=policy();
        let (_,a)=p.authorize(&req("get_inbox_slots")).unwrap();
        let (_,b)=p.authorize(&req("get_inbox_slots")).unwrap();
        let (bytes_a,_)=a.serialize_and_hash().unwrap();
        let (bytes_b,_)=b.serialize_and_hash().unwrap();
        assert_ne!(bytes_a,bytes_b);
        assert!(a.expires_at.as_micros()>Timestamp::now().as_micros());
        assert!(a.expires_at.as_micros()-Timestamp::now().as_micros()<=31_000_000);
    }
    #[test]
    fn lair_url_is_read_from_a_private_root_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp=tempfile::tempdir().unwrap();
        let root=tmp.path().join("ks");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();
        let cfg=root.join("lair-keystore-config.yaml");
        let good=format!("---\nconnectionUrl: unix://{}/socket?k=SERVERPUB\npidFile: x\n",root.display());
        fs::write(&cfg,&good).unwrap();
        fs::set_permissions(&cfg,fs::Permissions::from_mode(0o644)).unwrap();
        assert!(lair_url_from_root(&root).is_err(),"world-readable config");
        fs::set_permissions(&cfg,fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(&*lair_url_from_root(&root).unwrap(),&format!("unix://{}/socket?k=SERVERPUB",root.display()));
        assert!(lair_url_from_root(Path::new("ks")).is_err(),"relative root");
        fs::set_permissions(&root,fs::Permissions::from_mode(0o755)).unwrap();
        assert!(lair_url_from_root(&root).is_err(),"open root");
        fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&cfg,"connectionUrl: unix:///elsewhere/socket?k=X\n").unwrap();
        assert!(lair_url_from_root(&root).is_err(),"socket outside root");
        fs::write(&cfg,format!("{good}connectionUrl: unix://{}/socket\n",root.display())).unwrap();
        assert!(lair_url_from_root(&root).is_err(),"ambiguous duplicate key");
        fs::write(&cfg,"connectionUrl: tcp://127.0.0.1:1?k=X\n").unwrap();
        assert!(lair_url_from_root(&root).is_err(),"non-unix");
    }
    #[test]
    fn registration_and_publish_require_exact_data_and_known_recipient() {
        let p=pinned();
        let mut r=req("register_encryption_key");
        assert!(p.authorize(&r).is_err());
        r.public_key=Some([5;32]);
        assert!(p.authorize(&r).is_ok());
        assert!(policy().authorize(&r).is_err(),"a policy without a pinned spec is read-only");
        r.envelope=Some(env_to(peer(),1,b"hi"));
        assert!(p.authorize(&r).is_err());
        r.operation="send_protocol_message".into();r.public_key=None;
        assert!(p.authorize(&r).is_ok());
        assert!(policy().authorize(&r).is_err()); // capability never supplied
        r.envelope=Some(env_to(AgentPubKey::from_raw_32(vec![22;32]).get_raw_39().to_vec(),1,b"hi"));
        assert!(p.authorize(&r).is_err()); // not a member, no capability
    }
    // Security-review B2 refusal: capabilities need a pinned FROST spec, so a
    // policy cannot be assembled for a probe or other non-FROST proposal.
    #[test]
    fn b2_capabilities_require_pinned_frost_spec() {
        assert!(SignerPolicy::new(SignerPolicyFile {binding:binding(),recipients:cap(peer()),spec:None}).is_err());
        let mut probe=spec();probe.protocol_id="mpc-transport-probe".into();probe.max_round=1;
        assert!(SignerPolicy::new(SignerPolicyFile {binding:binding(),recipients:cap(peer()),spec:Some(probe)}).is_err());
        let mut other=spec();other.session_id=[8;32];
        assert!(SignerPolicy::new(SignerPolicyFile {binding:binding(),recipients:cap(peer()),spec:Some(other)}).is_err());
        let stranger=AgentPubKey::from_raw_32(vec![22;32]).get_raw_39().to_vec();
        assert!(SignerPolicy::new(SignerPolicyFile {binding:binding(),recipients:cap(stranger),spec:Some(spec())}).is_err());
        let old:SignerPolicyFile=serde_json::from_value(serde_json::json!({"binding":binding(),"recipients":[]})).unwrap();
        assert!(SignerPolicy::new(old).is_ok(),"a pre-B2 read-only policy still loads");
    }
    #[test]
    fn b2_send_must_equal_envelope_rebuilt_from_pinned_spec() {
        let p=pinned();
        let mut r=req("send_protocol_message");
        r.envelope=Some(env_to(peer(),1,b"hi"));
        assert!(p.authorize(&r).is_ok());
        for change in 0..5 {
            let mut bad=r.clone();
            let e=bad.envelope.as_mut().unwrap();
            match change {
                0=>e.protocol_id="mpc-transport-probe".into(),
                1=>e.protocol_version=2,
                2=>e.session_id=[9;32],
                3=>e.round=7,
                _=>e.payload_hash=[0;32],
            }
            assert!(p.authorize(&bad).is_err(),"altered envelope {change} was authorised");
        }
    }
    // Security review 2026-10-22 R2: the DKG-time signer never signs a
    // signing-round frame; only the plan-pinned signing profile may.
    #[test]
    fn dkg_profile_refuses_signing_rounds() {
        let p=pinned();
        for round in [1,2] {
            let mut r=req("send_protocol_message");r.envelope=Some(env_to(peer(),round,b"hi"));
            assert!(p.authorize(&r).is_ok(),"DKG round {round}");
        }
        for round in [4,5,6] {
            let mut r=req("send_protocol_message");r.envelope=Some(env_to(peer(),round,b"hi"));
            assert!(p.authorize(&r).is_err(),"signing round {round} must be refused by the DKG profile");
        }
    }
}
