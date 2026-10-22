//! Phase 4 local Unix signer IPC. This is a *client protocol*, NOT a Lair
//! signing implementation. The signer runs under the same trusted uid and
//! must independently enforce app/agent/cell/ceremony/capability policy.
//! The raw private agent signing key never enters this process.
use crate::connection_policy::ConductorPin;
use crate::signed_relay::{FreshMpcSigner, SignIntent};
use crate::signed_call_policy::{validate_signed_call, validate_signed_envelope, validate_signed_key_registration, validate_signed_result};
use holochain_conductor_api::ZomeCallParamsSigned;
use holochain_mpc_core::Envelope;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

const MAX_REQUEST: usize = 384 * 1024;
const MAX_RESPONSE: usize = 512 * 1024;
const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerBinding {
    pub installed_app_id: String,
    pub role: String,
    pub dna_hash: Vec<u8>,
    pub agent: Vec<u8>,
    pub proposal_action: Vec<u8>,
    pub session_id: [u8;32],
    pub channel_id: [u8;32],
}
impl From<&ConductorPin> for SignerBinding {
    fn from(pin: &ConductorPin) -> Self {
        Self { installed_app_id:pin.app_id.clone(),role:pin.role.clone(),
            dna_hash:pin.dna_hash.clone(),agent:pin.node.worker_agent.clone(),
            proposal_action:pin.node.proposal_action.clone(),
            session_id:pin.node.session_id,channel_id:pin.node.channel_id }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerRequest {
    pub version: u8,
    pub operation: String,
    pub binding: SignerBinding,
    pub envelope: Option<Envelope>,
    pub public_key: Option<[u8;32]>,
    /// Phase 8 result publication only; absent (and not serialized) otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultRequest>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultRequest {
    pub result_bytes: Vec<u8>,
    pub verification_artifact: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerResponse {
    version: u8,
    signed: ZomeCallParamsSigned,
}

pub struct UnixMpcSigner {
    socket_path: PathBuf,
    pin: ConductorPin,
}

impl UnixMpcSigner {
    pub fn new(path: PathBuf, pin: ConductorPin) -> Result<Self, String> {
        pin.node.validate()?;
        if pin.role != "mpc" || pin.dna_hash.len() != 39 || pin.app_id.is_empty() {
            return Err("invalid signer ceremony pin".into());
        }
        check_socket(&path)?;
        Ok(Self {socket_path:path,pin})
    }

    pub async fn probe(&self) -> Result<(), String> {
        let socket = tokio::time::timeout(TIMEOUT, UnixStream::connect(&self.socket_path))
            .await.map_err(|_| "signer socket connection timed out")?
            .map_err(|_| "signer socket not accepting connections")?;
        same_user_peer(&socket)?;
        Ok(())
    }

    fn request(&self, intent: &SignIntent<'_>) -> SignerRequest {
        let (envelope,public_key,result) = match intent {
            SignIntent::RegisterEncryptionKey(key) => (None,Some(*key),None),
            SignIntent::Publish(env) => (Some((*env).clone()),None,None),
            SignIntent::PublishResult { result_bytes, verification_artifact } => (None,None,
                Some(ResultRequest { result_bytes:result_bytes.to_vec(),
                    verification_artifact:verification_artifact.to_vec() })),
            _ => (None,None,None),
        };
        SignerRequest { version:1,operation:intent.call().name().into(),
            binding:SignerBinding::from(&self.pin),envelope,public_key,result }
    }

    async fn request_signed(&self, req: &SignerRequest) -> Result<ZomeCallParamsSigned,String> {
        // Do not log request bytes: a future protocol revision may include
        // confidential information; Round-2 ciphertext is already included.
        let encoded = Zeroizing::new(serde_json::to_vec(req).map_err(|_| "cannot encode signer request")?);
        if encoded.is_empty() || encoded.len() > MAX_REQUEST {
            return Err("signer request size limit exceeded".into());
        }
        check_socket(&self.socket_path)?;
        let mut conn = tokio::time::timeout(TIMEOUT, UnixStream::connect(&self.socket_path))
            .await.map_err(|_| "signer connect timed out")?
            .map_err(|_| "signer socket unavailable")?;
        same_user_peer(&conn)?;
        let bytes = tokio::time::timeout(TIMEOUT, async {
            conn.write_all(&(encoded.len() as u32).to_be_bytes()).await
                .map_err(|_| "signer request header write failed")?;
            conn.write_all(&encoded).await.map_err(|_| "signer request write failed")?;
            let mut header = [0_u8;4];
            conn.read_exact(&mut header).await.map_err(|_| "signer reply header missing")?;
            let size = u32::from_be_bytes(header) as usize;
            if size == 0 || size > MAX_RESPONSE {
                return Err("signer reply size limit exceeded");
            }
            let mut reply=Zeroizing::new(vec![0_u8;size]);
            conn.read_exact(&mut reply).await.map_err(|_| "signer reply truncated")?;
            Ok::<_,&'static str>(reply)
        }).await.map_err(|_| "signer RPC deadline exceeded")??;
        let response: SignerResponse = serde_json::from_slice(&bytes)
            .map_err(|_| "signer returned malformed signed zome call")?;
        if response.version != 1 { return Err("unsupported signer response version".into()); }
        Ok(response.signed)
    }
}

fn check_socket(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {return Err("signer socket path must be absolute".into());}
    let parent=path.parent().ok_or("signer socket has no parent")?;
    let dir=fs::symlink_metadata(parent).map_err(|_| "signer directory is unavailable")?;
    let sock=fs::symlink_metadata(path).map_err(|_| "signer socket is unavailable")?;
    let uid=unsafe { libc::geteuid() };
    if !dir.is_dir() || dir.file_type().is_symlink() || dir.uid()!=uid ||
       dir.permissions().mode() & 0o777 != 0o700 ||
       !sock.file_type().is_socket() || sock.uid()!=uid ||
       sock.permissions().mode() & 0o777 != 0o600 {
        return Err("signer socket requires owned 0700 directory and 0600 socket".into());
    }
    Ok(())
}

fn same_user_peer(socket: &UnixStream) -> Result<(),String> {
    // Linux SO_PEERCRED binds each connection to the operator's local uid;
    // file permissions alone would not identify an already-open fd.
    let mut cred: libc::ucred = unsafe {std::mem::zeroed()};
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let status = unsafe { libc::getsockopt(socket.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,
        &mut cred as *mut libc::ucred as *mut libc::c_void,&mut len) };
    if status != 0 || len as usize != std::mem::size_of::<libc::ucred>() ||
       cred.uid != unsafe{libc::geteuid()} {
        return Err("signer peer is not the expected local uid".into());
    }
    Ok(())
}

impl FreshMpcSigner for UnixMpcSigner {
    async fn sign(&mut self, intent: SignIntent<'_>) -> Result<ZomeCallParamsSigned,String> {
        let request=self.request(&intent);
        let call=intent.call();
        let signed=self.request_signed(&request).await?;
        validate_signed_call(&self.pin,call,&signed)?;
        match intent {
            SignIntent::Publish(envelope) => validate_signed_envelope(&self.pin,envelope,&signed)?,
            SignIntent::RegisterEncryptionKey(key) =>
                validate_signed_key_registration(&self.pin,key,&signed)?,
            SignIntent::PublishResult { result_bytes, verification_artifact } =>
                validate_signed_result(&self.pin,result_bytes,verification_artifact,&signed)?,
            _=>{},
        }
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::ChannelContext;
    use holochain_zome_types::prelude::*;
    use holochain_nonce::Nonce256Bits;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;
    fn pin() -> ConductorPin {
        let agent = AgentPubKey::from_raw_32(vec![9;32]);
        let dna = DnaHash::from_raw_32(vec![8;32]);
        let proposal = ActionHash::from_raw_32(vec![7;32]);
        ConductorPin {app_id:"app.test".into(),role:"mpc".into(),dna_hash:dna.get_raw_39().to_vec(),
            node:ChannelContext {worker_agent:agent.get_raw_39().to_vec(),
                proposal_action:proposal.get_raw_39().to_vec(),session_id:[3;32],channel_id:[4;32]}}
    }
    fn signed_read(pin: &ConductorPin) -> ZomeCallParamsSigned {
        let agent=AgentPubKey::try_from_raw_39(pin.node.worker_agent.clone()).unwrap();
        let dna=DnaHash::try_from_raw_39(pin.dna_hash.clone()).unwrap();
        let proposal=ActionHash::try_from_raw_39(pin.node.proposal_action.clone()).unwrap();
        let params=ZomeCallParams {provenance:agent.clone(),cell_id:CellId::new(dna,agent),
            zome_name:ZomeName::from("mpc"),fn_name:FunctionName::from("get_inbox"),
            cap_secret:None,payload:ExternIO::encode(proposal).unwrap(),
            nonce:Nonce256Bits::try_from(vec![1u8;32]).expect("32-byte test nonce"),expires_at:Timestamp::now()};
        let (bytes,_) = params.serialize_and_hash().unwrap();
        ZomeCallParamsSigned::new(bytes,Signature([0;64])) // mock signer; not valid on real conductor
    }
    #[tokio::test]
    async fn signer_rpc_enforces_binding_and_rejects_other_operation() {
        let tmp=tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(),fs::Permissions::from_mode(0o700)).unwrap();
        let path=tmp.path().join("sign.sock");
        let listener=UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).unwrap();
        let bound=pin();
        let expected=bound.clone();
        let server=tokio::spawn(async move {
            let (mut peer,_)=listener.accept().await.unwrap();
            let mut h=[0;4];peer.read_exact(&mut h).await.unwrap();
            let length=u32::from_be_bytes(h) as usize;
            let mut data=vec![0;length];peer.read_exact(&mut data).await.unwrap();
            let parsed:SignerRequest=serde_json::from_slice(&data).unwrap();
            assert_eq!(parsed.version,1);
            assert_eq!(parsed.operation,"get_inbox");
            assert_eq!(parsed.binding.agent,expected.node.worker_agent);
            assert_eq!(parsed.binding.proposal_action,expected.node.proposal_action);
            assert!(parsed.envelope.is_none());
            assert!(parsed.public_key.is_none());
            let wire=serde_json::to_vec(&SignerResponse{version:1,signed:signed_read(&expected)}).unwrap();
            peer.write_all(&(wire.len() as u32).to_be_bytes()).await.unwrap();
            peer.write_all(&wire).await.unwrap();
        });
        let mut signer=UnixMpcSigner::new(path,bound).unwrap();
        assert!(signer.sign(SignIntent::ReadInbox).await.is_ok());
        server.await.unwrap();
    }
    #[tokio::test]
    async fn signer_socket_requires_private_directory_and_socket() {
        let temp=tempfile::tempdir().unwrap();
        let path=temp.path().join("sign.sock");
        let _listener=UnixListener::bind(&path).unwrap();
        // The production socket validator deliberately requires BOTH the
        // containing directory to be 0700 and the socket to be 0600.
        // tempfile directories are not guaranteed to start with 0700.
        fs::set_permissions(temp.path(),fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&path,fs::Permissions::from_mode(0o666)).unwrap();
        assert!(UnixMpcSigner::new(path.clone(),pin()).is_err());
        fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).unwrap();
        assert!(UnixMpcSigner::new(path.clone(),pin()).is_ok());
        // A private socket alone is insufficient when its parent is shared.
        fs::set_permissions(temp.path(),fs::Permissions::from_mode(0o755)).unwrap();
        assert!(UnixMpcSigner::new(path.clone(),pin()).is_err());
        fs::set_permissions(temp.path(),fs::Permissions::from_mode(0o700)).unwrap();
        assert!(UnixMpcSigner::new(path.clone(),pin()).is_ok());
        let mut wrong=pin();wrong.role="other".into();
        assert!(UnixMpcSigner::new(path,wrong).is_err());
    }
}
