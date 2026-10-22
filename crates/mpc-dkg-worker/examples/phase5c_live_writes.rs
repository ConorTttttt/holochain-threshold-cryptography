//! Phase 5C-A/B TEST-ONLY LIVE WRITES. Run only against a dedicated 1-of-1
//! development proposal. This does not start DKG, grant remote capabilities,
//! or produce a usable post-restart transport key. Never use for production.
//!
//! This example deliberately leaves existing crate APIs unchanged, including
//! the production MPC signer allowlist. `accept-session` uses an interactive,
//! separately-authorized Lair signing operation; `register-dev-key` uses the
//! existing pinned MPC Unix signer interface.
use holochain_conductor_api::{AppAuthenticationRequest, AppInfo, AppRequest, AppResponse, CellInfo, ZomeCallParamsSigned};
use holochain_keystore::{AgentPubKeyExt, MetaLairClient};
use holochain_mpc_core::SessionSpec;
use holochain_mpc_dkg_worker::conductor_client::{authenticate_and_pin, read_app_token, submit_signed_mpc_call, MpcZomeResult};
use holochain_mpc_dkg_worker::connection_policy::{parse_local_app_socket, ConductorPin, ObservedApp, ObservedCell};
use holochain_mpc_dkg_worker::node_service::{decode_hex_exact, pinned_context};
use holochain_mpc_dkg_worker::signed_call_policy::MpcCall;
use holochain_mpc_dkg_worker::signed_relay::{FreshMpcSigner, SignIntent};
use holochain_mpc_dkg_worker::socket_signer::UnixMpcSigner;
use holochain_mpc_security::sealed::NativeChannelKey;
use holochain_nonce::Nonce256Bits;
use holochain_websocket::{connect, ConnectRequest, WebsocketConfig};
use holochain_zome_types::prelude::{ActionHash, AgentPubKey, CellId, DnaHash, ExternIO, FunctionName, Timestamp, ZomeCallParams, ZomeName};
use lair_keystore_api::dependencies::sodoken;
use lair_keystore_api::ipc_keystore::ipc_keystore_connect;
use rand::RngCore;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroize;

const RPC_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation { AcceptSession, RegisterDevKey }
impl Operation {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "accept-session" => Ok(Self::AcceptSession),
            "register-dev-key" => Ok(Self::RegisterDevKey),
            _ => Err("only accept-session or register-dev-key are supported".into()),
        }
    }
    fn confirmation(self) -> &'static str {
        match self {
            Self::AcceptSession => "--confirm-acceptance-write",
            Self::RegisterDevKey => "--confirm-disposable-key-write",
        }
    }
}

struct Options {
    operation: Operation, state: PathBuf, addr: SocketAddr, origin: String,
    token: PathBuf, app_id: String, dna: Vec<u8>, lair_url: Option<String>, signer_socket: Option<PathBuf>,
}

fn parse_args<I: Iterator<Item=String>>(mut iter: I) -> Result<Options, String> {
    let op = Operation::parse(&iter.next().ok_or("missing subcommand")?)?;
    let mut state=None; let mut addr=None; let mut origin=None; let mut token=None;
    let mut app_id=None; let mut dna=None; let mut lair_url=None; let mut signer_socket=None;
    let mut confirm=false;
    while let Some(flag) = iter.next() {
        if flag == op.confirmation() {
            if confirm { return Err("duplicate write confirmation".into()); }
            confirm=true;
            continue;
        }
        if flag.starts_with("--confirm-") {return Err("unrecognised write confirmation".into());}
        let val=iter.next().ok_or("option missing value")?;
        match flag.as_str() {
            "--state-dir" if state.is_none()=>state=Some(PathBuf::from(val)),
            "--app-socket" if addr.is_none()=>addr=Some(parse_local_app_socket(&val).map_err(str::to_owned)?),
            "--origin" if origin.is_none()=>origin=Some(val),
            "--app-token-file" if token.is_none()=>token=Some(PathBuf::from(val)),
            "--installed-app-id" if app_id.is_none()=>app_id=Some(val),
            "--dna-hex" if dna.is_none()=>dna=Some(decode_hex_exact::<39>(&val)
                .map_err(|_|"DNA hash must contain exactly 39 bytes of hex")?.to_vec()),
            "--lair-url" if lair_url.is_none()=>lair_url=Some(val),
            "--signer-socket" if signer_socket.is_none()=>signer_socket=Some(PathBuf::from(val)),
            _=>return Err("unknown or duplicate option".into()),
        }
    }
    if !confirm {return Err(format!("write requires explicit {}",op.confirmation()));}
    if lair_url.is_none() ||
       op==Operation::AcceptSession && signer_socket.is_some() ||
       op==Operation::RegisterDevKey && signer_socket.is_none() {
        return Err("both modes require --lair-url; register-dev-key also requires --signer-socket".into());
    }
    if lair_url.as_ref().is_some_and(|v| !v.starts_with("unix://") || v.len()>1024) {
        return Err("Lair URL must be a bounded local Unix URL".into());
    }
    Ok(Options {operation:op, state:state.ok_or("missing --state-dir")?,
        addr:addr.ok_or("missing --app-socket")?, origin:origin.ok_or("missing --origin")?,
        token:token.ok_or("missing --app-token-file")?, app_id:app_id.ok_or("missing --installed-app-id")?,
        dna:dna.ok_or("missing --dna-hex")?,lair_url,signer_socket})
}

fn observer(info: &AppInfo) -> ObservedApp {
    let mut cells=Vec::new();
    for (role, entries) in &info.cell_info {
        for item in entries {
            if let CellInfo::Provisioned(p)=item {
                cells.push(ObservedCell { role:role.to_string(),
                    dna_hash:p.cell_id.dna_hash().get_raw_39().to_vec(),
                    agent:p.cell_id.agent_pubkey().get_raw_39().to_vec() });
            }
        }
    }
    ObservedApp {installed_app_id:info.installed_app_id.to_string(),
        agent:info.agent_pub_key.get_raw_39().to_vec(),cells}
}

#[derive(Deserialize,Debug)]
struct SessionStatus {
    spec: SessionSpec,
    accepted: Vec<AgentPubKey>,
    ready_observed: bool,
}
fn validate_one_agent_session(pin:&ConductorPin,status:&SessionStatus)->Result<(),String> {
    if status.spec.participants.len()!=1 || status.spec.threshold!=1 ||
       status.spec.participants[0]!=pin.node.worker_agent ||
       status.spec.session_id!=pin.node.session_id {
        return Err("Phase 5C development write requires exactly the pinned 1-of-1 test session".into());
    }
    if status.accepted.iter().any(|a|a.get_raw_39()!=pin.node.worker_agent.as_slice()) ||
       status.accepted.len()>1 {
        return Err("unexpected acceptance author(s)".into());
    }
    Ok(())
}

fn params_for(pin:&ConductorPin,name:&str)->Result<ZomeCallParams,String> {
    let agent=AgentPubKey::try_from_raw_39(pin.node.worker_agent.clone())
        .map_err(|_|"invalid agent pin")?;
    let dna=DnaHash::try_from_raw_39(pin.dna_hash.clone())
        .map_err(|_|"invalid DNA pin")?;
    let proposal=ActionHash::try_from_raw_39(pin.node.proposal_action.clone())
        .map_err(|_|"invalid proposal pin")?;
    // This helper has an EXACT TWO-FUNCTION allowlist. Neither function is
    // reachable through Phase 5A's general-purpose production signer socket.
    if name!="get_session_status" && name!="accept_session" {
        return Err("forbidden bootstrap function".into());
    }
    let mut random=[0_u8;32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let nonce=Nonce256Bits::try_from(random.to_vec()).map_err(|_|"invalid random nonce")?;
    let expires_at=Timestamp::now().checked_add(&Duration::from_secs(30))
        .ok_or("expiry overflow")?;
    Ok(ZomeCallParams {provenance:agent.clone(),cell_id:CellId::new(dna,agent),
        zome_name:ZomeName::from("mpc"),fn_name:FunctionName::from(name),
        cap_secret:None,payload:ExternIO::encode(proposal).map_err(|_|"payload encoding failed")?,
        nonce,expires_at})
}

async fn sign_call(pin:&ConductorPin,which:&str,lair:&MetaLairClient)->Result<ZomeCallParamsSigned,String>{
    let params=params_for(pin,which)?;
    let agent=params.provenance.clone();
    let (bytes,hash)=params.serialize_and_hash().map_err(|_|"call encoding failed")?;
    let signature=agent.sign_raw(lair,Arc::<[u8]>::from(hash))
        .await.map_err(|_|"Lair refused exact-agent call")?;
    Ok(ZomeCallParamsSigned::new(bytes,signature))
}

async fn connect_lair(url:&str)->Result<MetaLairClient,String> {
    let mut phrase=rpassword::prompt_password("Lair unlock passphrase: ")
        .map_err(|_|"could not securely read Lair passphrase")?;
    if phrase.is_empty() || phrase.len()>4096 {phrase.zeroize();return Err("invalid passphrase length".into());}
    let mut locked=sodoken::LockedArray::new(phrase.len())
        .map_err(|_|"cannot lock Lair password memory")?;
    locked.lock().copy_from_slice(phrase.as_bytes());
    phrase.zeroize();
    let shared=Arc::new(Mutex::new(locked));
    let url=url2::Url2::parse(url);
    let raw=tokio::time::timeout(Duration::from_secs(20),ipc_keystore_connect(url.into(),shared))
        .await.map_err(|_|"Lair authentication timed out")?
        .map_err(|_|"Lair authentication failed")?;
    MetaLairClient::from_client(raw).await.map_err(|_|"Lair client initialisation failed".into())
}

async fn signed_session_status(opts:&Options,pin:&ConductorPin,lair:&MetaLairClient)
  ->Result<SessionStatus,String> {
    let token=read_app_token(&opts.token).map_err(|_|"app token invalid")?;
    let request:ConnectRequest=opts.addr.into();
    let request=request.try_set_header("Origin",&opts.origin)
        .map_err(|_|"invalid local Origin")?;
    let (sender,mut receiver)=connect(Arc::new(WebsocketConfig::CLIENT_DEFAULT),request)
        .await.map_err(|_|"conductor app interface unavailable")?;
    let pump=tokio::spawn(async move {while receiver.recv::<AppResponse>().await.is_ok() {}});
    let result=async {
        sender.authenticate(AppAuthenticationRequest{token:token.to_vec()})
            .await.map_err(|_|"app authentication failed")?;
        let info:AppResponse=sender.request(AppRequest::AppInfo).await.map_err(|_|"AppInfo failed")?;
        let AppResponse::AppInfo(Some(info))=info else {return Err("AppInfo rejected".into());};
        pin.verify(&observer(&info)).map_err(str::to_owned)?;
        let signed=sign_call(pin,"get_session_status",lair).await?;
        let response:AppResponse=tokio::time::timeout(RPC_DEADLINE,
            sender.request(AppRequest::CallZome(Box::new(signed))))
            .await.map_err(|_|"session status timed out")?
            .map_err(|_|"session status RPC unavailable")?;
        let AppResponse::ZomeCalled(io)=response else {return Err("session status rejected".into());};
        let status:SessionStatus=io.decode().map_err(|_|"bad session status")?;
        validate_one_agent_session(pin,&status)?;
        Ok::<SessionStatus,String>(status)
    }.await;
    pump.abort();
    result
}

async fn accept_session(opts:&Options,pin:&ConductorPin)->Result<(),String>{
    // Preflight WITHOUT requesting a signature.
    tokio::time::timeout(RPC_DEADLINE,
        authenticate_and_pin(opts.addr,&opts.origin,&opts.token,pin))
        .await.map_err(|_|"conductor preflight timed out")??;
    let lair=connect_lair(opts.lair_url.as_deref().ok_or("missing Lair URL")?).await?;
    let status=signed_session_status(opts,pin,&lair).await?;
    if status.ready_observed || !status.accepted.is_empty() {
        return Err("proposal already accepted; refusing another write".into());
    }
    let token=read_app_token(&opts.token).map_err(|_|"app token invalid")?;
    let connection:ConnectRequest=opts.addr.into();
    let connection=connection.try_set_header("Origin",&opts.origin)
        .map_err(|_|"invalid local Origin")?;
    let (sender,mut receiver)=connect(Arc::new(WebsocketConfig::CLIENT_DEFAULT),connection)
        .await.map_err(|_|"conductor app interface unavailable")?;
    let pump=tokio::spawn(async move {while receiver.recv::<AppResponse>().await.is_ok() {}});
    let run=async {
        sender.authenticate(AppAuthenticationRequest{token:token.to_vec()})
            .await.map_err(|_|"app authentication failed")?;
        let info:AppResponse=sender.request(AppRequest::AppInfo).await.map_err(|_|"AppInfo failed")?;
        let AppResponse::AppInfo(Some(info))=info else {return Err("AppInfo was rejected".into());};
        pin.verify(&observer(&info)).map_err(str::to_string)?;

        let signed=sign_call(pin,"accept_session",&lair).await?;
        // ONCE: a timeout or uncertain response is terminal. Inspect the chain.
        let response:AppResponse=tokio::time::timeout(RPC_DEADLINE,
            sender.request(AppRequest::CallZome(Box::new(signed))))
            .await.map_err(|_|"acceptance outcome UNKNOWN: inspect chain, do not retry")?
            .map_err(|_|"acceptance outcome UNKNOWN: inspect chain, do not retry")?;
        let AppResponse::ZomeCalled(io)=response else {
            return Err("acceptance rejected or outcome UNKNOWN: inspect chain before retry".into());
        };
        let action:ActionHash=io.decode().map_err(|_|"acceptance response unknown; inspect chain")?;
        if action.get_raw_39().len()!=39 {return Err("acceptance action invalid".into());}
        println!("PASS: Lair-signed accept_session accepted by real conductor (action recorded)");
        Ok::<(),String>(())
    }.await;
    pump.abort();
    run
}

async fn registered_keys(opts:&Options,pin:&ConductorPin,signer:&mut UnixMpcSigner)
  ->Result<Vec<holochain_mpc_dkg_worker::conductor_bridge::KeyEvidence>,String>{
    let signed=signer.sign(SignIntent::ReadEncryptionKeys).await?;
    match tokio::time::timeout(RPC_DEADLINE,
        submit_signed_mpc_call(opts.addr,&opts.origin,&opts.token,pin,
            MpcCall::GetEncryptionKeyBindings,signed))
        .await.map_err(|_|"key lookup timed out")?? {
        MpcZomeResult::EncryptionKeys(keys)=>Ok(keys),
        _=>Err("wrong signed key lookup response".into()),
    }
}

async fn register_dev_key(opts:&Options,pin:&ConductorPin)->Result<(),String>{
    tokio::time::timeout(RPC_DEADLINE,
        authenticate_and_pin(opts.addr,&opts.origin,&opts.token,pin))
        .await.map_err(|_|"conductor preflight timed out")??;
    let mut signer=UnixMpcSigner::new(opts.signer_socket.clone().ok_or("missing signer socket")?,pin.clone())?;
    signer.probe().await?;
    // A fresh, agent-signed status read verifies that this is the dedicated
    // ONE-member test proposal and that it was accepted BEFORE allowing a
    // permanently visible (but unusable after exit) test key registration.
    let lair=connect_lair(opts.lair_url.as_deref().ok_or("missing Lair URL")?).await?;
    let status=signed_session_status(opts,pin,&lair).await?;
    if !status.ready_observed || status.accepted.len()!=1 {
        return Err("test session not fully accepted: run accept-session first".into());
    }
    // A single test-only key; refuse duplicate/forked registration. The
    // backing private key never leaves process memory and is discarded.
    let prior=registered_keys(opts,pin,&mut signer).await?;
    if !prior.is_empty() {return Err("key binding already exists; no second registration will be attempted".into());}
    let transport=NativeChannelKey::generate();
    let public_key=transport.public_key();
    if public_key==[0;32] {return Err("invalid generated transport public key".into());}
    let signed=signer.sign(SignIntent::RegisterEncryptionKey(public_key)).await?;
    let result=tokio::time::timeout(RPC_DEADLINE,
        submit_signed_mpc_call(opts.addr,&opts.origin,&opts.token,pin,
            MpcCall::RegisterEncryptionKey,signed))
        .await.map_err(|_|"key registration outcome UNKNOWN: inspect chain, do not retry")?
        .map_err(|_|"key registration outcome UNKNOWN: inspect chain, do not retry")?;
    let MpcZomeResult::KeyRegistration{action}=result else {
        return Err("key registration reply unknown: inspect chain".into());
    };
    let found=registered_keys(opts,pin,&mut signer).await?;
    if found.len()!=1 || found[0].action!=action ||
       found[0].author!=pin.node.worker_agent || found[0].public_key!=public_key {
        return Err("key register/readback mismatch; inspect chain; do not retry".into());
    }
    // Deliberately no attempt to claim this key is a persistent DKG key.
    println!("PASS: Lair-signed test public key registered and read back from real conductor");
    println!("NOTE: test private encryption key was discarded; this binding is NOT suitable for DKG");
    Ok(())
}

#[tokio::main]
async fn main(){
    let result:Result<(),String>=async {
        let opts=parse_args(std::env::args().skip(1))?;
        let node=pinned_context(&opts.state).map_err(|_|"private pinned node state unavailable")?;
        let pin=ConductorPin {app_id:opts.app_id.clone(),role:"mpc".into(),dna_hash:opts.dna.clone(),node};
        match opts.operation {
            Operation::AcceptSession=>accept_session(&opts,&pin).await,
            Operation::RegisterDevKey=>register_dev_key(&opts,&pin).await,
        }
    }.await;
    if let Err(e)=result {eprintln!("FAIL: Phase 5C development write: {e}");std::process::exit(1);}
}

#[cfg(test)]
mod tests {
    use super::*;
    fn flags(op:&str)->Vec<String>{vec![op.into(),"--state-dir".into(),"/tmp/node".into(),
        "--app-socket".into(),"127.0.0.1:8888".into(),"--origin".into(),"http://localhost:8888".into(),
        "--app-token-file".into(),"/tmp/token".into(),"--installed-app-id".into(),"app".into(),
        "--dna-hex".into(),"aa".repeat(39)]}
    #[test]
    fn rejects_unauthorised_operations_and_missing_confirmation(){
        assert!(Operation::parse("send-protocol-message").is_err());
        assert!(Operation::parse("prepare-inbox-grant").is_err());
        assert!(Operation::parse("register-encryption-key").is_err());
        assert!(parse_args(flags("accept-session").into_iter()).is_err());
        assert!(parse_args(flags("register-dev-key").into_iter()).is_err());
    }
    #[test]
    fn test_only_mode_separation_and_pinned_inputs(){
        let mut a=flags("accept-session");
        a.extend(["--lair-url".into(),"unix:///private/ks/socket".into(),
                  "--confirm-acceptance-write".into()]);
        assert!(parse_args(a.clone().into_iter()).is_ok());
        a.push("--signer-socket".into()); a.push("/tmp/x".into());
        assert!(parse_args(a.into_iter()).is_err());
        let mut b=flags("register-dev-key");
        b.extend(["--signer-socket".into(),"/private/signer.sock".into(),
                  "--lair-url".into(),"unix:///private/ks".into(),
                  "--confirm-disposable-key-write".into()]);
        assert!(parse_args(b.clone().into_iter()).is_ok());
        b.push("--lair-url".into());b.push("unix:///private/ks".into());
        assert!(parse_args(b.into_iter()).is_err()); // duplicate URL
    }
    #[test]
    fn refuses_non_test_single_member_proposals(){
        use holochain_mpc_dkg_worker::ipc::ChannelContext;
        let pin=ConductorPin {app_id:"app".into(),role:"mpc".into(),dna_hash:vec![9;39],
            node:ChannelContext {worker_agent:vec![8;39],proposal_action:vec![7;39],
            session_id:[6;32],channel_id:[5;32]}};
        let mut spec=SessionSpec {session_id:[6;32],application_id:"app".into(),
            protocol_id:"frost-ed25519".into(),protocol_version:1,context_hash:[1;32],
            participants:vec![vec![8;39]],threshold:1,max_round:6};
        let mut status=SessionStatus {spec:spec.clone(),accepted:vec![],ready_observed:false};
        assert!(validate_one_agent_session(&pin,&status).is_ok());
        spec.threshold=2;status.spec=spec;
        assert!(validate_one_agent_session(&pin,&status).is_err());
        status.spec.threshold=1;status.spec.participants.push(vec![9;39]);
        assert!(validate_one_agent_session(&pin,&status).is_err());
    }
}
