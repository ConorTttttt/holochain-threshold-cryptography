//! Phase 5A standalone Lair-backed signer for the Phase 4 relay socket.
//! Only run with an isolated operator account and trusted, pre-provisioned Lair.
use holochain_mpc_dkg_worker::lair_signer::read_private_policy;
use holochain_mpc_dkg_worker::socket_signer::SignerRequest;
use holochain_keystore::MetaLairClient;
use lair_keystore_api::ipc_keystore::ipc_keystore_connect;
use lair_keystore_api::dependencies::sodoken;
use serde::Serialize;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::fd::AsRawFd;
use std::path::{Path,PathBuf};
use std::sync::{Arc,Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt,AsyncWriteExt};
use tokio::net::{UnixListener,UnixStream};
use zeroize::{Zeroize,Zeroizing};

const MAX_REQUEST:usize=384*1024;
const MAX_RESPONSE:usize=512*1024;
const DEADLINE:Duration=Duration::from_secs(15);

struct Args { probe_profile:bool, signing_profile:bool, status_profile:bool, policy:PathBuf,socket:PathBuf,lair_url:zeroize::Zeroizing<String> }
fn args() -> Result<Args,String> {
    let mut probe_profile=false;
    let mut signing_profile=false;
    let mut status_profile=false;
    let mut policy=None;let mut socket=None;let mut lair_url=None;let mut lair_root=None;
    let mut cmd=std::env::args().skip(1);
    while let Some(flag)=cmd.next() {
        if flag=="--probe-profile" {
            if probe_profile {return Err("repeated --probe-profile".into());}
            probe_profile=true;continue;
        }
        if flag=="--signing-profile" {
            if signing_profile {return Err("repeated --signing-profile".into());}
            signing_profile=true;continue;
        }
        if flag=="--frost-status-profile" {
            if status_profile {return Err("repeated --frost-status-profile".into());}
            status_profile=true;continue;
        }
        let val=cmd.next().ok_or("missing option value")?;
        match flag.as_str() {
            "--policy-file"=>policy=Some(PathBuf::from(val)),
            "--signer-socket"=>socket=Some(PathBuf::from(val)),
            "--lair-url" if lair_url.is_none()=>lair_url=Some(val),
            // Preferred: keeps the Lair URL out of argv / `ps` output.
            "--lair-root" if lair_root.is_none()=>lair_root=Some(PathBuf::from(val)),
            _=>return Err("unknown or repeated option".into()),
        }
    }
    let lair_url=match (lair_url,lair_root) {
        (Some(url),None)=>zeroize::Zeroizing::new(url),
        (None,Some(root))=>holochain_mpc_dkg_worker::lair_signer::lair_url_from_root(&root)?,
        _=>return Err("give exactly one of --lair-root (preferred) or --lair-url".into()),
    };
    if lair_url.len()>1024 || !lair_url.starts_with("unix://") {
        return Err("only a pre-provisioned local Unix Lair URL is supported".into());
    }
    if [probe_profile,signing_profile,status_profile].into_iter().filter(|v| *v).count()>1 {
        return Err("choose at most one signer profile".into());
    }
    Ok(Args{probe_profile,signing_profile,status_profile,policy:policy.ok_or("missing --policy-file")?,
        socket:socket.ok_or("missing --signer-socket")?,lair_url})
}

fn socket_parent(path:&Path)->Result<(),String> {
    if !path.is_absolute() {return Err("signer socket requires absolute path".into());}
    let parent=path.parent().ok_or("missing socket parent")?;
    let info=fs::symlink_metadata(parent).map_err(|_|"signer socket parent missing")?;
    if !info.is_dir() || info.file_type().is_symlink() ||
       info.uid()!=unsafe{libc::geteuid()} || info.permissions().mode() & 0o777 != 0o700 {
       return Err("signer parent must be an owned 0700 directory".into());
    }
    if fs::symlink_metadata(path).is_ok() {return Err("signer socket already exists: refusing replacement".into());}
    Ok(())
}
fn same_uid(conn:&UnixStream)->Result<(),String> {
    let mut peer:libc::ucred=unsafe{std::mem::zeroed()};
    let mut len=std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ok=unsafe{libc::getsockopt(conn.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,
        &mut peer as *mut libc::ucred as *mut libc::c_void,&mut len)};
    if ok!=0 || len as usize!=std::mem::size_of::<libc::ucred>() ||
       peer.uid!=unsafe{libc::geteuid()} {return Err("unauthorised signer socket peer".into());}
    Ok(())
}

#[derive(Serialize)]
struct SignerResponse {version:u8,signed:holochain_conductor_api::ZomeCallParamsSigned}

enum ActivePolicy {
    Frost(holochain_mpc_dkg_worker::lair_signer::SignerPolicy),
    Probe(holochain_mpc_dkg_worker::probe_signer::ProbeSignerPolicy),
    Signing(holochain_mpc_dkg_worker::signing_signer::SigningSignerPolicy),
    FrostStatus(holochain_mpc_dkg_worker::frost_status_signer::FrostStatusSignerPolicy),
}
impl ActivePolicy {
    async fn sign(&self, req:&SignerRequest, lair:&MetaLairClient)
        ->Result<holochain_conductor_api::ZomeCallParamsSigned,String> {
        match self {Self::Frost(p)=>p.sign(req,lair).await,Self::Probe(p)=>p.sign(req,lair).await,
            Self::Signing(p)=>p.sign(req,lair).await,
            Self::FrostStatus(p)=>p.sign(req,lair).await}
    }
}

async fn handle(mut conn:UnixStream,policy:&ActivePolicy,
    lair:&MetaLairClient)->Result<(),String> {
    same_uid(&conn)?;
    // Requests receive no error body: failed policy or Lair signing closes the
    // socket and the relay treats it as an uncertain operation, then aborts.
    let mut length=[0_u8;4];
    let signed=tokio::time::timeout(DEADLINE,async {
        conn.read_exact(&mut length).await.map_err(|_|"truncated signer header")?;
        let size=u32::from_be_bytes(length) as usize;
        if size==0 || size>MAX_REQUEST {return Err("oversized signer request");}
        let mut raw=Zeroizing::new(vec![0_u8;size]);
        conn.read_exact(&mut raw).await.map_err(|_|"truncated signer request")?;
        let req:SignerRequest=serde_json::from_slice(&raw).map_err(|_|"invalid signer request")?;
        policy.sign(&req,lair).await.map_err(|_|"signing request denied")
    }).await.map_err(|_|"signer request deadline exceeded")??;
    let raw=Zeroizing::new(serde_json::to_vec(&SignerResponse{version:1,signed})
        .map_err(|_|"cannot encode signed response")?);
    if raw.len()==0 || raw.len()>MAX_RESPONSE {return Err("signed response too large".into());}
    tokio::time::timeout(DEADLINE,async {
        conn.write_all(&(raw.len() as u32).to_be_bytes()).await?;
        conn.write_all(&raw).await?;
        conn.flush().await
    }).await.map_err(|_|"signer response timed out")?
        .map_err(|_|"signer response write failed")?;
    Ok(())
}

async fn run()->Result<(),String> {
    let opts=args()?;
    // Policy MUST be pinned before unlocking Lair or creating the socket.
    let policy=if opts.probe_profile {
        use holochain_mpc_dkg_worker::probe_signer::{read_private_json,ProbeSignerPolicy};
        ActivePolicy::Probe(ProbeSignerPolicy::new(read_private_json(&opts.policy)?)?)
    } else if opts.signing_profile {
        use holochain_mpc_dkg_worker::{probe_signer::read_private_json,signing_signer::SigningSignerPolicy};
        ActivePolicy::Signing(SigningSignerPolicy::new(read_private_json(&opts.policy)?)?)
    } else if opts.status_profile {
        use holochain_mpc_dkg_worker::{probe_signer::read_private_json,frost_status_signer::FrostStatusSignerPolicy};
        ActivePolicy::FrostStatus(FrostStatusSignerPolicy::new(read_private_json(&opts.policy)?)?)
    } else {ActivePolicy::Frost(read_private_policy(&opts.policy)?)};
    socket_parent(&opts.socket)?;

    // Prompt the operator instead of persisting the Lair passphrase in the
    // config, environment, argv, logs, or shell history. Clear the ordinary
    // temporary string immediately after copying it to locked memory.
    let mut phrase=rpassword::prompt_password("Lair unlock passphrase: ")
        .map_err(|_|"cannot read Lair unlock passphrase")?;
    if phrase.is_empty() || phrase.len()>4096 {phrase.zeroize();return Err("invalid Lair passphrase length".into());}
    let mut locked=sodoken::LockedArray::new(phrase.len())
        .map_err(|_|"cannot allocate locked passphrase")?;
    locked.lock().copy_from_slice(phrase.as_bytes());
    phrase.zeroize();
    let shared=Arc::new(Mutex::new(locked));
    let connection_url=url2::Url2::parse(&opts.lair_url);
    let client=tokio::time::timeout(Duration::from_secs(20),ipc_keystore_connect(connection_url.into(),shared))
        .await.map_err(|_|"Lair connection timed out")?
        .map_err(|_|"Lair authentication failed")?;
    let lair=MetaLairClient::from_client(client).await.map_err(|_|"Lair client setup failed")?;

    let listener=UnixListener::bind(&opts.socket).map_err(|_|"cannot bind private signer socket")?;
    fs::set_permissions(&opts.socket,fs::Permissions::from_mode(0o600))
        .map_err(|_|"cannot secure signer socket")?;
    let info=fs::symlink_metadata(&opts.socket).map_err(|_|"cannot stat bound signer socket")?;
    if info.uid()!=unsafe{libc::geteuid()} || info.permissions().mode() & 0o777 != 0o600 {
        return Err("bound signer socket not private".into());
    }
    println!("Lair signer ready for one pinned MPC ceremony (no signing secrets printed)");
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            incoming=listener.accept()=> {
                let (conn,_)=incoming.map_err(|_|"signer accept failed")?;
                if handle(conn,&policy,&lair).await.is_err() {
                    // Do not log request, signature, capability or passphrase.
                    eprintln!("signer refused or could not complete an RPC");
                }
            },
        }
    }
    drop(listener);
    let after=fs::symlink_metadata(&opts.socket).map_err(|_|"signer socket disappeared")?;
    if after.ino()==info.ino() && after.dev()==info.dev() {
        let _=fs::remove_file(&opts.socket);
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    holochain_mpc_dkg_worker::notice::exit_on_help("mpc-lair-signer", "Lair-backed signer service. See docs/V040_LAIR_SIGNER_PHASE5A.md.");
    if let Err(e)=run().await {eprintln!("FAIL: Lair signer: {e}");std::process::exit(1);}
}
