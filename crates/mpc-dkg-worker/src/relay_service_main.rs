//! Phase 4 experimental one-ceremony local relay daemon.
//! Requires mpc-node to be running and a separately authorised signer socket.
//! No Lair implementation, no conductor admin access and no key-package export.
use holochain_mpc_dkg_worker::conductor_bridge::ConductorBridge;
use holochain_mpc_dkg_worker::conductor_client::authenticate_and_pin;
use holochain_mpc_dkg_worker::connection_policy::{parse_local_app_socket,ConductorPin};
use holochain_mpc_dkg_worker::node_service::{decode_hex_exact,pinned_context};
use holochain_mpc_dkg_worker::relay::RelayEngine;
use holochain_mpc_dkg_worker::relay_supervisor::{supervise,PollPolicy};
use holochain_mpc_dkg_worker::signed_relay::SignedAppTransport;
use holochain_mpc_dkg_worker::socket_signer::UnixMpcSigner;
use holochain_mpc_frost_ed25519::Binding;
use std::fs::{self,OpenOptions};
use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt,OpenOptionsExt,PermissionsExt};
use std::path::{Path,PathBuf};
use std::time::Duration;

struct Options {
    state:PathBuf, binding:PathBuf, socket:SocketAddr, origin:String,
    token:PathBuf, app_id:String, dna:Vec<u8>, signer:PathBuf,
    interval_ms:u64, max_polls:u32,
}
fn cli() -> Result<Options,String> {
    let mut state=None;let mut binding=None;let mut socket=None;let mut origin=None;
    let mut token=None;let mut app_id=None;let mut dna=None;let mut signer=None;
    let mut interval_ms=500_u64;let mut max_polls=600_u32;
    let mut args=std::env::args().skip(1);
    while let Some(flag)=args.next() {
        let val=args.next().ok_or("missing value for relay flag")?;
        match flag.as_str() {
            "--state-dir" => state=Some(PathBuf::from(val)),
            "--binding-file" => binding=Some(PathBuf::from(val)),
            "--app-socket" => socket=Some(parse_local_app_socket(&val).map_err(str::to_owned)?),
            "--origin" => origin=Some(val),
            "--app-token-file" => token=Some(PathBuf::from(val)),
            "--installed-app-id" => app_id=Some(val),
            "--dna-hex" => dna=Some(decode_hex_exact::<39>(&val).map_err(|e| e.to_string())?.to_vec()),
            "--signer-socket" => signer=Some(PathBuf::from(val)),
            "--poll-ms" => interval_ms=val.parse().map_err(|_| "invalid poll interval")?,
            "--max-polls" => max_polls=val.parse().map_err(|_| "invalid poll budget")?,
            _ => return Err("unknown relay-service option".into()),
        }
    }
    Ok(Options {
        state:state.ok_or("missing --state-dir")?,binding:binding.ok_or("missing --binding-file")?,
        socket:socket.ok_or("missing --app-socket")?,origin:origin.ok_or("missing --origin")?,
        token:token.ok_or("missing --app-token-file")?,
        app_id:app_id.ok_or("missing --installed-app-id")?,
        dna:dna.ok_or("missing --dna-hex")?,
        signer:signer.ok_or("missing --signer-socket")?,interval_ms,max_polls,
    })
}

/// Local ceremony spec is private at rest to prevent untrusted changes to
/// participant roster, threshold, context hash and proposal binding.
fn private_binding(path:&Path) -> Result<Binding,String> {
    let info=fs::symlink_metadata(path).map_err(|_| "binding file unavailable")?;
    if !info.is_file() || info.file_type().is_symlink() ||
        info.permissions().mode() & 0o777 != 0o600 ||
        info.uid()!=unsafe{libc::geteuid()} || info.nlink()!=1 ||
        info.len()==0 || info.len()>64*1024 {
        return Err("binding JSON must be a private 0600 regular file".into());
    }
    let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW)
        .open(path).map_err(|_| "cannot open private binding JSON")?;
    let after=file.metadata().map_err(|_| "cannot stat opened binding JSON")?;
    if info.dev()!=after.dev() || info.ino()!=after.ino() || info.len()!=after.len() {
        return Err("binding JSON changed while opening".into());
    }
    let mut raw=Vec::new();
    file.take(64*1024+1).read_to_end(&mut raw)
        .map_err(|_| "cannot read binding JSON")?;
    if raw.len() != info.len() as usize {return Err("binding JSON changed during read".into());}
    let b:Binding=serde_json::from_slice(&raw).map_err(|_| "invalid ceremony binding JSON")?;
    Binding::new(b.proposal_action.clone(),b.spec.clone())
        .map_err(|e|format!("invalid ceremony binding: {e}"))?;
    Ok(b)
}

async fn stop_signal() {
    let term=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    match term {
        Ok(mut sigterm)=>tokio::select! {
            _=tokio::signal::ctrl_c()=>{},
            _=sigterm.recv()=>{},
        },
        Err(_)=>{let _=tokio::signal::ctrl_c().await;},
    }
}

async fn run() -> Result<(),String> {
    let opts=cli()?;
    let binding=private_binding(&opts.binding)?;
    let node=pinned_context(&opts.state).map_err(|e|e.to_string())?;
    if node.proposal_action != binding.proposal_action || node.session_id != binding.spec.session_id ||
       !binding.spec.contains(&node.worker_agent) {
        return Err("node configuration disagrees with ceremony spec".into());
    }
    let pin=ConductorPin{app_id:opts.app_id,role:"mpc".into(),dna_hash:opts.dna,node:node.clone()};
    let policy=PollPolicy{interval:Duration::from_millis(opts.interval_ms),
        rpc_deadline:Duration::from_secs(20),max_polls:opts.max_polls};
    policy.validate()?;
    // All preflight checks MUST happen before DKG randomness is consumed.
    let signer=UnixMpcSigner::new(opts.signer,pin.clone())?;
    signer.probe().await?;
    authenticate_and_pin(opts.socket,&opts.origin,&opts.token,&pin).await?;
    let bridge=ConductorBridge::connect(&opts.state,node.clone(),binding.clone())?;
    let transport=SignedAppTransport{addr:opts.socket,origin:opts.origin,
        token_file:opts.token,pin,signer};
    let mut relay=RelayEngine::new(bridge,transport,binding,node.worker_agent)?;
    supervise(&mut relay,policy,stop_signal()).await?;
    let descriptor=relay.descriptor().ok_or("relay completed without group descriptor")?;
    // Public evidence for activation and signing (Phase 8); the share itself
    // was already sealed in the node journal before completion was reported.
    holochain_mpc_dkg_worker::node_service::write_descriptor(&opts.state,descriptor)
        .map_err(|e|format!("cannot record group descriptor: {e}"))?;
    // Deliberately do not print private key packages or signing secrets.
    println!("PASS: DKG completed with public descriptor, transcript={:?}",descriptor.dkg_transcript_hash);
    Ok(())
}

#[tokio::main]
async fn main() {
    holochain_mpc_dkg_worker::notice::exit_on_help("mpc-relay-service", "DKG relay service. See docs/V040_RELAY_SERVICE_PHASE4.md.");
    if let Err(e)=run().await {
        eprintln!("FAIL: relay service terminated: {e}");
        eprintln!("The affected proposal must not be resumed after DKG admission.");
        std::process::exit(1);
    }
}
