//! v0.4.0 Phase 8 signing service: one approved operation on one node.
//!
//! Reopens this node's sealed FROST share (verified against its journal),
//! waits until every member has attested the group and every selected signer
//! has approved the plan, then exchanges commitments and shares with the
//! other selected signers, aggregates, verifies and publishes the result.
//! Every Holochain call is signed by a separately running
//! `mpc-lair-signer --signing-profile` pinned to the same plan.
//! A failed run is terminal for its operation id: approve a NEW plan instead.
use holochain_mpc_dkg_worker::conductor_client::authenticate_and_pin;
use holochain_mpc_dkg_worker::connection_policy::{parse_local_app_socket, ConductorPin};
use holochain_mpc_dkg_worker::node_service::{decode_hex_exact, recover_share};
use holochain_mpc_dkg_worker::probe_signer::read_private_json;
use holochain_mpc_dkg_worker::signed_relay::SignedAppTransport;
use holochain_mpc_dkg_worker::signing::{run_signing, signed_message, SigningPlan, SigningPoll};
use holochain_mpc_dkg_worker::socket_signer::UnixMpcSigner;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

struct Options {
    state: PathBuf, plan: PathBuf, socket: SocketAddr, origin: String, token: PathBuf,
    app_id: String, dna: Vec<u8>, signer: PathBuf, interval_ms: u64, max_polls: u32, out: PathBuf,
}

fn cli() -> Result<Options, String> {
    let (mut state, mut plan, mut socket, mut origin, mut token, mut app_id, mut dna, mut signer, mut out) =
        (None, None, None, None, None, None, None, None, None);
    let (mut interval_ms, mut max_polls) = (1000_u64, 600_u32);
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let val = args.next().ok_or("missing option value")?;
        match flag.as_str() {
            "--state-dir" => state = Some(PathBuf::from(val)),
            "--plan-file" => plan = Some(PathBuf::from(val)),
            "--app-socket" => socket = Some(parse_local_app_socket(&val).map_err(str::to_owned)?),
            "--origin" => origin = Some(val),
            "--app-token-file" => token = Some(PathBuf::from(val)),
            "--installed-app-id" => app_id = Some(val),
            "--dna-hex" => dna = Some(decode_hex_exact::<39>(&val).map_err(|e| e.to_string())?.to_vec()),
            "--signer-socket" => signer = Some(PathBuf::from(val)),
            "--out-dir" => out = Some(PathBuf::from(val)),
            "--poll-ms" => interval_ms = val.parse().map_err(|_| "invalid poll interval")?,
            "--max-polls" => max_polls = val.parse().map_err(|_| "invalid poll budget")?,
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    if !(100..=60_000).contains(&interval_ms) || !(1..=10_000).contains(&max_polls) {
        return Err("poll interval must be 100..60000 ms and budget 1..10000 polls".into());
    }
    Ok(Options { state: state.ok_or("missing --state-dir")?, plan: plan.ok_or("missing --plan-file")?,
        socket: socket.ok_or("missing --app-socket")?, origin: origin.ok_or("missing --origin")?,
        token: token.ok_or("missing --app-token-file")?, app_id: app_id.ok_or("missing --installed-app-id")?,
        dna: dna.ok_or("missing --dna-hex")?, signer: signer.ok_or("missing --signer-socket")?,
        interval_ms, max_polls, out: out.ok_or("missing --out-dir")? })
}

/// Public outputs only: never overwrite, and keep them in an owned 0700 directory.
fn write_new(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let info = std::fs::symlink_metadata(dir).map_err(|_| "output directory missing")?;
    if !dir.is_absolute() || !info.is_dir() || info.file_type().is_symlink() ||
       info.uid() != unsafe { libc::geteuid() } || info.permissions().mode() & 0o777 != 0o700 {
        return Err("--out-dir must be an absolute, owned 0700 directory".into());
    }
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(dir.join(name))
        .map_err(|_| format!("cannot create {name} (it must not already exist)"))?;
    file.write_all(bytes).and_then(|_| file.sync_all()).map_err(|_| format!("cannot write {name}"))
}

async fn run() -> Result<(), String> {
    let opts = cli()?;
    let plan: SigningPlan = read_private_json(&opts.plan)?;
    plan.validate()?;
    let (context, mut store, custody) = recover_share(&opts.state, &plan.descriptor)
        .map_err(|e| format!("cannot reopen this node's share: {e}"))?;
    let pin = ConductorPin { app_id: opts.app_id, role: "mpc".into(), dna_hash: opts.dna, node: context.clone() };
    // All preflight checks happen before any nonce is reserved.
    let signer = UnixMpcSigner::new(opts.signer, pin.clone())?;
    signer.probe().await?;
    authenticate_and_pin(opts.socket, &opts.origin, &opts.token, &pin).await?;
    let mut transport = SignedAppTransport { addr: opts.socket, origin: opts.origin, token_file: opts.token, pin, signer };
    let artifact = run_signing(&mut transport, &mut store, custody, &context.worker_agent, plan.clone(),
        SigningPoll { interval: Duration::from_millis(opts.interval_ms), max_polls: opts.max_polls }).await?;
    write_new(&opts.out, "artifact.json", &serde_json::to_vec_pretty(&artifact).map_err(|e| e.to_string())?)?;
    write_new(&opts.out, "signature.bin", &artifact.signature)?;
    write_new(&opts.out, "group-public-key.bin", &artifact.public_key)?;
    write_new(&opts.out, "signed-message.bin", &signed_message(&plan)?)?;
    println!("PASS: approved threshold signature produced, verified and published; signature={}",
        artifact.signature.iter().map(|b| format!("{b:02x}")).collect::<String>());
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("FAIL: signing service terminated: {e}");
        eprintln!("This operation id must not be retried; approve a new signing plan.");
        std::process::exit(1);
    }
}
