//! Opt-in proof-of-interface for pre-signed MPC zome calls. A trusted agent
//! signer must produce a JSON-serialized ZomeCallParamsSigned; this binary
//! never creates an agent key, signs on behalf of the agent or mints grants.
//! Not a production automatic relay.
use holochain_conductor_api::ZomeCallParamsSigned;
use holochain_mpc_dkg_worker::conductor_client::{submit_signed_mpc_call, MpcZomeResult};
use holochain_mpc_dkg_worker::connection_policy::{parse_local_app_socket, ConductorPin};
use holochain_mpc_dkg_worker::node_service::{decode_hex_exact, pinned_context};
use holochain_mpc_dkg_worker::signed_call_policy::MpcCall;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

struct Args {
    state: PathBuf, addr: SocketAddr, origin: String, token: PathBuf,
    app_id: String, role: String, dna: Vec<u8>,
    call: PathBuf, operation: MpcCall,
}
fn args() -> Result<Args, String> {
    let mut items = std::env::args().skip(1);
    let mut state = None;
    let mut addr = None;
    let mut origin = None;
    let mut token = None;
    let mut app_id = None;
    let mut role = "mpc".to_string();
    let mut dna = None;
    let mut call = None;
    let mut operation = None;
    while let Some(flag) = items.next() {
        let val = items.next().ok_or("missing command-line argument value")?;
        match flag.as_str() {
            "--state-dir" => state = Some(PathBuf::from(val)),
            "--app-socket" => addr = Some(parse_local_app_socket(&val).map_err(str::to_owned)?),
            "--origin" => origin = Some(val),
            "--app-token-file" => token = Some(PathBuf::from(val)),
            "--installed-app-id" => app_id = Some(val),
            "--role" => role = val,
            "--dna-hex" => dna = Some(decode_hex_exact::<39>(&val)
                .map_err(|e| e.to_string())?.to_vec()),
            "--signed-call-file" => call = Some(PathBuf::from(val)),
            "--operation" => operation = Some(match val.as_str() {
                "get-inbox" => MpcCall::GetInbox,
                "get-encryption-key-bindings" => MpcCall::GetEncryptionKeyBindings,
                "register-encryption-key" => MpcCall::RegisterEncryptionKey,
                "send-protocol-message" => MpcCall::SendProtocolMessage,
                _ => return Err("operation not in MPC zome allowlist".into()),
            }),
            _ => return Err("unknown signed conductor-call argument".into()),
        }
    }
    Ok(Args {
        state: state.ok_or("missing --state-dir")?,
        addr: addr.ok_or("missing --app-socket")?,
        origin: origin.ok_or("missing --origin")?,
        token: token.ok_or("missing --app-token-file")?,
        app_id: app_id.ok_or("missing --installed-app-id")?,
        role, dna: dna.ok_or("missing --dna-hex")?,
        call: call.ok_or("missing --signed-call-file")?,
        operation: operation.ok_or("missing --operation")?,
    })
}

fn read_signed(path: &Path) -> Result<ZomeCallParamsSigned, String> {
    let before = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !before.is_file() || before.file_type().is_symlink() ||
        before.permissions().mode() & 0o777 != 0o600 ||
        before.uid() != unsafe { libc::geteuid() } || before.nlink() != 1 ||
        before.len() == 0 || before.len() > 512 * 1024 {
        return Err("signed-call input must be one private 0600 file".into());
    }
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW)
        .open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if before.dev() != opened.dev() || before.ino() != opened.ino() ||
       before.len() != opened.len() || before.mode() != opened.mode() {
        return Err("signed-call input was replaced while opening".into());
    }
    let mut data = Vec::with_capacity(before.len() as usize);
    file.take(512 * 1024 + 1).read_to_end(&mut data).map_err(|e| e.to_string())?;
    if data.len() != before.len() as usize {
        return Err("signed-call file size changed".into());
    }
    serde_json::from_slice(&data).map_err(|_| "invalid signed-call JSON".into())
}

#[tokio::main]
async fn main() {
    holochain_mpc_dkg_worker::notice::exit_on_help("mpc-conductor-call", "Signed zome call through a loopback app interface. See docs/V040_SIGNED_ZOME_CALLS_PHASE2.md.");
    let result: Result<(), String> = async {
        let options = args()?;
        let node = pinned_context(&options.state).map_err(|e| e.to_string())?;
        let pin = ConductorPin {
            app_id: options.app_id, role: options.role,
            dna_hash: options.dna, node,
        };
        let signed = read_signed(&options.call)?;
        let result = submit_signed_mpc_call(options.addr, &options.origin,
            &options.token, &pin, options.operation, signed).await?;
        match result {
            MpcZomeResult::ProbeSession { .. } => return Err("probe status requires dedicated probe CLI".into()),
            MpcZomeResult::Inbox(inbox) => println!("PASS: authorised inbox returned {} envelopes", inbox.len()),
            MpcZomeResult::EncryptionKeys(keys) => println!("PASS: authorised lookup returned {} key bindings", keys.len()),
            MpcZomeResult::KeyRegistration { .. } => println!("PASS: own encryption key registered"),
            MpcZomeResult::DeliveryReceipt { already_stored, .. } =>
                println!("PASS: signed delivery acknowledged (already_stored={already_stored})"),
            MpcZomeResult::ActivationAttestations(_) | MpcZomeResult::SigningApprovals(_) |
            MpcZomeResult::ResultCommitment { .. } =>
                return Err("signing-phase calls require the mpc-sign service".into()),
        };
        Ok(())
    }.await;
    if let Err(e) = result {
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
}
