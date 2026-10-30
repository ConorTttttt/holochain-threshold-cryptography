//! Phase 5B: read-only end-to-end proof of a Lair signer + real Holochain app
//! interface. This deliberately NEVER starts DKG or submits a chain write.
//! A PASS requires an actual conductor to accept one freshly signed zome call.
use holochain_mpc_dkg_worker::conductor_client::{authenticate_and_pin, submit_signed_mpc_call, MpcZomeResult};
use holochain_mpc_dkg_worker::connection_policy::{parse_local_app_socket, ConductorPin};
use holochain_mpc_dkg_worker::node_service::{decode_hex_exact, pinned_context};
use holochain_mpc_dkg_worker::signed_call_policy::MpcCall;
use holochain_mpc_dkg_worker::signed_relay::{FreshMpcSigner, SignIntent};
use holochain_mpc_dkg_worker::socket_signer::UnixMpcSigner;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

const RPC_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReadOperation { Inbox, EncryptionKeys }
impl ReadOperation {
    fn parse(name: &str) -> Result<Self, String> {
        match name {
            "get-inbox" => Ok(Self::Inbox),
            "get-encryption-key-bindings" => Ok(Self::EncryptionKeys),
            _ => Err("Phase 5B probe allows read-only operations only".into()),
        }
    }
    fn call(self) -> MpcCall {
        match self {
            Self::Inbox => MpcCall::GetInbox,
            Self::EncryptionKeys => MpcCall::GetEncryptionKeyBindings,
        }
    }
    fn intent(self) -> SignIntent<'static> {
        match self {
            Self::Inbox => SignIntent::ReadInbox,
            Self::EncryptionKeys => SignIntent::ReadEncryptionKeys,
        }
    }
}

struct Options {
    state: PathBuf,
    app_socket: SocketAddr,
    origin: String,
    app_token: PathBuf,
    installed_app_id: String,
    dna: Vec<u8>,
    signer_socket: PathBuf,
    operation: ReadOperation,
}

fn parse_args() -> Result<Options, String> {
    let mut state=None;
    let mut app_socket=None;
    let mut origin=None;
    let mut app_token=None;
    let mut installed_app_id=None;
    let mut dna=None;
    let mut signer_socket=None;
    let mut operation=None;
    let mut args=std::env::args().skip(1);
    while let Some(flag)=args.next() {
        let value=args.next().ok_or("missing option value")?;
        match flag.as_str() {
            "--state-dir" => state=Some(PathBuf::from(value)),
            "--app-socket" => app_socket=Some(parse_local_app_socket(&value).map_err(str::to_owned)?),
            "--origin" => origin=Some(value),
            "--app-token-file" => app_token=Some(PathBuf::from(value)),
            "--installed-app-id" => installed_app_id=Some(value),
            "--dna-hex" => dna=Some(decode_hex_exact::<39>(&value)
                .map_err(|_|"DNA hash must be 39 bytes of hex")?.to_vec()),
            "--signer-socket" => signer_socket=Some(PathBuf::from(value)),
            "--operation" => operation=Some(ReadOperation::parse(&value)?),
            _ => return Err("unknown live-probe option".into()),
        }
    }
    Ok(Options {
        state:state.ok_or("missing --state-dir")?,
        app_socket:app_socket.ok_or("missing --app-socket")?,
        origin:origin.ok_or("missing --origin")?,
        app_token:app_token.ok_or("missing --app-token-file")?,
        installed_app_id:installed_app_id.ok_or("missing --installed-app-id")?,
        dna:dna.ok_or("missing --dna-hex")?,
        signer_socket:signer_socket.ok_or("missing --signer-socket")?,
        operation:operation.ok_or("missing --operation")?,
    })
}

async fn run() -> Result<(),String> {
    let args=parse_args()?;
    let node=pinned_context(&args.state).map_err(|_|"private node state pin unavailable")?;
    let pin=ConductorPin {app_id:args.installed_app_id,role:"mpc".to_owned(),
        dna_hash:args.dna,node};
    // Verify a private local signer endpoint, and the real app cell identity,
    // BEFORE asking Lair for a signature. No MPC worker is started here.
    let mut signer=UnixMpcSigner::new(args.signer_socket,pin.clone())?;
    signer.probe().await?;
    tokio::time::timeout(RPC_DEADLINE,
        authenticate_and_pin(args.app_socket,&args.origin,&args.app_token,&pin))
        .await.map_err(|_|"conductor preflight timed out")??;
    // A FRESH signed call per invocation. No reusable signatures or retries.
    let signed=signer.sign(args.operation.intent()).await?;
    let result=tokio::time::timeout(RPC_DEADLINE,
        submit_signed_mpc_call(args.app_socket,&args.origin,&args.app_token,
            &pin,args.operation.call(),signed))
        .await.map_err(|_|"conductor signed read timed out (do not replay call)")??;
    match (args.operation,result) {
        (ReadOperation::Inbox,MpcZomeResult::Inbox(messages)) =>
            println!("PASS: Lair-signed Holochain inbox read accepted ({} envelopes)",messages.len()),
        (ReadOperation::EncryptionKeys,MpcZomeResult::EncryptionKeys(keys)) =>
            println!("PASS: Lair-signed Holochain key read accepted ({} bindings)",keys.len()),
        _ => return Err("conductor replied with the wrong MPC result type".into()),
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    holochain_mpc_dkg_worker::notice::exit_on_help("mpc-lair-live-probe", "Read-only Lair and conductor probe. See docs/V040_LAIR_LIVE_PROBE_PHASE5B.md.");
    if let Err(message)=run().await {
        // No request bodies, private capabilities, signer signatures or
        // Lair errors are logged by the probe.
        eprintln!("FAIL: live signer probe: {message}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permits_only_two_read_calls() {
        assert_eq!(ReadOperation::parse("get-inbox").unwrap(),ReadOperation::Inbox);
        assert_eq!(ReadOperation::parse("get-encryption-key-bindings").unwrap(),ReadOperation::EncryptionKeys);
        for refused in ["send-protocol-message","register-encryption-key","prepare-inbox-grant",
                        "propose-session","","get_inbox","GetInbox"] {
            assert!(ReadOperation::parse(refused).is_err(),"accepted forbidden probe operation: {refused}");
        }
    }
    #[test]
    fn read_calls_map_to_expected_zome_functions() {
        assert_eq!(ReadOperation::Inbox.call().name(),"get_inbox");
        assert_eq!(ReadOperation::EncryptionKeys.call().name(),"get_encryption_key_bindings");
    }
}
