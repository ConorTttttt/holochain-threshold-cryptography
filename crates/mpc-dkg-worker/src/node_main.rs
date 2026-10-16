//! Separate experimental local MPC service: one process per node per DKG proposal.
use holochain_mpc_dkg_worker::ipc::ChannelContext;
use holochain_mpc_dkg_worker::node_service::{decode_hex_exact, provision, serve};
use std::path::PathBuf;
use std::fs::File;
use std::io::Read;

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("provision") if args.len() == 6 => {
            let dir = PathBuf::from(&args[2]);
            let agent = decode_hex_exact::<39>(&args[3]).map_err(|e| e.to_string())?;
            let proposal = decode_hex_exact::<39>(&args[4]).map_err(|e| e.to_string())?;
            let session = decode_hex_exact::<32>(&args[5]).map_err(|e| e.to_string())?;
            let mut channel = [0_u8; 32];
            File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut channel))
                .map_err(|e| e.to_string())?;
            provision(&dir, ChannelContext { worker_agent: agent.to_vec(),
                proposal_action: proposal.to_vec(), session_id: session, channel_id: channel })
                .map_err(|e| e.to_string())?;
            println!("private node directory provisioned; review the pinned Holochain identity before use");
            Ok(())
        }
        Some("serve") if args.len() == 3 => {
            serve(&PathBuf::from(&args[2])).map_err(|e| e.to_string())
        }
        _ => Err("usage: mpc-node provision <absolute-empty-dir> <agent-hex-39B> <proposal-hex-39B> <session-hex-32B> | mpc-node serve <absolute-dir>".into()),
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("mpc-node: {error}");
        std::process::exit(1);
    }
}
