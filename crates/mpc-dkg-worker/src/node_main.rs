//! Separate experimental local MPC service: one process per node per DKG proposal.
use holochain_mpc_dkg_worker::ipc::ChannelContext;
use holochain_mpc_dkg_worker::node_service::{decode_hex_exact, provision, serve, transport_public_key};
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
        // Independent of FROST DKG. Creates transport.sqlite exclusively, not
        // journal.sqlite. Never start the non-resumable worker for this action.
        Some("transport-key-create") if args.len() == 5 &&
            args[4] == "--confirm-local-key-write" => {
            let dna = decode_hex_exact::<39>(&args[3]).map_err(|e| e.to_string())?;
            let public = transport_public_key(&PathBuf::from(&args[2]), dna, true)
                .map_err(|e| e.to_string())?;
            let public_hex: String = public.iter().map(|b| format!("{b:02x}")).collect();
            println!("PASS: durable transport key created; public_key_hex={public_hex}");
            Ok(())
        }
        // Recovery does NOT generate a replacement. SQLite may perform
        // internal WAL/schema housekeeping; it never starts FROST DKG.
        Some("transport-key-public") if args.len() == 4 => {
            let dna = decode_hex_exact::<39>(&args[3]).map_err(|e| e.to_string())?;
            let public = transport_public_key(&PathBuf::from(&args[2]), dna, false)
                .map_err(|e| e.to_string())?;
            let public_hex: String = public.iter().map(|b| format!("{b:02x}")).collect();
            println!("PASS: durable transport key recovered; public_key_hex={public_hex}");
            Ok(())
        }
        _ => Err("usage: mpc-node provision <absolute-empty-dir> <agent-hex-39B> <proposal-hex-39B> <session-hex-32B> | mpc-node serve <absolute-dir> | mpc-node transport-key-create <absolute-node-dir> <dna-hex-39B> --confirm-local-key-write | mpc-node transport-key-public <absolute-node-dir> <dna-hex-39B>".into()),
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("mpc-node: {error}");
        std::process::exit(1);
    }
}
