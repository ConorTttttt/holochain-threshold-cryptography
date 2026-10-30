//! Standalone authenticated loopback app-WebSocket identity probe.
//! This is NOT a zome-calling relay yet. Its return code is an explicit
//! pre-flight identity gate for a future independent MPC conductor bridge.
use holochain_mpc_dkg_worker::conductor_client::authenticate_and_pin;
use holochain_mpc_dkg_worker::connection_policy::{parse_local_app_socket, ConductorPin};
use holochain_mpc_dkg_worker::node_service::{decode_hex_exact, pinned_context};
use std::path::PathBuf;

fn execute_args() -> Result<(PathBuf, std::net::SocketAddr, String, PathBuf, String, String, Vec<u8>), String> {
    let mut args = std::env::args().skip(1);
    let mut state = None;
    let mut addr = None;
    let mut token = None;
    let mut origin = None;
    let mut app_id = None;
    let mut role = "mpc".to_string();
    let mut dna = None;
    while let Some(flag) = args.next() {
        let value = args.next().ok_or("missing command-line option value")?;
        match flag.as_str() {
            "--state-dir" => state = Some(PathBuf::from(value)),
            "--app-socket" => addr = Some(parse_local_app_socket(&value).map_err(str::to_owned)?),
            "--app-token-file" => token = Some(PathBuf::from(value)),
            "--origin" => origin = Some(value),
            "--installed-app-id" => app_id = Some(value),
            "--role" => role = value,
            "--dna-hex" => dna = Some(decode_hex_exact::<39>(&value)
                .map_err(|e| e.to_string())?.to_vec()),
            _ => return Err("unknown argument (try --state-dir --app-socket --origin --app-token-file --installed-app-id --dna-hex)".into()),
        }
    }
    Ok((state.ok_or("missing --state-dir")?, addr.ok_or("missing --app-socket")?,
        origin.ok_or("missing --origin")?, token.ok_or("missing --app-token-file")?, app_id.ok_or("missing --installed-app-id")?,
        role, dna.ok_or("missing --dna-hex")?))
}

#[tokio::main]
async fn main() {
    holochain_mpc_dkg_worker::notice::exit_on_help("mpc-conductor-connect", "Identity preflight against a loopback app interface. See docs/V040_APP_WEBSOCKET_PREFLIGHT.md.");
    let result: Result<(), String> = async {
        let (state, addr, origin, token, app_id, role, dna) = execute_args()?;
        let node = pinned_context(&state).map_err(|e| e.to_string())?;
        let pin = ConductorPin { app_id, role, dna_hash: dna, node };
        authenticate_and_pin(addr, &origin, &token, &pin).await?;
        println!("PASS: authenticated local Holochain app and exact pinned MPC cell");
        Ok(())
    }.await;
    if let Err(error) = result {
        eprintln!("FAIL: {error}");
        std::process::exit(1);
    }
}
