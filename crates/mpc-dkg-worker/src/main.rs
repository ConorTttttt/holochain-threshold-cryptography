//! Test-only MAC-authenticated stdio worker with optional encrypted, non-resumable DKG journal. NOT a production conductor RPC.
use holochain_mpc_dkg_worker::{AuthenticatedController, Command};
use holochain_mpc_dkg_worker::ipc::{AuthFrame, TestBootstrap};
use holochain_mpc_runtime::MasterKey;
use std::io::{self, BufRead, Write};
use zeroize::Zeroize;

const MAX_LINE: usize = 512 * 1024;
fn main() {
    holochain_mpc_dkg_worker::notice::exit_on_help("mpc-dkg-worker", "Test-only stdio worker; requires --test-authenticated-stdio. See docs/V036_AUTHENTICATED_NODE_IPC.md.");
    // Fail closed: there is no unauthenticated CLI fallback in v0.3.6.
    if std::env::args().nth(1).as_deref() != Some("--test-authenticated-stdio") {
        eprintln!("worker requires --test-authenticated-stdio (not for production)");
        std::process::exit(2);
    }
    authenticated_main();
}

fn authenticated_main() {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut line = String::new();
    if input.read_line(&mut line).is_err() || line.len() > MAX_LINE {
        eprintln!("invalid test-only IPC bootstrap"); std::process::exit(2);
    }
    let mut bootstrap: TestBootstrap = match serde_json::from_str(&line) {
        Ok(b) => b,
        Err(_) => { eprintln!("invalid bootstrap encoding"); std::process::exit(2); }
    };
    // Erase cleartext bootstrap material after the authenticated channel owns
    // its separate key copy. The original channel key is zeroized on drop.
    let result = match bootstrap.persistence.take() {
        Some(p) if p.master_key != [0;32] => AuthenticatedController::new_durable(
            bootstrap.secret, bootstrap.context.clone(),
            &p.database_path, MasterKey::from_bytes(p.master_key)),
        Some(_) => Err("missing external database encryption key".into()),
        None => AuthenticatedController::new(bootstrap.secret, bootstrap.context.clone()),
    };
    bootstrap.secret.zeroize();
    line.zeroize();
    let mut controller = match result {
        Ok(c) => c,
        Err(_) => { eprintln!("invalid bootstrap context"); std::process::exit(2); }
    };
    let mut stdout = io::stdout().lock();
    for line in input.lines() {
        let line = match line { Ok(line) if line.len() <= MAX_LINE => line, _ => break };
        let frame: AuthFrame<Command> = match serde_json::from_str(&line) {
            Ok(f) => f, Err(_) => { eprintln!("malformed authenticated IPC frame"); std::process::exit(1); }
        };
        let reply = match controller.handle(frame) {
            Ok(r) => r,
            Err(_) => { eprintln!("unauthorized or invalid IPC command; aborted"); std::process::exit(1); }
        };
        if serde_json::to_writer(&mut stdout, &reply).is_err() ||
           stdout.write_all(b"\n").is_err() || stdout.flush().is_err() {
            std::process::exit(2);
        }
    }
}
