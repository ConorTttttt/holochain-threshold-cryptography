//! Disposable demonstration worker. stdio is NOT an authenticated production RPC.
use holochain_mpc_dkg_worker::{Command, Controller, Reply};
use std::io::{self, BufRead, Write};

const MAX_LINE: usize = 512 * 1024;
fn main() {
    // Explicitly opt in to the testing-only trust boundary.
    if std::env::args().nth(1).as_deref() != Some("--unsafe-test-stdio") {
        eprintln!("experimental MPC worker: --unsafe-test-stdio is required; NOT FOR PRODUCTION");
        std::process::exit(2);
    }
    let stdin = io::stdin();
    let mut controller = Controller::default();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = match line { Ok(line) => line, Err(_) => break };
        if line.len() > MAX_LINE { eprintln!("IPC frame too large"); std::process::exit(2); }
        let result = serde_json::from_str::<Command>(&line)
            .map_err(|_| "invalid command encoding".to_string())
            .and_then(|command| controller.handle(command));
        let terminate = result.is_err();
        let reply = result.unwrap_or_else(|reason| Reply::Error { reason });
        // Reply contains public data / ciphertext only, no FROST secret shares.
        if serde_json::to_writer(&mut stdout, &reply).is_err() ||
           stdout.write_all(b"\n").is_err() || stdout.flush().is_err() {
            std::process::exit(2);
        }
        if terminate { std::process::exit(1); }
    }
}
