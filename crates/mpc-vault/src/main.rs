//! `mpc-vault`: serve | demo | gen-token | solana-setup.
//! DEVELOPMENT BUILD. DEVNET ONLY. NOT PRODUCTION CUSTODY.
use ed25519_dalek::SigningKey;
use holochain_mpc_vault::api::{router, Api};
use holochain_mpc_vault::chain::Chain;
use holochain_mpc_vault::cli_node::CliNode;
use holochain_mpc_vault::config::*;
use holochain_mpc_vault::engine::{Engine, EngineConfig, BANNER};
use holochain_mpc_vault::node::Node;
use holochain_mpc_vault::solana::{self, Rpc, Solana, DEVNET_RPC};
use holochain_mpc_vault::store::Store;
use holochain_mpc_vault::util::{hex, SystemClock};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "usage:\n  mpc-vault serve --config <file>\n  mpc-vault demo --listen <127.0.0.1:port> --token-file <file> --data-dir <dir> [--ui-dir <dir>]\n  mpc-vault gen-token <file>\n  mpc-vault solana-funder --funder-key-file <file>\n  mpc-vault solana-setup --config <file> --funder-key-file <file> --fund-lamports <n> [--nonce] [--wait-funding-secs <n>] [--try-airdrop]";

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn load_config(path: &str) -> Result<Config, String> {
    let raw = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    serde_json::from_slice(&raw).map_err(|e| format!("invalid config: {e}"))
}

fn solana_chain(cfg: &Config) -> Result<Solana, String> {
    let sol = cfg.solana.clone().unwrap_or(SolanaConfig { rpc_url: None, nonce_account: None });
    let url = sol.rpc_url.unwrap_or_else(|| DEVNET_RPC.to_owned());
    check_rpc(&url)?;
    Ok(Solana::new(&url, sol.nonce_account))
}

async fn serve_api(listen: &str, token: Vec<u8>, engine: Engine, ui_dir: Option<PathBuf>) -> Result<(), String> {
    let addr = listen_addr(listen)?;
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let ticker = engine.clone();
    tokio::spawn(async move { loop { tokio::time::sleep(Duration::from_secs(5)).await; ticker.tick(); } });
    let api = Arc::new(Api { engine, token, port, ui_dir });
    println!("mpc-vault listening on http://127.0.0.1:{port}  ({BANNER})");
    axum::serve(listener, router(api)).with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; })
        .await.map_err(|e| e.to_string())
}

fn serve(args: &[String]) -> Result<(), String> {
    let cfg = load_config(&flag(args, "--config").ok_or(USAGE)?)?;
    let token = read_token(&cfg.token_file)?;
    listen_addr(&cfg.listen)?;
    let node: Arc<dyn Node> = Arc::new(CliNode::new(cfg.node.clone())?);
    let chain: Arc<dyn Chain> = Arc::new(solana_chain(&cfg)?);
    let engine_cfg = EngineConfig { auto_broadcast: cfg.auto_broadcast.unwrap_or(true),
        default_expiry_secs: cfg.default_expiry_secs.unwrap_or(86_400), ..EngineConfig::default() };
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let engine = Engine::open(Store::open(&cfg.data_dir)?, vec![chain], node, Arc::new(SystemClock), engine_cfg)?;
        serve_api(&cfg.listen, token, engine, cfg.ui_dir.clone()).await
    })
}

fn demo(args: &[String]) -> Result<(), String> {
    let listen = flag(args, "--listen").ok_or(USAGE)?;
    let token = read_token(Path::new(&flag(args, "--token-file").ok_or(USAGE)?))?;
    let data_dir = PathBuf::from(flag(args, "--data-dir").ok_or(USAGE)?);
    let ui_dir = flag(args, "--ui-dir").map(PathBuf::from);
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        println!("DEMO MODE: mock chain, simulated group and a simulated second operator. All data is EXAMPLE data.");
        let d = holochain_mpc_vault::demo::start(&data_dir, Arc::new(SystemClock), Duration::from_secs(4)).await?;
        serve_api(&listen, token, d.engine, ui_dir).await
    })
}

/// Load (or create, 0600) a THROWAWAY devnet funder key. Never use a key that holds real funds.
fn funder_key(path: &Path) -> Result<SigningKey, String> {
    if !path.is_absolute() { return Err("--funder-key-file must be an absolute path".into()); }
    let seed: [u8; 32] = match std::fs::read_to_string(path) {
        Ok(s) => holochain_mpc_vault::util::unhex_exact(s.trim()).ok_or("funder key file is corrupt")?,
        Err(_) => {
            let mut seed = [0_u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
            use std::io::Write;
            std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
                .and_then(|mut f| f.write_all(hex(&seed).as_bytes())).map_err(|e| format!("cannot create the funder key: {e}"))?;
            seed
        }
    };
    Ok(SigningKey::from_bytes(&seed))
}

/// Wait for the funder to hold `need` lamports. The devnet RPC faucet is closed, so a person
/// funds the printed address from https://faucet.solana.com (devnet); `try_airdrop` stays for
/// the day the RPC faucet reopens.
fn ensure_funded(rpc: &Rpc, chain: &Solana, addr: &str, need: u64, wait_secs: u64, try_airdrop: bool) -> Result<(), String> {
    let have = rpc.balance(addr)?;
    if have >= need { return Ok(()); }
    if try_airdrop {
        match solana::request_airdrop(rpc, addr, need - have).and_then(|sig| solana::wait_confirmed(chain, &sig, 90)) {
            Ok(()) => return Ok(()),
            Err(e) => eprintln!("airdrop not available ({e})"),
        }
    }
    println!("FUND THIS DEVNET ADDRESS with at least {need} lamports (0.1 SOL is plenty): {addr}\n  web faucet: https://faucet.solana.com  (network: devnet; throwaway key, no real value)");
    let end = std::time::Instant::now() + Duration::from_secs(wait_secs);
    while std::time::Instant::now() < end {
        std::thread::sleep(Duration::from_secs(10));
        if rpc.balance(addr).unwrap_or(0) >= need { println!("funder funded"); return Ok(()); }
    }
    Err(format!("the funder {addr} holds less than {need} lamports; fund it and run this again"))
}

/// `solana-funder`: create the throwaway funder key if missing and print its address.
fn solana_funder(args: &[String]) -> Result<(), String> {
    let key = funder_key(Path::new(&flag(args, "--funder-key-file").ok_or(USAGE)?))?;
    println!("funder={}", solana::address(&key.verifying_key().to_bytes()));
    Ok(())
}

/// Fund the vault address and create a durable nonce account it controls, using a
/// THROWAWAY devnet funder key. Never use real funds.
fn solana_setup(args: &[String]) -> Result<(), String> {
    let cfg = load_config(&flag(args, "--config").ok_or(USAGE)?)?;
    let fund: u64 = flag(args, "--fund-lamports").ok_or(USAGE)?.parse().map_err(|_| "invalid --fund-lamports")?;
    let wait: u64 = flag(args, "--wait-funding-secs").map_or(Ok(0), |v| v.parse()).map_err(|_| "invalid --wait-funding-secs")?;
    let want_nonce = args.iter().any(|a| a == "--nonce");
    let url = cfg.solana.as_ref().and_then(|s| s.rpc_url.clone()).unwrap_or_else(|| DEVNET_RPC.to_owned());
    check_rpc(&url)?;
    let chain = Solana::new(&url, None);
    let rpc = Rpc::new(&url);
    let group = CliNode::new(cfg.node.clone())?.group().map_err(|e| e.0)?;
    let vault_addr = solana::address(&group.group_key);
    let funder = funder_key(Path::new(&flag(args, "--funder-key-file").ok_or(USAGE)?))?;
    let funder_addr = solana::address(&funder.verifying_key().to_bytes());
    println!("THROWAWAY devnet funder: {funder_addr}\nvault address:           {vault_addr}");
    let need = fund + if want_nonce { 1_600_000 } else { 0 } + 50_000;
    ensure_funded(&rpc, &chain, &funder_addr, need, wait, args.iter().any(|a| a == "--try-airdrop"))?;
    let sig = solana::fund(&rpc, &funder, group.group_key, fund)?;
    solana::wait_confirmed(&chain, &sig, 90)?;
    println!("funded the vault with {fund} lamports (tx {sig})");
    if want_nonce {
        let mut nseed = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nseed);
        let nonce = SigningKey::from_bytes(&nseed);
        let sig = solana::create_nonce_account(&rpc, &funder, &nonce, group.group_key)?;
        solana::wait_confirmed(&chain, &sig, 90)?;
        let n = solana::address(&nonce.verifying_key().to_bytes());
        println!("nonce_account={n}\nadd it to the config:  \"solana\": {{ \"nonce_account\": \"{n}\" }}");
    }
    println!("vault balance now {} lamports", rpc.balance(&vault_addr)?);
    Ok(())
}

/// The repository-wide non-production notice, word for word as in
/// `holochain_mpc_dkg_worker::notice::NOTICE` (this crate does not depend on the
/// worker). `scripts/release_check.py` asserts the exact text for every binary.
const NOTICE: &str = "NOT PRODUCTION SOFTWARE. EXPERIMENTAL, UNAUDITED DEVELOPMENT SOURCE.\n\
Do not use it with real keys, funds, identities or secret shares. Custody is\n\
development-grade and no independent audit has been done (see SECURITY.md).";
const CUSTODY_WARNING: &str = "Development build. Not production custody. Do not use with real funds.";

fn main() {
    // `--help`/`-h` first: print the notice and exit 0 before reading any config,
    // key file or network. Every other invocation is unchanged.
    if matches!(std::env::args().nth(1).as_deref(), Some("--help" | "-h")) {
        print!("mpc-vault\n\n{NOTICE}\n\n{CUSTODY_WARNING} Devnet only.\n\n{USAGE}\n");
        std::process::exit(0);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or_default();
    let result = match args.first().map(String::as_str) {
        Some("serve") => serve(rest),
        Some("demo") => demo(rest),
        Some("gen-token") => rest.first().ok_or_else(|| USAGE.to_owned()).and_then(|p| gen_token(Path::new(p))),
        Some("solana-setup") => solana_setup(rest),
        Some("solana-funder") => solana_funder(rest),
        _ => Err(USAGE.to_owned()),
    };
    if let Err(e) = result {
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
}
