//! Phase 5B operator bootstrap. Each subcommand does ONE narrowly scoped thing:
//!
//! * `decode-hash`    — validated Holochain base64 -> raw 39-byte hex (read-only).
//! * `write-policy`   — derive a `"recipients": []` signer policy from a
//!                      provisioned node directory (local file only).
//! * `issue-app-token`— ADMIN write: ask the local conductor for an app token
//!                      and store it raw in a new 0600 file. Never printed.
//! * `check-app-interfaces` — ADMIN read: list the conductor's app interfaces and
//!                      fail if any allows any origin or is not bound to an app
//!                      (risk R7). Changes nothing.
//! * `attach-app-interface` — ADMIN write: attach ONE new app interface bound to
//!                      one installed app and to the single origin
//!                      `http://localhost:<port>`. Never `*`, never unbound.
//! * `propose-session`— SOURCE-CHAIN write: author ONE single-participant
//!                      read-probe `SessionProposal`, signed with the agent's
//!                      existing Lair key. Prints only public identifiers.
//!
//! The write commands refuse to run without an explicit `--confirm-*`
//! flag: that flag is the operator's approval, not a convenience default.
//! Nothing here creates or exports Lair keys, installs apps, grants
//! capabilities, or changes conductor configuration.
use holochain_conductor_api::{
    AdminRequest, AdminResponse, AppAuthenticationRequest, AppRequest, AppResponse, CellInfo,
    IssueAppAuthenticationTokenPayload, ZomeCallParamsSigned,
};
use holochain_keystore::{AgentPubKeyExt, MetaLairClient};
use holochain_mpc_core::SessionSpec;
use holochain_mpc_dkg_worker::lair_signer::{SignerPolicy, SignerPolicyFile};
use holochain_mpc_dkg_worker::node_service::pinned_context;
use holochain_mpc_dkg_worker::socket_signer::SignerBinding;
use holochain_nonce::Nonce256Bits;
use holochain_websocket::{connect, ConnectRequest, WebsocketConfig};
use holochain_zome_types::prelude::{
    ActionHash, ActionHashB64, AgentPubKey, AgentPubKeyB64, CellId, DnaHash, DnaHashB64, ExternIO,
    FunctionName, Timestamp, ZomeCallParams, ZomeName,
};
use lair_keystore_api::dependencies::sodoken;
use lair_keystore_api::ipc_keystore::ipc_keystore_connect;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroize;

const RPC_DEADLINE: Duration = Duration::from_secs(30);
const PROBE_APPLICATION_ID: &str = "org.holochain-mpc.phase5b-read-probe";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Validated decode: checks the `u` multibase prefix, URL-safe base64, the
/// 3-byte hash-type prefix and the 4-byte DHT location checksum.
fn decode_b64(kind: &str, value: &str) -> Result<Vec<u8>, String> {
    let raw = match kind {
        "dna" => DnaHash::from(DnaHashB64::from_b64_str(value).map_err(|_| "not a valid DnaHash")?)
            .get_raw_39().to_vec(),
        "agent" => AgentPubKey::from(AgentPubKeyB64::from_b64_str(value).map_err(|_| "not a valid AgentPubKey")?)
            .get_raw_39().to_vec(),
        "action" => ActionHash::from(ActionHashB64::from_b64_str(value).map_err(|_| "not a valid ActionHash")?)
            .get_raw_39().to_vec(),
        _ => return Err("hash kind must be dna, agent or action".into()),
    };
    Ok(raw)
}

/// Create a NEW 0600 file below an owned 0700 directory. Never overwrites.
fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if !path.is_absolute() { return Err("output path must be absolute".into()); }
    let parent = path.parent().ok_or("output path has no parent")?;
    let info = fs::symlink_metadata(parent).map_err(|_| "output parent directory missing")?;
    if !info.is_dir() || info.file_type().is_symlink() || info.uid() != unsafe { libc::geteuid() } ||
        info.permissions().mode() & 0o777 != 0o700 {
        return Err("output parent must be an owned 0700 directory".into());
    }
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(path)
        .map_err(|_| "cannot create output file (it must not already exist)")?;
    file.write_all(bytes).and_then(|_| file.sync_all()).map_err(|_| "cannot write output file")?;
    Ok(())
}

fn local_addr(port: &str) -> Result<SocketAddr, String> {
    let port: u16 = port.parse().map_err(|_| "invalid port")?;
    if port == 0 { return Err("invalid port".into()); }
    Ok(SocketAddr::from(([127, 0, 0, 1], port)))
}

fn local_origin(origin: &str) -> Result<(), String> {
    let ok = origin.strip_prefix("http://localhost").is_some_and(|part| {
        part.is_empty() || part.strip_prefix(':').is_some_and(|p| p.parse::<u16>().is_ok_and(|n| n != 0))
    });
    if origin.len() > 256 || !ok { return Err("Origin must be http://localhost[:port]".into()); }
    Ok(())
}

/// Minimal `--flag value` parser; every flag is required exactly once.
fn flags(args: &[String], allowed: &[&str]) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut out = std::collections::BTreeMap::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if flag.starts_with("--confirm-") {
            if !allowed.contains(&flag.as_str()) { return Err(format!("unknown option {flag}")); }
            out.insert(flag.clone(), String::new());
            continue;
        }
        let value = it.next().ok_or("missing option value")?;
        if !allowed.contains(&flag.as_str()) || out.insert(flag.clone(), value.clone()).is_some() {
            return Err(format!("unknown or repeated option {flag}"));
        }
    }
    Ok(out)
}

fn need<'a>(m: &'a std::collections::BTreeMap<String, String>, k: &str) -> Result<&'a str, String> {
    m.get(k).map(String::as_str).ok_or_else(|| format!("missing {k}"))
}

/// Construct the ONE spec this tool will propose: the local agent as sole
/// participant, threshold 1. It exists only so read calls have a real,
/// validated proposal to load; it must never be used for a DKG ceremony.
pub fn probe_spec(app_id: &str, dna: &[u8], agent: &[u8], session_id: [u8; 32]) -> Result<SessionSpec, String> {
    let description = format!("holochain-mpc-core/phase5b/read-probe/v1|app={app_id}|dna={}|agent={}|session={}",
        hex(dna), hex(agent), hex(&session_id));
    let spec = SessionSpec {
        session_id,
        application_id: PROBE_APPLICATION_ID.into(),
        protocol_id: "frost-ed25519".into(),
        protocol_version: 1,
        context_hash: holochain_mpc_core::commitment("phase5b-read-probe-context", description.as_bytes()),
        participants: vec![agent.to_vec()],
        threshold: 1,
        max_round: 6,
    };
    spec.validate().map_err(|e| format!("probe spec invalid: {e}"))?;
    if AgentPubKey::try_from_raw_39(agent.to_vec()).is_err() { return Err("invalid agent".into()); }
    Ok(spec)
}

async fn issue_app_token(args: &[String]) -> Result<(), String> {
    let m = flags(args, &["--admin-port", "--installed-app-id", "--out", "--expiry-seconds",
        "--confirm-admin-token-issue"])?;
    if !m.contains_key("--confirm-admin-token-issue") {
        return Err("refusing: pass --confirm-admin-token-issue to approve issuing an app token".into());
    }
    let addr = local_addr(need(&m, "--admin-port")?)?;
    let app = need(&m, "--installed-app-id")?.to_owned();
    let out = Path::new(need(&m, "--out")?);
    let expiry: u64 = need(&m, "--expiry-seconds")?.parse().map_err(|_| "invalid expiry")?;
    if expiry == 0 || expiry > 24 * 3600 {
        return Err("--expiry-seconds must be 1..=86400 (non-expiring tokens are refused)".into());
    }
    // Fail before contacting the conductor if the output cannot be created.
    if fs::symlink_metadata(out).is_ok() { return Err("token output already exists: refusing".into()); }
    let (sender, mut receiver) = connect(Arc::new(WebsocketConfig::CLIENT_DEFAULT), addr)
        .await.map_err(|_| "local admin socket unavailable")?;
    let pump = tokio::spawn(async move { while receiver.recv::<AdminResponse>().await.is_ok() {} });
    // single_use=false: the live probe authenticates twice per invocation
    // (identity preflight, then the signed call on a fresh connection).
    let request = AdminRequest::IssueAppAuthenticationToken(IssueAppAuthenticationTokenPayload {
        installed_app_id: app, expiry_seconds: expiry, single_use: false });
    let response = tokio::time::timeout(RPC_DEADLINE, sender.request::<_, AdminResponse>(request)).await;
    pump.abort();
    let mut issued = match response {
        Ok(Ok(AdminResponse::AppAuthenticationTokenIssued(issued))) => issued,
        Ok(Ok(AdminResponse::Error(_))) => return Err("conductor refused token issuance".into()),
        _ => return Err("token issuance RPC failed".into()),
    };
    let result = write_private_new(out, &issued.token);
    issued.token.zeroize();
    result?;
    println!("app token stored in a new 0600 file (bytes not printed); expires in {expiry}s, multi-use");
    Ok(())
}

/// R7: the origin the Phase 5B/5C tools send for an app interface on `port`
/// (`--origin http://localhost:<port>`), and the ONLY origin an interface made
/// by `attach-app-interface` accepts.
fn interface_origin(port: u16) -> String { format!("http://localhost:{port}") }

/// Validated request for a per-app interface: loopback bind (the conductor's
/// default when no bind address is given), one explicit origin, one app.
fn attach_request(app_id: &str, port: &str) -> Result<(u16, AdminRequest), String> {
    let port: u16 = port.parse().ok().filter(|p| *p != 0).ok_or("invalid app port")?;
    if app_id.is_empty() || app_id.len() > 128 ||
       app_id.chars().any(|c| c.is_whitespace() || c.is_control() || c == ',' || c == '*') {
        return Err("invalid installed app id".into());
    }
    Ok((port, AdminRequest::AttachAppInterface {
        port: Some(port), danger_bind_addr: None,
        allowed_origins: interface_origin(port).into(), installed_app_id: Some(app_id.to_owned()) }))
}

/// Problems with one listed interface. Empty means acceptable.
fn interface_findings(port: u16, origins: &str, app: Option<&str>, expect_app: Option<&str>) -> Vec<String> {
    let mut found = Vec::new();
    if origins.split(',').any(|o| o.trim() == "*") { found.push(format!("port {port}: allows any origin (*)")); }
    match (app, expect_app) {
        (None, _) => found.push(format!("port {port}: not bound to an installed app")),
        (Some(a), Some(e)) if a != e => found.push(format!("port {port}: bound to another app ({a})")),
        _ => {}
    }
    found
}

async fn admin_request(addr: SocketAddr, request: AdminRequest) -> Result<AdminResponse, String> {
    let (sender, mut receiver) = connect(Arc::new(WebsocketConfig::CLIENT_DEFAULT), addr)
        .await.map_err(|_| "local admin socket unavailable")?;
    let pump = tokio::spawn(async move { while receiver.recv::<AdminResponse>().await.is_ok() {} });
    let response = tokio::time::timeout(RPC_DEADLINE, sender.request::<_, AdminResponse>(request)).await;
    pump.abort();
    match response {
        Ok(Ok(AdminResponse::Error(_))) => Err("conductor refused the admin request".into()),
        Ok(Ok(other)) => Ok(other),
        _ => Err("admin RPC failed".into()),
    }
}

async fn listed_interfaces(addr: SocketAddr) -> Result<Vec<(u16, String, Option<String>)>, String> {
    match admin_request(addr, AdminRequest::ListAppInterfaces).await? {
        AdminResponse::AppInterfacesListed(list) => Ok(list.into_iter()
            .map(|i| (i.port, String::from(i.allowed_origins), i.installed_app_id)).collect()),
        _ => Err("unexpected reply to ListAppInterfaces".into()),
    }
}

async fn check_app_interfaces(args: &[String]) -> Result<(), String> {
    let m = flags(args, &["--admin-port", "--installed-app-id"])?;
    let addr = local_addr(need(&m, "--admin-port")?)?;
    let expect = m.get("--installed-app-id").map(String::as_str);
    let list = listed_interfaces(addr).await?;
    let mut problems = 0;
    for (port, origins, app) in &list {
        let found = interface_findings(*port, origins, app.as_deref(), expect);
        println!("interface port={port} allowed_origins={origins} installed_app_id={}",
            app.as_deref().unwrap_or("(none)"));
        for f in &found { println!("  FINDING {f}"); }
        problems += found.len();
    }
    if list.is_empty() { println!("no app interfaces attached"); }
    if problems > 0 { return Err(format!("{problems} app-interface finding(s) (risk R7)")); }
    Ok(())
}

async fn attach_app_interface(args: &[String]) -> Result<(), String> {
    let m = flags(args, &["--admin-port", "--installed-app-id", "--app-port", "--confirm-admin-interface-attach"])?;
    if !m.contains_key("--confirm-admin-interface-attach") {
        return Err("refusing: pass --confirm-admin-interface-attach to approve attaching an app interface".into());
    }
    let addr = local_addr(need(&m, "--admin-port")?)?;
    let app = need(&m, "--installed-app-id")?;
    let (port, request) = attach_request(app, need(&m, "--app-port")?)?;
    // Refuse to shadow an interface that is already on this port.
    if listed_interfaces(addr).await?.iter().any(|(p, _, _)| *p == port) {
        return Err("an app interface already exists on that port: refusing".into());
    }
    match admin_request(addr, request).await? {
        AdminResponse::AppInterfaceAttached { port: got } if got == port => {}
        _ => return Err("conductor did not attach the requested interface".into()),
    }
    // Read it back: the conductor must report exactly the requested binding.
    let origin = interface_origin(port);
    let ok = listed_interfaces(addr).await?.iter().any(|(p, o, a)|
        *p == port && *o == origin && a.as_deref() == Some(app));
    if !ok { return Err("attached interface does not read back as requested".into()); }
    println!("attached app interface port={port} allowed_origins={origin} installed_app_id={app}");
    Ok(())
}

async fn connect_lair(url: &str) -> Result<MetaLairClient, String> {
    if url.len() > 1024 || !url.starts_with("unix://") {
        return Err("only a local unix:// Lair URL is supported".into());
    }
    let mut phrase = rpassword::prompt_password("Lair unlock passphrase: ")
        .map_err(|_| "cannot read Lair unlock passphrase")?;
    if phrase.is_empty() || phrase.len() > 4096 { phrase.zeroize(); return Err("invalid passphrase length".into()); }
    let mut locked = sodoken::LockedArray::new(phrase.len()).map_err(|_| "cannot allocate locked passphrase")?;
    locked.lock().copy_from_slice(phrase.as_bytes());
    phrase.zeroize();
    let client = tokio::time::timeout(Duration::from_secs(20),
        ipc_keystore_connect(url2::Url2::parse(url).into(), Arc::new(Mutex::new(locked))))
        .await.map_err(|_| "Lair connection timed out")?
        .map_err(|_| "Lair authentication failed")?;
    MetaLairClient::from_client(client).await.map_err(|_| "Lair client setup failed".into())
}

async fn propose_session(args: &[String]) -> Result<(), String> {
    let m = flags(args, &["--app-port", "--origin", "--app-token-file", "--installed-app-id",
        "--dna-b64", "--agent-b64", "--lair-url", "--record-out", "--confirm-source-chain-write"])?;
    if !m.contains_key("--confirm-source-chain-write") {
        return Err("refusing: pass --confirm-source-chain-write to approve authoring a SessionProposal".into());
    }
    let addr = local_addr(need(&m, "--app-port")?)?;
    let origin = need(&m, "--origin")?;
    local_origin(origin)?;
    let app_id = need(&m, "--installed-app-id")?;
    let dna = decode_b64("dna", need(&m, "--dna-b64")?)?;
    let agent = decode_b64("agent", need(&m, "--agent-b64")?)?;
    let record_out = Path::new(need(&m, "--record-out")?);
    if fs::symlink_metadata(record_out).is_ok() { return Err("record output already exists: refusing".into()); }
    let token = holochain_mpc_dkg_worker::conductor_client::read_app_token(
        Path::new(need(&m, "--app-token-file")?)).map_err(|e| e.to_string())?;

    let mut session_id = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut session_id);
    let spec = probe_spec(app_id, &dna, &agent, session_id)?;

    // Unlock Lair BEFORE touching the app socket so a wrong passphrase costs nothing.
    let lair = connect_lair(need(&m, "--lair-url")?).await?;

    let request: ConnectRequest = addr.into();
    let request = request.try_set_header("Origin", origin).map_err(|_| "invalid Origin header")?;
    let (sender, mut receiver) = connect(Arc::new(WebsocketConfig::CLIENT_DEFAULT), request)
        .await.map_err(|_| "local app socket unavailable")?;
    let pump = tokio::spawn(async move { while receiver.recv::<AppResponse>().await.is_ok() {} });
    let outcome = async {
        sender.authenticate(AppAuthenticationRequest { token: token.to_vec() })
            .await.map_err(|_| "app authentication failed")?;
        let info = match sender.request::<_, AppResponse>(AppRequest::AppInfo).await {
            Ok(AppResponse::AppInfo(Some(info))) => info,
            _ => return Err("authenticated AppInfo unavailable".to_string()),
        };
        // Exact pin: app id, app agent, and exactly one provisioned `mpc` cell.
        let cells: Vec<_> = info.cell_info.get("mpc").into_iter().flatten().filter_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()), _ => None }).collect();
        if info.installed_app_id != app_id || info.agent_pub_key.get_raw_39() != agent.as_slice() ||
            cells.len() != 1 || cells[0].dna_hash().get_raw_39() != dna.as_slice() ||
            cells[0].agent_pubkey().get_raw_39() != agent.as_slice() {
            return Err("conductor app/agent/DNA does not match the operator-supplied pin".into());
        }
        let agent_key = AgentPubKey::try_from_raw_39(agent.clone()).map_err(|_| "invalid agent")?;
        let dna_hash = DnaHash::try_from_raw_39(dna.clone()).map_err(|_| "invalid DNA")?;
        let mut nonce = vec![0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let params = ZomeCallParams {
            provenance: agent_key.clone(), cell_id: CellId::new(dna_hash, agent_key.clone()),
            zome_name: ZomeName::from("mpc"), fn_name: FunctionName::from("propose_session"),
            cap_secret: None, payload: ExternIO::encode(spec.clone()).map_err(|_| "cannot encode spec")?,
            nonce: Nonce256Bits::try_from(nonce).map_err(|_| "nonce generation failed")?,
            expires_at: Timestamp::now().checked_add(&Duration::from_secs(30)).ok_or("expiry overflow")?,
        };
        let (bytes, hash) = params.serialize_and_hash().map_err(|_| "call serialization failed")?;
        let signature = agent_key.sign_raw(&lair, Arc::<[u8]>::from(hash)).await
            .map_err(|_| "Lair refused to sign with the installed agent key")?;
        let signed = ZomeCallParamsSigned::new(bytes, signature);
        match tokio::time::timeout(RPC_DEADLINE,
            sender.request::<_, AppResponse>(AppRequest::CallZome(Box::new(signed)))).await {
            Ok(Ok(AppResponse::ZomeCalled(io))) => io.decode::<ActionHash>()
                .map_err(|_| "conductor returned an invalid action hash".to_string()),
            // The spec is public; the conductor's message helps diagnose validation.
            Ok(Ok(AppResponse::Error(e))) => Err(format!("conductor rejected propose_session: {}",
                format!("{e:?}").chars().take(400).collect::<String>())),
            _ => Err("propose_session outcome UNKNOWN: inspect the chain with dump-state before any retry".into()),
        }
    }.await;
    pump.abort();
    let action = outcome?;
    let action_hex = hex(action.get_raw_39());
    let record = serde_json::json!({
        "schema": 1, "purpose": "phase5b-read-probe-only",
        "installed_app_id": app_id,
        "dna_hash_b64": DnaHashB64::from(DnaHash::try_from_raw_39(dna.clone()).unwrap()).to_string(),
        "dna_hash_hex": hex(&dna),
        "agent_b64": AgentPubKeyB64::from(AgentPubKey::try_from_raw_39(agent.clone()).unwrap()).to_string(),
        "agent_hex": hex(&agent),
        "proposal_action_b64": ActionHashB64::from(action.clone()).to_string(),
        "proposal_action_hex": action_hex,
        "session_id_hex": hex(&session_id),
        "spec": spec,
    });
    let json = serde_json::to_vec_pretty(&record).map_err(|_| "cannot encode record")?;
    // The proposal already exists on-chain at this point: always print the
    // public identifiers so a record-file failure cannot lose them.
    println!("PROPOSAL CREATED (public identifiers only)");
    println!("proposal_action_b64={}", ActionHashB64::from(action));
    println!("proposal_action_hex={action_hex}");
    println!("session_id_hex={}", hex(&session_id));
    write_private_new(record_out, &json)?;
    println!("record written to a new 0600 file");
    Ok(())
}

fn write_policy(args: &[String]) -> Result<(), String> {
    let m = flags(args, &["--state-dir", "--installed-app-id", "--dna-hex", "--out"])?;
    let context = pinned_context(Path::new(need(&m, "--state-dir")?))
        .map_err(|_| "private node state unavailable or invalid")?;
    let dna = holochain_mpc_dkg_worker::node_service::decode_hex_exact::<39>(need(&m, "--dna-hex")?)
        .map_err(|_| "DNA hash must be 39 bytes of hex")?.to_vec();
    let binding = SignerBinding {
        installed_app_id: need(&m, "--installed-app-id")?.to_owned(), role: "mpc".into(),
        dna_hash: dna, agent: context.worker_agent, proposal_action: context.proposal_action,
        session_id: context.session_id, channel_id: context.channel_id,
    };
    let json = serde_json::to_vec_pretty(&serde_json::json!({"binding": binding, "recipients": []}))
        .map_err(|_| "cannot encode policy")?;
    // Round-trip through the signer's own parser and validator before writing.
    let parsed: SignerPolicyFile = serde_json::from_slice(&json).map_err(|_| "policy does not round-trip")?;
    SignerPolicy::new(parsed)?;
    write_private_new(Path::new(need(&m, "--out")?), &json)?;
    println!("read-only signer policy written (recipients: [])");
    Ok(())
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("decode-hash") if args.len() == 3 => {
            println!("{}", hex(&decode_b64(&args[1], &args[2])?));
            Ok(())
        }
        Some("write-policy") => write_policy(&args[1..]),
        Some("issue-app-token") => issue_app_token(&args[1..]).await,
        Some("check-app-interfaces") => check_app_interfaces(&args[1..]).await,
        Some("attach-app-interface") => attach_app_interface(&args[1..]).await,
        Some("propose-session") => propose_session(&args[1..]).await,
        _ => Err("usage: mpc-phase5b-bootstrap decode-hash <dna|agent|action> <b64> | write-policy ... | \
                  issue-app-token ... --confirm-admin-token-issue | check-app-interfaces ... | \
                  attach-app-interface ... --confirm-admin-interface-attach | propose-session ... --confirm-source-chain-write \
                  (see docs/V040_PHASE5B_BOOTSTRAP.md)".into()),
    }
}

#[tokio::main]
async fn main() {
    holochain_mpc_dkg_worker::notice::exit_on_help("mpc-phase5b-bootstrap", "usage: mpc-phase5b-bootstrap decode-hash | write-policy | issue-app-token | check-app-interfaces | attach-app-interface | propose-session\nWrites need an explicit --confirm-* flag. See docs/V040_PHASE5B_BOOTSTRAP.md.");
    if let Err(e) = run().await {
        eprintln!("FAIL: phase5b bootstrap: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const DNA: &str = "uhC0kV173j4T9Qc2pCxriXG5im1O5Zw7aFxchFZJuPG68qxwgzGm5";
    const AGENT: &str = "uhCAkVOE_IPgBUc6zuSoVhkgslTdHyepHxIyIFVURdOVhej3KlKwd";

    #[test]
    fn validated_hash_decoding() {
        let dna = decode_b64("dna", DNA).unwrap();
        let agent = decode_b64("agent", AGENT).unwrap();
        assert_eq!((dna.len(), agent.len()), (39, 39));
        assert_eq!(&dna[..3], &[0x84, 0x2d, 0x24]);
        assert_eq!(&agent[..3], &[0x84, 0x20, 0x24]);
        // Wrong kind, corrupted checksum, and truncation must all fail.
        assert!(decode_b64("agent", DNA).is_err());
        assert!(decode_b64("action", AGENT).is_err());
        let mut bad = AGENT.to_owned(); bad.pop(); bad.push(if AGENT.ends_with('A') { 'B' } else { 'A' });
        assert!(decode_b64("agent", &bad).is_err());
        assert!(decode_b64("dna", &DNA[..DNA.len() - 2]).is_err());
        assert!(decode_b64("bogus", DNA).is_err());
    }

    #[test]
    fn probe_spec_is_single_member_and_bound() {
        let dna = decode_b64("dna", DNA).unwrap();
        let agent = decode_b64("agent", AGENT).unwrap();
        let a = probe_spec("mpc-phase5b", &dna, &agent, [7; 32]).unwrap();
        assert!(a.contains(&agent));
        assert_eq!((a.participants.len(), a.threshold), (1, 1));
        let b = probe_spec("mpc-phase5b", &dna, &agent, [8; 32]).unwrap();
        assert_ne!(a.context_hash, b.context_hash);
        assert!(probe_spec("mpc-phase5b", &dna, &agent, [0; 32]).is_err());
        assert!(probe_spec("mpc-phase5b", &dna, &dna[..20], [7; 32]).is_err());
    }

    #[test]
    fn private_output_never_overwrites_and_needs_private_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("p");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(write_private_new(&dir.join("x"), b"1").is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        write_private_new(&dir.join("x"), b"1").unwrap();
        assert_eq!(fs::metadata(dir.join("x")).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(write_private_new(&dir.join("x"), b"2").is_err());
        assert_eq!(fs::read(dir.join("x")).unwrap(), b"1");
        assert!(write_private_new(Path::new("relative"), b"1").is_err());
    }

    #[test]
    fn write_commands_require_explicit_confirmation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let tok: Vec<String> = ["--admin-port", "1", "--installed-app-id", "a", "--out", "/nonexistent/t",
            "--expiry-seconds", "60"].iter().map(|s| s.to_string()).collect();
        assert!(rt.block_on(issue_app_token(&tok)).unwrap_err().contains("--confirm-admin-token-issue"));
        let prop: Vec<String> = ["--app-port", "1"].iter().map(|s| s.to_string()).collect();
        assert!(rt.block_on(propose_session(&prop)).unwrap_err().contains("--confirm-source-chain-write"));
        assert!(flags(&["--confirm-everything".into()], &["--out"]).is_err());
        assert!(flags(&["--out".into(), "a".into(), "--out".into(), "b".into()], &["--out"]).is_err());
    }

    #[test]
    fn non_expiring_tokens_refused() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        for e in ["0", "86401"] {
            let a: Vec<String> = ["--admin-port", "1", "--installed-app-id", "a", "--out", "/nonexistent/t",
                "--expiry-seconds", e, "--confirm-admin-token-issue"].iter().map(|s| s.to_string()).collect();
            assert!(rt.block_on(issue_app_token(&a)).unwrap_err().contains("expiry"));
        }
    }

    #[test]
    fn app_interface_request_is_per_app_and_never_a_wildcard() {
        let (port, request) = attach_request("mpc-phase5c", "8891").unwrap();
        assert_eq!(port, 8891);
        let AdminRequest::AttachAppInterface { port: p, danger_bind_addr, allowed_origins, installed_app_id } = request
            else { panic!("wrong request") };
        assert_eq!(p, Some(8891));
        assert_eq!(danger_bind_addr, None, "must keep the conductor's loopback default");
        assert_eq!(String::from(allowed_origins), "http://localhost:8891");
        assert_eq!(installed_app_id.as_deref(), Some("mpc-phase5c"));
        for (app, port) in [("", "8891"), ("a b", "8891"), ("a,b", "8891"), ("*", "8891"), ("a\n", "8891"),
                            ("mpc", "0"), ("mpc", "65536"), ("mpc", "x"), (&"a".repeat(129), "8891")] {
            assert!(attach_request(app, port).is_err(), "{app:?} {port}");
        }
    }

    #[test]
    fn interface_findings_flag_wildcards_and_unbound_interfaces() {
        assert!(interface_findings(1, "http://localhost:1", Some("app"), Some("app")).is_empty());
        assert!(interface_findings(1, "http://localhost:1", Some("app"), None).is_empty());
        assert_eq!(interface_findings(1, "*", Some("app"), None).len(), 1);
        assert_eq!(interface_findings(1, "http://localhost:1,*", Some("app"), None).len(), 1);
        assert_eq!(interface_findings(1, "http://localhost:1", None, None).len(), 1);
        assert_eq!(interface_findings(1, "*", None, None).len(), 2);
        assert_eq!(interface_findings(1, "http://localhost:1", Some("other"), Some("app")).len(), 1);
    }

    #[test]
    fn attach_requires_explicit_confirmation_before_any_connection() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let args: Vec<String> = ["--admin-port", "1", "--installed-app-id", "a", "--app-port", "2"]
            .iter().map(|s| s.to_string()).collect();
        assert!(rt.block_on(attach_app_interface(&args)).unwrap_err().contains("--confirm-admin-interface-attach"));
        let mut wildcard = args.clone();
        wildcard[3] = "*".into();
        wildcard.push("--confirm-admin-interface-attach".into());
        assert_eq!(rt.block_on(attach_app_interface(&wildcard)).unwrap_err(), "invalid installed app id");
    }
}
