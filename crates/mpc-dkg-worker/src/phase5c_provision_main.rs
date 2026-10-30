//! Phase 5C-B operator provisioning for a multi-agent MPC ceremony.
//!
//! Read-only:   `ids`, `status`, `list-grants`
//! Local only:  `import-offer` (opens a sealed offer with this agent's Lair),
//!              `write-policy` (0600 signer policy with every peer capability)
//! WRITES (each needs its own `--confirm-*` flag = operator approval):
//!   `propose`       — one `SessionProposal`        --confirm-source-chain-write
//!   `accept`        — one `SessionAcceptance`      --confirm-acceptance-write
//!   `prepare-grant` — one assigned inbox grant     --confirm-grant-write
//!   `revoke-grant`  — delete one session grant     --confirm-grant-revoke
//!   `activate-group`— one group activation attestation   --confirm-activation-write
//!   `approve-intent`— one approval of one signing plan    --confirm-approval-write
//!                     (refused unless `--message-file`, the operator's own
//!                     copy, equals the plan's message byte for byte)
//! Phase 8 local only: `make-intent` (public signing plan), `write-signing-policy`
//! (0600 signing-profile signer policy); read-only: `signing-status`.
//!
//! Every conductor call is signed once by this agent's EXISTING Lair key after
//! the app/agent/DNA pin is checked. An uncertain write outcome is terminal:
//! inspect with `status`/`list-grants`, never blindly retry. The Lair URL is
//! read from `--lair-root` (never argv). Capability secrets are never printed;
//! they leave this process only inside a sealed offer for one peer agent.
use holochain_conductor_api::{
    AdminRequest, AdminResponse, AppAuthenticationRequest, AppRequest, AppResponse, CellInfo,
    ZomeCallParamsSigned,
};
use holochain_keystore::{AgentPubKeyExt, MetaLairClient};
use holochain_mpc_core::SessionSpec;
use holochain_mpc_dkg_worker::capability_exchange::{
    assemble_policy, ensure_no_session_grant, grant_views, open_offer, seal_offer, verify_created_grant,
    CapabilityOffer, CeremonyRecord, GrantView, SealedOffer, OFFER_SCHEMA, RECORD_SCHEMA,
};
use holochain_mpc_dkg_worker::conductor_client::read_app_token;
use holochain_mpc_dkg_worker::lair_signer::{connect_lair_interactive, lair_url_from_root};
use holochain_mpc_dkg_worker::node_service::{pinned_context, read_descriptor, recover_share};
use holochain_mpc_dkg_worker::signing::{activated_group, approval_review, ActivationEvidence, ApprovalEvidence,
    SigningPlan, PLAN_SCHEMA};
use holochain_mpc_dkg_worker::signing_signer::{SigningSignerPolicy, PROFILE as SIGNING_PROFILE};
use holochain_mpc_dkg_worker::socket_signer::SignerBinding;
use holochain_nonce::Nonce256Bits;
use holochain_websocket::{connect, ConnectRequest, WebsocketConfig, WebsocketSender};
use holochain_zome_types::prelude::{
    ActionHash, ActionHashB64, AgentPubKey, AgentPubKeyB64, CapSecret, CellId, DnaHash, DnaHashB64,
    ExternIO, FunctionName, Timestamp, ZomeCallParams, ZomeName,
};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const RPC_DEADLINE: Duration = Duration::from_secs(30);
const MAX_FILE: u64 = 64 * 1024;
const APPLICATION_ID: &str = "org.holochain-mpc.phase5c-ceremony";
/// The only coordinator functions this tool can ever sign.
const SIGNABLE: [&str; 9] = ["propose_session", "accept_session", "get_session_status",
                             "prepare_inbox_grant", "revoke_inbox_grant",
                             "publish_group_activation_attestation", "get_group_activation_attestations",
                             "publish_signing_approval", "get_signing_approvals"];

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn agent_b64(raw: &[u8]) -> String {
    AgentPubKey::try_from_raw_39(raw.to_vec()).map(|a| AgentPubKeyB64::from(a).to_string())
        .unwrap_or_else(|_| "<invalid>".into())
}
fn decode_agent(v: &str) -> Result<Vec<u8>, String> {
    Ok(AgentPubKey::from(AgentPubKeyB64::from_b64_str(v.trim()).map_err(|_| "not a valid AgentPubKey")?)
        .get_raw_39().to_vec())
}

// ---------------------------------------------------------------- arguments

#[derive(Debug)]
struct Flags(BTreeMap<String, String>);
impl Flags {
    /// Every value flag must be listed in `allowed`; a write's single
    /// confirmation flag must be exactly `confirm` and is then mandatory.
    fn parse(args: &[String], allowed: &[&str], confirm: Option<&str>) -> Result<Self, String> {
        let mut out = BTreeMap::new();
        let mut confirmed = false;
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            if flag.starts_with("--confirm-") {
                if Some(flag.as_str()) != confirm || confirmed { return Err(format!("unexpected {flag}")); }
                confirmed = true;
                continue;
            }
            let value = it.next().ok_or("option missing value")?;
            if !allowed.contains(&flag.as_str()) || out.insert(flag.clone(), value.clone()).is_some() {
                return Err(format!("unknown or repeated option {flag}"));
            }
        }
        if let Some(c) = confirm {
            if !confirmed { return Err(format!("refusing: this is a write; pass {c} to approve it")); }
        }
        for flag in allowed {
            if !out.contains_key(*flag) { return Err(format!("missing {flag}")); }
        }
        Ok(Self(out))
    }
    fn get(&self, k: &str) -> &str { &self.0[k] }
    fn path(&self, k: &str) -> Result<PathBuf, String> {
        let p = PathBuf::from(self.get(k));
        if !p.is_absolute() { return Err(format!("{k} must be an absolute path")); }
        Ok(p)
    }
    fn port(&self, k: &str) -> Result<SocketAddr, String> {
        let port: u16 = self.get(k).parse().map_err(|_| format!("invalid {k}"))?;
        if port == 0 { return Err(format!("invalid {k}")); }
        Ok(SocketAddr::from(([127, 0, 0, 1], port)))
    }
    fn origin(&self) -> Result<String, String> {
        let o = self.get("--origin");
        let ok = o.strip_prefix("http://localhost").is_some_and(|p| p.is_empty() ||
            p.strip_prefix(':').is_some_and(|n| n.parse::<u16>().is_ok_and(|n| n != 0)));
        if o.len() > 256 || !ok { return Err("Origin must be http://localhost[:port]".into()); }
        Ok(o.to_owned())
    }
}

// --------------------------------------------------------------- local files

fn private_dir(path: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|_| format!("{} missing", path.display()))?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != unsafe { libc::geteuid() } ||
        m.permissions().mode() & 0o777 != 0o700 {
        return Err(format!("{} must be an owned 0700 directory", path.display()));
    }
    Ok(())
}

/// Owned, regular, single-link, not group/world-writable; `secret` => 0600.
fn read_owned(path: &Path, secret: bool) -> Result<Zeroizing<Vec<u8>>, String> {
    let m = fs::symlink_metadata(path).map_err(|_| format!("{} unavailable", path.display()))?;
    let mode = m.permissions().mode() & 0o777;
    if !m.is_file() || m.file_type().is_symlink() || m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } ||
        (if secret { mode != 0o600 } else { mode & 0o022 != 0 }) || m.len() == 0 || m.len() > MAX_FILE {
        return Err(format!("{} must be an owned private regular file", path.display()));
    }
    let f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
        .map_err(|_| "cannot open file")?;
    let mut out = Zeroizing::new(Vec::new());
    f.take(MAX_FILE + 1).read_to_end(&mut out).map_err(|_| "cannot read file")?;
    Ok(out)
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    private_dir(path.parent().ok_or("output has no parent")?)?;
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(path)
        .map_err(|_| format!("cannot create {} (it must not already exist)", path.display()))?;
    f.write_all(bytes).and_then(|_| f.sync_all()).map_err(|_| "cannot write output".into())
}

fn load_record(path: &Path) -> Result<CeremonyRecord, String> {
    let r: CeremonyRecord = serde_json::from_slice(&read_owned(path, false)?)
        .map_err(|_| "invalid ceremony record")?;
    r.validate()?;
    Ok(r)
}

// ---------------------------------------------------------------- conductor

#[derive(Deserialize, Debug)]
struct SessionStatus { spec: SessionSpec, accepted: Vec<AgentPubKey>, ready_observed: bool }

#[derive(Deserialize)]
struct PreparedGrant { grant_hash: ActionHash, cap_secret: CapSecret }
/// Required by `ExternIO::decode`; never reveal the secret.
impl std::fmt::Debug for PreparedGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("PreparedGrant{<redacted>}") }
}

enum CallError { Rejected(String), Unknown }
impl CallError {
    fn write(self, what: &str) -> String {
        match self {
            CallError::Rejected(m) => format!("{what} rejected: {m}"),
            CallError::Unknown => format!("{what} outcome UNKNOWN: inspect with `status`/`list-grants`; do NOT retry"),
        }
    }
    fn read(self, what: &str) -> String {
        match self { CallError::Rejected(m) => format!("{what} rejected: {m}"), CallError::Unknown => format!("{what} failed") }
    }
}

/// An authenticated app connection pinned to one app, agent and `mpc` cell.
struct App { sender: WebsocketSender, pump: tokio::task::JoinHandle<()>, dna: DnaHash, agent: AgentPubKey,
             lair: MetaLairClient }
impl Drop for App { fn drop(&mut self) { self.pump.abort(); } }

impl App {
    async fn open(f: &Flags, app_id: &str, dna: &[u8], agent: &[u8], lair: MetaLairClient) -> Result<Self, String> {
        let token = read_app_token(&f.path("--app-token-file")?).map_err(|e| e.to_string())?;
        let req: ConnectRequest = f.port("--app-port")?.into();
        let req = req.try_set_header("Origin", &f.origin()?).map_err(|_| "invalid Origin")?;
        let (sender, mut rx) = connect(Arc::new(WebsocketConfig::CLIENT_DEFAULT), req)
            .await.map_err(|_| "local app socket unavailable")?;
        let pump = tokio::spawn(async move { while rx.recv::<AppResponse>().await.is_ok() {} });
        let app = App { sender, pump, dna: DnaHash::try_from_raw_39(dna.to_vec()).map_err(|_| "bad DNA")?,
            agent: AgentPubKey::try_from_raw_39(agent.to_vec()).map_err(|_| "bad agent")?, lair };
        app.sender.authenticate(AppAuthenticationRequest { token: token.to_vec() })
            .await.map_err(|_| "app authentication failed (token expired or conductor restarted?)")?;
        let info = match app.sender.request::<_, AppResponse>(AppRequest::AppInfo).await {
            Ok(AppResponse::AppInfo(Some(i))) => i,
            _ => return Err("authenticated AppInfo unavailable".into()),
        };
        let cells: Vec<CellId> = info.cell_info.get("mpc").into_iter().flatten().filter_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()), _ => None }).collect();
        if info.installed_app_id != app_id || info.agent_pub_key != app.agent || cells.len() != 1 ||
            cells[0] != CellId::new(app.dna.clone(), app.agent.clone()) {
            return Err("conductor app/agent/DNA does not match the pin: wrong conductor or agent".into());
        }
        Ok(app)
    }

    /// Sign exactly once with the pinned agent's Lair key and submit.
    async fn call<T: DeserializeOwned + std::fmt::Debug>(&self, function: &str, payload: ExternIO, verbose: bool)
        -> Result<T, CallError> {
        if !SIGNABLE.contains(&function) { return Err(CallError::Rejected("function not signable".into())); }
        let mut nonce = vec![0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let params = ZomeCallParams {
            provenance: self.agent.clone(), cell_id: CellId::new(self.dna.clone(), self.agent.clone()),
            zome_name: ZomeName::from("mpc"), fn_name: FunctionName::from(function), cap_secret: None, payload,
            nonce: Nonce256Bits::try_from(nonce).map_err(|_| CallError::Rejected("nonce".into()))?,
            expires_at: Timestamp::now().checked_add(&Duration::from_secs(30))
                .ok_or(CallError::Rejected("expiry".into()))?,
        };
        let (bytes, hash) = params.serialize_and_hash().map_err(|_| CallError::Rejected("encoding".into()))?;
        let sig = self.agent.sign_raw(&self.lair, Arc::<[u8]>::from(hash)).await
            .map_err(|_| CallError::Rejected("Lair refused to sign with the pinned agent key".into()))?;
        let signed = ZomeCallParamsSigned::new(bytes, sig);
        match tokio::time::timeout(RPC_DEADLINE,
            self.sender.request::<_, AppResponse>(AppRequest::CallZome(Box::new(signed)))).await {
            Ok(Ok(AppResponse::ZomeCalled(io))) => io.decode().map_err(|_| CallError::Unknown),
            // Only public-data calls may surface the conductor's message.
            Ok(Ok(AppResponse::Error(e))) => Err(CallError::Rejected(if verbose {
                format!("{e:?}").chars().take(400).collect() } else { "conductor error (details withheld)".into() })),
            _ => Err(CallError::Unknown),
        }
    }

    async fn status(&self, record: &CeremonyRecord) -> Result<SessionStatus, String> {
        let proposal = ActionHash::try_from_raw_39(record.proposal_action.clone()).map_err(|_| "bad proposal")?;
        let status: SessionStatus = self.call("get_session_status",
            ExternIO::encode(proposal).map_err(|_| "encoding")?, true).await
            .map_err(|e| e.read("get_session_status (proposal not yet visible via DHT?)"))?;
        record.pin_spec(&status.spec)?;
        if status.accepted.iter().any(|a| !record.spec.contains(a.get_raw_39())) {
            return Err("acceptance from a non-participant reported".into());
        }
        Ok(status)
    }
}

async fn list_grants(admin: SocketAddr, record: &CeremonyRecord, agent: &[u8]) -> Result<Vec<GrantView>, String> {
    let (sender, mut rx) = connect(Arc::new(WebsocketConfig::CLIENT_DEFAULT), admin)
        .await.map_err(|_| "local admin socket unavailable")?;
    let pump = tokio::spawn(async move { while rx.recv::<AdminResponse>().await.is_ok() {} });
    let response = tokio::time::timeout(RPC_DEADLINE, sender.request::<_, AdminResponse>(
        AdminRequest::ListCapabilityGrants { installed_app_id: record.installed_app_id.clone(), include_revoked: true }))
        .await;
    pump.abort();
    let info = match response {
        Ok(Ok(AdminResponse::CapabilityGrantsInfo(info))) => info,
        _ => return Err("ListCapabilityGrants failed".into()),
    };
    let cell = CellId::new(DnaHash::try_from_raw_39(record.dna_hash.clone()).map_err(|_| "bad DNA")?,
                           AgentPubKey::try_from_raw_39(agent.to_vec()).map_err(|_| "bad agent")?);
    // The conductor OMITS cells that have no grants, so absence means "none".
    // The cell itself is pinned separately through authenticated AppInfo.
    let mut found = info.0.into_iter().filter(|(c, _)| *c == cell);
    let grants = found.next().map(|(_, g)| g).unwrap_or_default();
    if found.next().is_some() { return Err("ambiguous cell in grant listing".into()); }
    grant_views(&grants)
}

async fn lair(f: &Flags) -> Result<MetaLairClient, String> {
    connect_lair_interactive(&lair_url_from_root(&f.path("--lair-root")?)?).await
}

// -------------------------------------------------------------- subcommands

const APP: [&str; 5] = ["--app-port", "--origin", "--app-token-file", "--agent-b64", "--lair-root"];
fn with(extra: &[&'static str]) -> Vec<&'static str> { APP.iter().chain(extra).copied().collect() }

pub fn ceremony_spec(app_id: &str, dna: &[u8], members: &[Vec<u8>], threshold: u16, session_id: [u8; 32])
    -> Result<SessionSpec, String> {
    let mut participants = members.to_vec();
    participants.sort();
    if participants.windows(2).any(|w| w[0] == w[1]) { return Err("duplicate participant".into()); }
    if participants.len() < 2 || threshold < 2 || usize::from(threshold) > participants.len() {
        return Err("need >= 2 participants and 2 <= threshold <= participants".into());
    }
    let description = format!("holochain-mpc-core/phase5c/ceremony/v1|app={app_id}|dna={}|t={threshold}|session={}|members={}",
        hex(dna), hex(&session_id), participants.iter().map(|p| hex(p)).collect::<Vec<_>>().join(","));
    let spec = SessionSpec { session_id, application_id: APPLICATION_ID.into(), protocol_id: "frost-ed25519".into(),
        protocol_version: 1, context_hash: holochain_mpc_core::commitment("phase5c-ceremony-context", description.as_bytes()),
        participants, threshold, max_round: 6 };
    spec.validate().map_err(|e| format!("spec invalid: {e}"))?;
    Ok(spec)
}

async fn propose(args: &[String], probe: bool) -> Result<(), String> {
    let f = Flags::parse(args, &with(&["--installed-app-id", "--dna-b64", "--participants-file",
        "--threshold", "--record-out"]), Some(if probe {"--confirm-probe-proposal-write"} else {"--confirm-source-chain-write"}))?;
    let local = decode_agent(f.get("--agent-b64"))?;
    let dna = DnaHash::from(DnaHashB64::from_b64_str(f.get("--dna-b64")).map_err(|_| "not a valid DnaHash")?)
        .get_raw_39().to_vec();
    let members = String::from_utf8(read_owned(&f.path("--participants-file")?, false)?.to_vec())
        .map_err(|_| "participants file is not UTF-8")?.lines().map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#')).map(decode_agent).collect::<Result<Vec<_>, _>>()?;
    if !members.contains(&local) { return Err("the proposing agent must be listed as a participant".into()); }
    let threshold: u16 = f.get("--threshold").parse().map_err(|_| "invalid threshold")?;
    let out = f.path("--record-out")?;
    if fs::symlink_metadata(&out).is_ok() { return Err("record output already exists".into()); }
    let app_id = f.get("--installed-app-id").to_owned();
    let mut session_id = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut session_id);
    let spec = if probe {
        if threshold!=2 {return Err("probe requires threshold two".into());}
        holochain_mpc_dkg_worker::transport_probe::proposal_spec(&app_id,&dna,&members,session_id)?
    } else {ceremony_spec(&app_id, &dna, &members, threshold, session_id)?};

    let app = App::open(&f, &app_id, &dna, &local, lair(&f).await?).await?;
    let action: ActionHash = app.call("propose_session", ExternIO::encode(spec.clone())
        .map_err(|_| "encoding")?, true).await.map_err(|e| e.write("propose_session"))?;
    let record = CeremonyRecord { schema: RECORD_SCHEMA, installed_app_id: app_id, dna_hash: dna,
        proposal_action: action.get_raw_39().to_vec(), spec };
    record.validate()?;
    println!("PROPOSAL CREATED (public identifiers only)");
    println!("proposal_action_b64={}", ActionHashB64::from(action));
    println!("session_id_hex={}", hex(&session_id));
    println!("participants={} threshold={}", record.spec.participants.len(), threshold);
    write_private_new(&out, &serde_json::to_vec_pretty(&record).map_err(|_| "encode")?)?;
    println!("ceremony record written; copy it (public data) to every participant operator");
    Ok(())
}

async fn accept(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &with(&["--record"]), Some("--confirm-acceptance-write"))?;
    let record = load_record(&f.path("--record")?)?;
    let local = decode_agent(f.get("--agent-b64"))?;
    record.peers_of(&local)?;
    let app = App::open(&f, &record.installed_app_id, &record.dna_hash, &local, lair(&f).await?).await?;
    let before = app.status(&record).await?;
    if before.accepted.iter().any(|a| a.get_raw_39() == local.as_slice()) {
        return Err("this agent already accepted this proposal; refusing another write".into());
    }
    let proposal = ActionHash::try_from_raw_39(record.proposal_action.clone()).map_err(|_| "bad proposal")?;
    let _: ActionHash = app.call("accept_session", ExternIO::encode(proposal).map_err(|_| "encoding")?, true)
        .await.map_err(|e| e.write("accept_session"))?;
    let after = app.status(&record).await?;
    if !after.accepted.iter().any(|a| a.get_raw_39() == local.as_slice()) {
        return Err("acceptance not visible on read-back: inspect before any retry".into());
    }
    println!("PASS: acceptance recorded ({}/{} accepted locally observed; ready={})",
        after.accepted.len(), record.spec.participants.len(), after.ready_observed);
    Ok(())
}

async fn status(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &with(&["--record"]), None)?;
    let record = load_record(&f.path("--record")?)?;
    let local = decode_agent(f.get("--agent-b64"))?;
    record.peers_of(&local)?;
    let app = App::open(&f, &record.installed_app_id, &record.dna_hash, &local, lair(&f).await?).await?;
    let s = app.status(&record).await?;
    println!("PASS: conductor proposal matches the pinned ceremony exactly");
    for p in &record.spec.participants {
        let ok = s.accepted.iter().any(|a| a.get_raw_39() == p.as_slice());
        println!("  {} {}{}", if ok { "accepted" } else { "pending " }, agent_b64(p),
                 if *p == local { " (local)" } else { "" });
    }
    println!("ready_observed={}", s.ready_observed);
    Ok(())
}

fn ids(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &["--record", "--agent-b64"], None)?;
    let record = load_record(&f.path("--record")?)?;
    let local = decode_agent(f.get("--agent-b64"))?;
    record.peers_of(&local)?;
    println!("AGENT_HEX={}\nPROPOSAL_HEX={}\nSESSION_HEX={}\nDNA_HEX={}", hex(&local),
             hex(&record.proposal_action), hex(&record.spec.session_id), hex(&record.dna_hash));
    Ok(())
}

async fn show_grants(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &["--record", "--admin-port", "--agent-b64"], None)?;
    let record = load_record(&f.path("--record")?)?;
    let local = decode_agent(f.get("--agent-b64"))?;
    let peers = record.peers_of(&local)?;
    let views = list_grants(f.port("--admin-port")?, &record, &local).await?;
    let tag = record.grant_tag();
    let mine: Vec<_> = views.iter().filter(|v| v.tag == tag).collect();
    println!("session grants (tag {tag}): {}", mine.len());
    for v in mine {
        println!("  {} {} access={} assignees_exact={} inbox_only={}",
            ActionHashB64::from(ActionHash::from_raw_39(v.action.clone())),
            if v.revoked { "REVOKED" } else { "live" }, v.access_type,
            v.assignees.as_ref() == Some(&peers),
            v.functions.as_ref().is_some_and(|f| f.len() == 1 && f.iter().all(|(z, n)| z == "mpc" && n == "receive_protocol_message")));
    }
    Ok(())
}

fn offer_name(grantor: &[u8], grantee: &[u8]) -> String {
    format!("offer-{}-to-{}.json", &hex(&grantor[3..])[..16], &hex(&grantee[3..])[..16])
}

async fn prepare_grant(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &with(&["--record", "--admin-port", "--offers-dir"]), Some("--confirm-grant-write"))?;
    let record = load_record(&f.path("--record")?)?;
    let local = decode_agent(f.get("--agent-b64"))?;
    let peers = record.peers_of(&local)?;
    let offers_dir = f.path("--offers-dir")?;
    private_dir(&offers_dir)?;
    for p in &peers {
        if fs::symlink_metadata(offers_dir.join(offer_name(&local, p))).is_ok() {
            return Err("an offer file for this ceremony already exists: refusing".into());
        }
    }
    let admin = f.port("--admin-port")?;
    ensure_no_session_grant(&list_grants(admin, &record, &local).await?, &record)?;
    let app = App::open(&f, &record.installed_app_id, &record.dna_hash, &local, lair(&f).await?).await?;
    if !app.status(&record).await?.ready_observed {
        return Err("not every participant has accepted yet: refusing to grant".into());
    }
    let proposal = ActionHash::try_from_raw_39(record.proposal_action.clone()).map_err(|_| "bad proposal")?;
    let prepared: PreparedGrant = app.call("prepare_inbox_grant", ExternIO::encode(proposal)
        .map_err(|_| "encoding")?, false).await.map_err(|e| e.write("prepare_inbox_grant"))?;
    let grant = prepared.grant_hash.get_raw_39().to_vec();
    if let Err(e) = verify_created_grant(&list_grants(admin, &record, &local).await?, &record, &local, &grant) {
        return Err(format!("grant {} FAILED verification ({e}); revoke it with `revoke-grant`; no offers written",
            ActionHashB64::from(prepared.grant_hash)));
    }
    println!("PASS: one assigned receive_protocol_message grant verified: {}",
             ActionHashB64::from(prepared.grant_hash.clone()));
    for peer in &peers {
        let offer = CapabilityOffer { schema: OFFER_SCHEMA, dna_hash: record.dna_hash.clone(),
            proposal_action: record.proposal_action.clone(), session_id: record.spec.session_id,
            grantor: local.clone(), grantee: peer.clone(), grant_action: grant.clone(),
            cap_secret: prepared.cap_secret };
        let sealed = seal_offer(&app.lair, &offer).await?;
        let name = offer_name(&local, peer);
        write_private_new(&offers_dir.join(&name), &serde_json::to_vec(&sealed).map_err(|_| "encode")?)?;
        println!("  sealed offer for {} -> {name}", agent_b64(peer));
    }
    println!("Deliver each offer file to its named agent's operator; only that agent's Lair can open it.");
    Ok(())
}

async fn revoke_grant(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &with(&["--record", "--admin-port", "--grant-b64"]), Some("--confirm-grant-revoke"))?;
    let record = load_record(&f.path("--record")?)?;
    let local = decode_agent(f.get("--agent-b64"))?;
    record.peers_of(&local)?;
    let target = ActionHash::from(ActionHashB64::from_b64_str(f.get("--grant-b64")).map_err(|_| "not a valid ActionHash")?);
    let admin = f.port("--admin-port")?;
    let views = list_grants(admin, &record, &local).await?;
    if !views.iter().any(|v| v.action == target.get_raw_39() && !v.revoked && v.tag == record.grant_tag()) {
        return Err("grant is not a live inbox grant of this session on this cell".into());
    }
    let app = App::open(&f, &record.installed_app_id, &record.dna_hash, &local, lair(&f).await?).await?;
    // Payload is a public action hash, so the conductor reason may be shown.
    // NOTE: the current DNA's integrity rule rejects every DeleteEntry, so this
    // is refused at validation ("append-only") and nothing is committed.
    let _: ActionHash = app.call("revoke_inbox_grant", ExternIO::encode(target.clone()).map_err(|_| "encoding")?, true)
        .await.map_err(|e| e.write("revoke_inbox_grant"))?;
    if !list_grants(admin, &record, &local).await?.iter().any(|v| v.action == target.get_raw_39() && v.revoked) {
        return Err("revocation not visible on read-back: inspect with list-grants".into());
    }
    println!("PASS: grant revoked; peers holding its secret can no longer deliver");
    Ok(())
}

async fn import_offer(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &["--record", "--agent-b64", "--lair-root", "--offer", "--caps-dir"], None)?;
    let record = load_record(&f.path("--record")?)?;
    let local = decode_agent(f.get("--agent-b64"))?;
    record.peers_of(&local)?;
    let caps = f.path("--caps-dir")?;
    private_dir(&caps)?;
    let sealed: SealedOffer = serde_json::from_slice(&read_owned(&f.path("--offer")?, false)?)
        .map_err(|_| "invalid sealed offer file")?;
    let out = caps.join(format!("cap-{}.json", hex(&sealed.grantor)));
    if fs::symlink_metadata(&out).is_ok() { return Err("a capability from this grantor is already imported".into()); }
    let offer = open_offer(&lair(&f).await?, &sealed, &record, &local).await?;
    write_private_new(&out, &Zeroizing::new(serde_json::to_vec(&offer).map_err(|_| "encode")?))?;
    println!("PASS: authenticated capability from {} imported (secret not shown)", agent_b64(&offer.grantor));
    Ok(())
}

fn write_policy(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &["--record", "--state-dir", "--caps-dir", "--out"], None)?;
    let record = load_record(&f.path("--record")?)?;
    let node = pinned_context(&f.path("--state-dir")?).map_err(|_| "private node state unavailable")?;
    let caps = f.path("--caps-dir")?;
    private_dir(&caps)?;
    let mut offers = Vec::new();
    for entry in fs::read_dir(&caps).map_err(|_| "cannot list caps dir")? {
        let path = entry.map_err(|_| "cannot list caps dir")?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if !(name.starts_with("cap-") && name.ends_with(".json")) {
            return Err(format!("unexpected file in caps dir: {name}"));
        }
        offers.push(serde_json::from_slice::<CapabilityOffer>(&read_owned(&path, true)?)
            .map_err(|_| format!("invalid capability file {name}"))?);
    }
    let json = assemble_policy(&record, &node, &offers)?;
    write_private_new(&f.path("--out")?, &json)?;
    println!("PASS: signer policy written with {} recipient capabilities (secrets not shown)", offers.len());
    Ok(())
}

// ------------------------------------------------------- Phase 8 signing

#[derive(serde::Serialize, Debug)]
struct PublishGroupAttestation { proposal: ActionHash, epoch: u64, descriptor_hash: [u8; 32],
                                 dkg_transcript_hash: [u8; 32], public_key_package_hash: [u8; 32] }
#[derive(serde::Serialize, Debug)]
struct PublishSigningApproval { proposal: ActionHash, operation_id: [u8; 32],
                                group_descriptor_hash: [u8; 32], intent_hash: [u8; 32] }
#[derive(Deserialize, Debug)]
struct AttestationWire { epoch: u64, descriptor_hash: [u8; 32], dkg_transcript_hash: [u8; 32],
                         public_key_package_hash: [u8; 32] }
#[derive(Deserialize, Debug)]
struct AttestationRecordWire { author: AgentPubKey, attestation: AttestationWire }
#[derive(Deserialize, Debug)]
struct ApprovalWire { operation_id: [u8; 32], group_descriptor_hash: [u8; 32], intent_hash: [u8; 32] }
#[derive(Deserialize, Debug)]
struct ApprovalRecordWire { author: AgentPubKey, approval: ApprovalWire }

impl App {
    async fn activations(&self, record: &CeremonyRecord) -> Result<Vec<ActivationEvidence>, String> {
        let proposal = ActionHash::try_from_raw_39(record.proposal_action.clone()).map_err(|_| "bad proposal")?;
        let records: Vec<AttestationRecordWire> = self.call("get_group_activation_attestations",
            ExternIO::encode(proposal).map_err(|_| "encoding")?, true).await
            .map_err(|e| e.read("get_group_activation_attestations"))?;
        Ok(records.into_iter().map(|r| ActivationEvidence { author: r.author.get_raw_39().to_vec(),
            epoch: r.attestation.epoch, descriptor_hash: r.attestation.descriptor_hash,
            dkg_transcript_hash: r.attestation.dkg_transcript_hash,
            public_key_package_hash: r.attestation.public_key_package_hash }).collect())
    }
    async fn approvals(&self, record: &CeremonyRecord) -> Result<Vec<ApprovalEvidence>, String> {
        let proposal = ActionHash::try_from_raw_39(record.proposal_action.clone()).map_err(|_| "bad proposal")?;
        let records: Vec<ApprovalRecordWire> = self.call("get_signing_approvals",
            ExternIO::encode(proposal).map_err(|_| "encoding")?, true).await
            .map_err(|e| e.read("get_signing_approvals"))?;
        Ok(records.into_iter().map(|r| ApprovalEvidence { author: r.author.get_raw_39().to_vec(),
            operation_id: r.approval.operation_id, group_descriptor_hash: r.approval.group_descriptor_hash,
            intent_hash: r.approval.intent_hash }).collect())
    }
}

fn load_plan(path: &Path, record: &CeremonyRecord) -> Result<SigningPlan, String> {
    let plan: SigningPlan = serde_json::from_slice(&read_owned(path, false)?).map_err(|_| "invalid signing plan")?;
    plan.validate()?;
    if plan.descriptor.spec != record.spec || plan.descriptor.proposal_action != record.proposal_action {
        return Err("signing plan belongs to another ceremony".into());
    }
    Ok(plan)
}

/// Attest, once, to the group descriptor this node itself completed.
async fn activate_group(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &with(&["--record", "--state-dir"]), Some("--confirm-activation-write"))?;
    let record = load_record(&f.path("--record")?)?;
    let local = decode_agent(f.get("--agent-b64"))?;
    record.peers_of(&local)?;
    let state = f.path("--state-dir")?;
    let node = pinned_context(&state).map_err(|_| "private node state unavailable")?;
    let descriptor = read_descriptor(&state).map_err(|_| "no completed group descriptor in node state")?;
    if node.worker_agent != local || node.proposal_action != record.proposal_action ||
       descriptor.spec != record.spec || descriptor.proposal_action != record.proposal_action {
        return Err("node state or descriptor belongs to another agent or ceremony".into());
    }
    // Prove this node durably completed exactly this descriptor; drop the share at once.
    drop(recover_share(&state, &descriptor).map_err(|e| format!("descriptor not verified by journal: {e}"))?);
    let digest = descriptor.digest().map_err(|e| e.to_string())?;
    let app = App::open(&f, &record.installed_app_id, &record.dna_hash, &local, lair(&f).await?).await?;
    if app.activations(&record).await?.iter().any(|a| a.author == local && a.epoch == descriptor.epoch) {
        return Err("this agent already attested this group epoch; refusing another write".into());
    }
    let proposal = ActionHash::try_from_raw_39(record.proposal_action.clone()).map_err(|_| "bad proposal")?;
    let _: ActionHash = app.call("publish_group_activation_attestation", ExternIO::encode(PublishGroupAttestation {
        proposal, epoch: descriptor.epoch, descriptor_hash: digest,
        dkg_transcript_hash: descriptor.dkg_transcript_hash,
        public_key_package_hash: descriptor.public_key_package_hash }).map_err(|_| "encoding")?, true)
        .await.map_err(|e| e.write("publish_group_activation_attestation"))?;
    let seen = app.activations(&record).await?;
    println!("PASS: group activation attested (descriptor {}); {}/{} members attested so far",
        hex(&digest), seen.iter().filter(|a| a.epoch == descriptor.epoch).count(), record.spec.participants.len());
    Ok(())
}

/// Write a PUBLIC signing plan with a fresh random operation id.
fn make_intent(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &["--state-dir", "--message-file", "--selected-file", "--out"], None)?;
    let descriptor = read_descriptor(&f.path("--state-dir")?).map_err(|_| "no completed group descriptor in node state")?;
    let message = read_owned(&f.path("--message-file")?, false)?.to_vec();
    let listed = String::from_utf8(read_owned(&f.path("--selected-file")?, false)?.to_vec())
        .map_err(|_| "selected file must be UTF-8")?;
    let mut selected = listed.split_whitespace().map(decode_agent).collect::<Result<Vec<_>, _>>()?;
    selected.sort();
    let mut operation_id = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut operation_id);
    let plan = SigningPlan { schema: PLAN_SCHEMA, descriptor, operation_id, message, selected };
    let review = approval_review(&plan, &plan.message)?;
    // Compact JSON: `validate` bounds this encoding, so every reader can load it.
    write_private_new(&f.path("--out")?, &serde_json::to_vec(&plan).map_err(|_| "encode plan")?)?;
    println!("PASS: signing plan written (public); give the same file to every selected operator.");
    println!("Each operator approves only with their own copy of the message (--message-file).");
    println!("{review}");
    for s in &plan.selected { println!("selected {}", agent_b64(s)); }
    Ok(())
}

/// Approve one exact plan, once, after the group is fully activated. The
/// operator's own `--message-file` must equal the plan's message byte for
/// byte; this is checked before Lair is unlocked or the conductor is called.
async fn approve_intent(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &with(&["--record", "--plan", "--message-file"]), Some("--confirm-approval-write"))?;
    let record = load_record(&f.path("--record")?)?;
    let local = decode_agent(f.get("--agent-b64"))?;
    record.peers_of(&local)?;
    let plan = load_plan(&f.path("--plan")?, &record)?;
    if !plan.selected.contains(&local) { return Err("this agent is not a selected signer of the plan".into()); }
    let review = approval_review(&plan, &read_owned(&f.path("--message-file")?, false)?)?;
    println!("{review}");
    for s in &plan.selected { println!("selected {}", agent_b64(s)); }
    let app = App::open(&f, &record.installed_app_id, &record.dna_hash, &local, lair(&f).await?).await?;
    let active = activated_group(&plan.descriptor, &app.activations(&record).await?)?
        .ok_or("group is not fully activated yet: every member must attest first")?;
    if app.approvals(&record).await?.iter().any(|a| a.author == local && a.operation_id == plan.operation_id) {
        return Err("this agent already approved this operation; refusing another write".into());
    }
    let intent_hash = plan.intent(&active)?.digest().map_err(|e| e.to_string())?;
    let proposal = ActionHash::try_from_raw_39(record.proposal_action.clone()).map_err(|_| "bad proposal")?;
    let _: ActionHash = app.call("publish_signing_approval", ExternIO::encode(PublishSigningApproval {
        proposal, operation_id: plan.operation_id, group_descriptor_hash: active.digest(), intent_hash })
        .map_err(|_| "encoding")?, true).await.map_err(|e| e.write("publish_signing_approval"))?;
    println!("PASS: signing approval recorded (intent {})", hex(&intent_hash));
    Ok(())
}

/// Build the 0600 signing-profile signer policy for one approved plan.
fn write_signing_policy(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &["--record", "--plan", "--state-dir", "--caps-dir", "--out"], None)?;
    let record = load_record(&f.path("--record")?)?;
    let plan = load_plan(&f.path("--plan")?, &record)?;
    let node = pinned_context(&f.path("--state-dir")?).map_err(|_| "private node state unavailable")?;
    let caps = f.path("--caps-dir")?;
    private_dir(&caps)?;
    let mut recipients = Vec::new();
    for entry in fs::read_dir(&caps).map_err(|_| "cannot list caps dir")? {
        let path = entry.map_err(|_| "cannot list caps dir")?.path();
        let offer: CapabilityOffer = serde_json::from_slice(&read_owned(&path, true)?)
            .map_err(|_| "invalid capability file")?;
        offer.check(&record, &node.worker_agent)?;
        if plan.selected.contains(&offer.grantor) && offer.grantor != node.worker_agent {
            recipients.push(serde_json::json!({"agent": offer.grantor, "cap_secret": offer.cap_secret}));
        }
    }
    let binding = SignerBinding { installed_app_id: record.installed_app_id.clone(), role: "mpc".into(),
        dna_hash: record.dna_hash.clone(), agent: node.worker_agent.clone(),
        proposal_action: node.proposal_action.clone(), session_id: node.session_id, channel_id: node.channel_id };
    let json = Zeroizing::new(serde_json::to_vec(&serde_json::json!({
        "profile": SIGNING_PROFILE, "binding": binding, "plan": plan, "recipients": recipients }))
        .map_err(|_| "cannot encode policy")?);
    // The signer reads at most 64 KiB; never write a policy it would refuse.
    if json.len() as u64 > MAX_FILE { return Err("signing policy exceeds the signer's 64 KiB limit".into()); }
    SigningSignerPolicy::new(serde_json::from_slice(&json).map_err(|_| "policy does not round-trip")?)?;
    write_private_new(&f.path("--out")?, &json)?;
    println!("PASS: signing-profile signer policy written for operation {} (secrets not shown)", hex(&plan.operation_id));
    Ok(())
}

/// Read-only: activation and approval progress for one plan.
async fn signing_status(args: &[String]) -> Result<(), String> {
    let f = Flags::parse(args, &with(&["--record", "--plan"]), None)?;
    let record = load_record(&f.path("--record")?)?;
    let local = decode_agent(f.get("--agent-b64"))?;
    record.peers_of(&local)?;
    let plan = load_plan(&f.path("--plan")?, &record)?;
    let app = App::open(&f, &record.installed_app_id, &record.dna_hash, &local, lair(&f).await?).await?;
    let activations = app.activations(&record).await?;
    let active = activated_group(&plan.descriptor, &activations)?;
    println!("activation: {}/{} attested; activated={}", activations.iter()
        .filter(|a| a.epoch == plan.descriptor.epoch).count(), record.spec.participants.len(), active.is_some());
    let approvals = app.approvals(&record).await?;
    for s in &plan.selected {
        let ok = approvals.iter().any(|a| &a.author == s && a.operation_id == plan.operation_id);
        println!("  {} {}", if ok { "approved" } else { "pending " }, agent_b64(s));
    }
    Ok(())
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or_default();
    match args.first().map(String::as_str) {
        Some("propose") => propose(rest, false).await,
        Some("propose-probe") => propose(rest, true).await,
        Some("accept") => accept(rest).await,
        Some("status") => status(rest).await,
        Some("ids") => ids(rest),
        Some("list-grants") => show_grants(rest).await,
        Some("prepare-grant") => prepare_grant(rest).await,
        Some("revoke-grant") => revoke_grant(rest).await,
        Some("import-offer") => import_offer(rest).await,
        Some("write-policy") => write_policy(rest),
        Some("activate-group") => activate_group(rest).await,
        Some("make-intent") => make_intent(rest),
        Some("approve-intent") => approve_intent(rest).await,
        Some("write-signing-policy") => write_signing_policy(rest),
        Some("signing-status") => signing_status(rest).await,
        _ => Err("usage: mpc-phase5c-provision <propose|propose-probe|accept|status|ids|list-grants|prepare-grant|\
                  revoke-grant|import-offer|write-policy|activate-group|make-intent|approve-intent|\
                  write-signing-policy|signing-status> ... (see docs/V040_PHASE8_SIGNING.md)".into()),
    }
}

#[tokio::main]
async fn main() {
    holochain_mpc_dkg_worker::notice::exit_on_help("mpc-phase5c-provision", "Capability provisioning, group activation and signing approvals. See docs/V040_PHASE5C_B_PROVISIONING.md and docs/V040_PHASE8_SIGNING.md.");
    if let Err(e) = run().await {
        eprintln!("FAIL: phase5c provisioning: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s(v: &[&str]) -> Vec<String> { v.iter().map(|x| x.to_string()).collect() }
    fn agent(fill: u8) -> Vec<u8> { AgentPubKey::from_raw_32(vec![fill; 32]).get_raw_39().to_vec() }

    #[test]
    fn every_write_needs_its_own_confirmation() {
        let base = ["--record", "/r", "--agent-b64", "x", "--app-port", "1", "--origin", "http://localhost:1",
                    "--app-token-file", "/t", "--lair-root", "/k"];
        let allowed = with(&["--record"]);
        assert!(Flags::parse(&s(&base), &allowed, Some("--confirm-acceptance-write")).unwrap_err().contains("refusing"));
        let mut wrong = s(&base); wrong.push("--confirm-grant-write".into());
        assert!(Flags::parse(&wrong, &allowed, Some("--confirm-acceptance-write")).is_err(), "other write's flag");
        let mut twice = s(&base); twice.extend(s(&["--confirm-acceptance-write", "--confirm-acceptance-write"]));
        assert!(Flags::parse(&twice, &allowed, Some("--confirm-acceptance-write")).is_err());
        let mut ok = s(&base); ok.push("--confirm-acceptance-write".into());
        assert!(Flags::parse(&ok, &allowed, Some("--confirm-acceptance-write")).is_ok());
        let mut ro = s(&base); ro.push("--confirm-acceptance-write".into());
        assert!(Flags::parse(&ro, &allowed, None).is_err(), "read-only commands take no confirmation");
    }

    #[test]
    fn lair_url_flag_is_not_accepted_anywhere() {
        let mut a = s(&["--record", "/r", "--agent-b64", "x", "--app-port", "1", "--origin", "http://localhost:1",
                        "--app-token-file", "/t"]);
        a.extend(s(&["--lair-url", "unix:///k/socket?k=X"]));
        assert!(Flags::parse(&a, &with(&["--record"]), None).is_err());
    }

    #[test]
    fn missing_repeated_and_relative_inputs_rejected() {
        assert!(Flags::parse(&s(&["--record", "/r"]), &["--record", "--agent-b64"], None).is_err());
        assert!(Flags::parse(&s(&["--record", "/r", "--record", "/s", "--agent-b64", "x"]), &["--record", "--agent-b64"], None).is_err());
        let f = Flags::parse(&s(&["--record", "rel", "--agent-b64", "x"]), &["--record", "--agent-b64"], None).unwrap();
        assert!(f.path("--record").is_err());
    }

    #[test]
    fn ceremony_spec_requires_real_multi_party_threshold() {
        let dna = DnaHash::from_raw_32(vec![2; 32]).get_raw_39().to_vec();
        let (a, b, c) = (agent(10), agent(11), agent(12));
        let spec = ceremony_spec("app", &dna, &[b.clone(), a.clone()], 2, [7; 32]).unwrap();
        assert!(spec.participants.windows(2).all(|w| w[0] < w[1]), "sorted");
        assert!(ceremony_spec("app", &dna, &[a.clone()], 1, [7; 32]).is_err());
        assert!(ceremony_spec("app", &dna, &[a.clone(), b.clone()], 1, [7; 32]).is_err());
        assert!(ceremony_spec("app", &dna, &[a.clone(), b.clone()], 3, [7; 32]).is_err());
        assert!(ceremony_spec("app", &dna, &[a.clone(), a.clone(), b.clone()], 2, [7; 32]).is_err());
        let other = ceremony_spec("app", &dna, &[a.clone(), b.clone(), c.clone()], 2, [7; 32]).unwrap();
        assert_ne!(spec.context_hash, other.context_hash, "context binds the member set");
    }

    #[test]
    fn probe_builder_is_distinct_from_unchanged_frost_builder() {
        let dna=DnaHash::from_raw_32(vec![2;32]).get_raw_39().to_vec();
        let members=vec![agent(10),agent(11)];
        let frost=ceremony_spec("app",&dna,&members,2,[7;32]).unwrap();
        let probe=holochain_mpc_dkg_worker::transport_probe::proposal_spec("app",&dna,&members,[7;32]).unwrap();
        assert_eq!(frost.protocol_id,"frost-ed25519");assert_eq!(frost.max_round,6);
        assert_eq!(probe.protocol_id,"mpc-transport-probe");assert_eq!(probe.max_round,1);
        assert_ne!(probe.context_hash,frost.context_hash);
        assert!(holochain_mpc_dkg_worker::transport_probe::proposal_spec("app",&dna,&members[..1],[7;32]).is_err());
        let mut duplicate=members.clone();duplicate[1]=duplicate[0].clone();
        assert!(holochain_mpc_dkg_worker::transport_probe::proposal_spec("app",&dna,&duplicate,[7;32]).is_err());
        let allowed=with(&["--installed-app-id","--dna-b64","--participants-file","--threshold","--record-out"]);
        assert!(Flags::parse(&s(&["--confirm-source-chain-write"]),&allowed,Some("--confirm-probe-proposal-write")).is_err());
    }

    #[test]
    fn offer_files_are_distinct_per_direction() {
        let (a, b) = (agent(10), agent(11));
        assert_ne!(offer_name(&a, &b), offer_name(&b, &a));
    }
}
