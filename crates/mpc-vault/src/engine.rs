//! The vault state machine. Every write goes through here, whether it comes
//! from the HTTP API or from a test.
//!
//! Rules that hold in every path:
//! - the summary shown to a person is decoded from the exact bytes that will
//!   be signed; stored bytes that stop matching their summary refuse all writes;
//! - signing and broadcasting happen at most once per proposal and are never
//!   retried here (uncertain writes); an uncertain broadcast is resolved by
//!   polling the chain for the signature, never by resending;
//! - the approval check, the signature check and the state transition are
//!   all done before the next step starts.
use crate::chain::*;
use crate::node::*;
use crate::store::Store;
use crate::util::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const BANNER: &str = "Development build. Devnet only. Not production custody.";
const NOTES: [&str; 2] = [
    "Policy enforcement (spending limits, allowlists) is not implemented: any proposal that two selected signers approve is signed.",
    "Owners and threshold cannot change without a new DKG, which creates a new vault with a new address.",
];

// ------------------------------------------------------------------ errors

#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    pub action: String,
}
impl ApiError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>, action: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), action: action.into() }
    }
    fn not_found(what: &str) -> Self {
        Self::new(404, "not_found", format!("no such {what}"), format!("List the {what}s and use one of their ids."))
    }
    fn bad(message: impl Into<String>, action: impl Into<String>) -> Self { Self::new(400, "bad_request", message, action) }
    fn store(e: String) -> Self {
        Self::new(500, "store_failed", format!("cannot write vault state: {e}"),
            "Nothing further was done. Check the data directory (space, permissions) and restart the service.")
    }
    fn node(message: impl Into<String>) -> Self {
        Self::new(502, "node_failed", message, "Check the node's conductor and Lair, then read the service log. Nothing was retried.")
    }
    fn chain(e: ChainError) -> Self {
        if e.unavailable {
            Self::new(502, "chain_unavailable", format!("the chain is unreachable: {e}"), "Check network access to the chain RPC and try again.")
        } else {
            Self::bad(e.message, "Fix the request and try again.")
        }
    }
}
type Res<T> = Result<T, ApiError>;

// ----------------------------------------------------------------- records

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State { Proposed, Approved, Signed, Broadcast, Confirmed, Rejected, Expired, Failed }

impl State {
    pub fn can_go(self, to: State) -> bool {
        use State::*;
        matches!((self, to),
            (Proposed, Approved | Rejected | Expired | Failed)
            | (Approved, Approved | Signed | Rejected | Expired | Failed)
            | (Signed, Broadcast | Confirmed | Failed)
            | (Broadcast, Confirmed | Failed))
    }
    pub fn is_terminal(self) -> bool { matches!(self, State::Confirmed | State::Rejected | State::Expired | State::Failed) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Task { Approving, Signing, Broadcasting }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin { Created, Imported }

#[derive(Clone, Serialize, Deserialize)]
pub struct MemberRec { pub index: usize, pub agent: String, pub raw_hex: String, pub local: bool }

#[derive(Clone, Serialize, Deserialize)]
pub struct VaultRec {
    pub id: String,
    pub name: String,
    pub chain: String,
    pub address: String,
    pub group_key_hex: String,
    pub members: Vec<MemberRec>,
    pub threshold: u16,
    pub created_at: u64,
}
impl VaultRec {
    fn key(&self) -> [u8; 32] { unhex_exact(&self.group_key_hex).expect("validated at creation") }
    fn local(&self) -> &MemberRec { self.members.iter().find(|m| m.local).expect("validated at creation") }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignerRec { pub agent: String, pub raw_hex: String, pub local: bool, pub approved: Option<bool> }

#[derive(Clone, Serialize, Deserialize)]
pub struct BroadcastRec { pub attempted_at: u64, pub uncertain: bool, pub txid: Option<String> }

#[derive(Clone, Serialize, Deserialize)]
pub struct Failure { pub step: String, pub reason: String, pub action: String }

#[derive(Clone, Serialize, Deserialize)]
pub struct TimelineRec { pub at: u64, pub node: Option<String>, pub event: String }

#[derive(Clone, Serialize, Deserialize)]
pub struct ProposalRec {
    pub id: String,
    pub vault_id: String,
    pub state: State,
    pub local_task: Option<Task>,
    pub origin: Origin,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: u64,
    pub operation_id: String,
    pub message_hex: String,
    pub message_sha256: String,
    pub plan: Value,
    pub summary: Summary,
    pub signers: Vec<SignerRec>,
    pub observed_at: u64,
    pub local_approved: bool,
    pub signing_started: bool,
    pub signature_hex: Option<String>,
    pub wire_hex: Option<String>,
    pub broadcast: Option<BroadcastRec>,
    pub failure: Option<Failure>,
    pub timeline: Vec<TimelineRec>,
}
impl ProposalRec {
    fn note(&mut self, at: u64, node: Option<&str>, event: impl Into<String>) {
        self.timeline.push(TimelineRec { at, node: node.map(str::to_owned), event: event.into() });
    }
    fn go(&mut self, to: State, at: u64) -> Res<()> {
        if !self.state.can_go(to) {
            return Err(ApiError::new(500, "internal", format!("illegal transition {:?} -> {to:?}", self.state),
                "This is a bug in the vault service; report it. Nothing was changed."));
        }
        self.state = to;
        self.updated_at = at;
        Ok(())
    }
    fn fail(&mut self, step: &str, reason: String, action: &str, at: u64) {
        self.failure = Some(Failure { step: step.into(), reason: reason.clone(), action: action.into() });
        self.local_task = None;
        self.note(at, None, format!("failed at {step}: {reason}"));
        if self.state.can_go(State::Failed) { self.state = State::Failed; }
        self.updated_at = at;
    }
    fn approvers(&self) -> Vec<String> {
        self.signers.iter().filter(|s| s.approved == Some(true)).map(|s| s.agent.clone()).collect()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Event { pub seq: u64, pub at: String, pub kind: String, pub proposal_id: Option<String>, pub message: String }

// ------------------------------------------------------------------- views

#[derive(Serialize)]
pub struct VaultView {
    pub id: String,
    pub name: String,
    pub chain: String,
    pub address: String,
    pub group_public_key: String,
    pub members: Vec<MemberView>,
    pub threshold: u16,
    pub group_status: &'static str,
    pub balance: Option<Money>,
    pub balance_error: Option<String>,
    pub created_at: String,
    pub notes: Vec<&'static str>,
}
#[derive(Serialize)]
pub struct MemberView { pub index: usize, pub agent: String, pub local: bool }

#[derive(Serialize)]
pub struct ProposalView {
    pub id: String,
    pub vault_id: String,
    pub state: State,
    pub local_task: Option<Task>,
    pub origin: Origin,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: String,
    pub operation_id: String,
    pub message_sha256: String,
    pub message_len: usize,
    pub signers: Vec<SignerView>,
    pub confirmations: ConfirmationsView,
    pub summary: Summary,
    pub integrity: Integrity,
    pub signature: Option<String>,
    pub broadcast: Option<BroadcastView>,
    pub failure: Option<Failure>,
    pub timeline: Vec<TimelineView>,
}
#[derive(Serialize)]
pub struct SignerView { pub agent: String, pub local: bool, pub approved: Option<bool> }
#[derive(Serialize)]
pub struct ConfirmationsView { pub count: usize, pub required: u16, pub approvers: Vec<String>, pub observed_at: String }
#[derive(Serialize)]
pub struct BroadcastView { pub attempted_at: String, pub uncertain: bool, pub txid: Option<String>, pub url: Option<String> }
#[derive(Serialize)]
pub struct TimelineView { pub at: String, pub node: Option<String>, pub event: String }
#[derive(Clone, Serialize, PartialEq, Debug)]
pub struct Integrity { pub status: &'static str, pub detail: Option<String> }

// ------------------------------------------------------------------ engine

#[derive(Clone)]
pub struct EngineConfig {
    /// The proposing node broadcasts once as soon as the signature verifies.
    pub auto_broadcast: bool,
    pub default_expiry_secs: u64,
    pub confirm_poll: Duration,
    /// How long one poller watches the chain before it stops (a refresh polls again).
    pub confirm_budget: Duration,
}
impl Default for EngineConfig {
    fn default() -> Self {
        Self { auto_broadcast: true, default_expiry_secs: 86_400, confirm_poll: Duration::from_secs(3),
            confirm_budget: Duration::from_secs(600) }
    }
}

#[derive(Default)]
struct Data {
    vaults: BTreeMap<String, VaultRec>,
    proposals: BTreeMap<String, ProposalRec>,
    events: Vec<Event>,
    pollers: BTreeSet<String>,
}

struct Inner {
    store: Store,
    data: Mutex<Data>,
    chains: BTreeMap<String, Arc<dyn Chain>>,
    node: Arc<dyn Node>,
    clock: Arc<dyn Clock>,
    cfg: EngineConfig,
}

#[derive(Clone)]
pub struct Engine(Arc<Inner>);

#[derive(Deserialize)]
pub struct NewProposal {
    pub vault_id: String,
    pub recipient: String,
    pub amount: String,
    pub memo: Option<String>,
    pub selected_signers: Option<Vec<String>>,
    pub expires_in_secs: Option<u64>,
}

pub struct Preview { pub summary: Summary, pub message_sha256: String, pub message_len: usize }

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Res<T> {
    tokio::task::spawn_blocking(f).await
        .map_err(|_| ApiError::new(500, "internal", "a worker task panicked", "Nothing was retried; read the service log."))
}

impl Engine {
    /// Load state and settle whatever a previous process left half-done.
    pub fn open(store: Store, chains: Vec<Arc<dyn Chain>>, node: Arc<dyn Node>, clock: Arc<dyn Clock>, cfg: EngineConfig)
        -> Result<Self, String> {
        let mut data = Data::default();
        for v in store.load_all::<VaultRec>("vaults")? { data.vaults.insert(v.id.clone(), v); }
        for p in store.load_all::<ProposalRec>("proposals")? { data.proposals.insert(p.id.clone(), p); }
        data.events = store.load_events()?;
        let chains = chains.into_iter().map(|c| (c.id().to_owned(), c)).collect();
        let engine = Self(Arc::new(Inner { store, data: Mutex::new(data), chains, node, clock, cfg }));
        engine.recover()?;
        Ok(engine)
    }

    fn now(&self) -> u64 { self.0.clock.now() }

    fn chain(&self, id: &str) -> Res<Arc<dyn Chain>> {
        self.0.chains.get(id).cloned().ok_or_else(|| ApiError::bad(format!("chain {id} is not configured"),
            "Use a chain this service was started with."))
    }

    fn event(&self, kind: &str, pid: Option<&str>, message: impl Into<String>) {
        let mut d = self.0.data.lock().unwrap();
        let e = Event { seq: d.events.len() as u64 + 1, at: rfc3339(self.now()), kind: kind.into(),
            proposal_id: pid.map(str::to_owned), message: message.into() };
        if let Err(err) = self.0.store.append_event(&e) { eprintln!("warning: cannot append to the event log: {err}"); }
        d.events.push(e);
    }

    /// Mutate one proposal and persist it before anyone can observe the change.
    fn mutate<R>(&self, id: &str, f: impl FnOnce(&mut ProposalRec, u64) -> Res<R>) -> Res<R> {
        let mut d = self.0.data.lock().unwrap();
        let rec = d.proposals.get_mut(id).ok_or_else(|| ApiError::not_found("proposal"))?;
        let mut work = rec.clone();
        let out = f(&mut work, self.now())?;
        self.0.store.save("proposals", id, &work).map_err(ApiError::store)?;
        *rec = work;
        Ok(out)
    }

    fn vault_of(&self, id: &str) -> Res<VaultRec> {
        self.0.data.lock().unwrap().vaults.get(id).cloned().ok_or_else(|| ApiError::not_found("vault"))
    }

    fn proposal_of(&self, id: &str) -> Res<ProposalRec> {
        self.0.data.lock().unwrap().proposals.get(id).cloned().ok_or_else(|| ApiError::not_found("proposal"))
    }

    // -------------------------------------------------------------- recovery

    fn recover(&self) -> Result<(), String> {
        let ids: Vec<String> = self.0.data.lock().unwrap().proposals.keys().cloned().collect();
        for id in ids {
            let rec = self.proposal_of(&id).map_err(|e| e.message)?;
            let mut poll = matches!(rec.state, State::Signed | State::Broadcast);
            if let Some(task) = rec.local_task {
                self.mutate(&id, |r, at| {
                    r.local_task = None;
                    match task {
                        Task::Approving => {
                            r.note(at, None, "service restarted while the approval was running; outcome unknown");
                            r.failure = Some(Failure { step: "approve".into(), reason: "the service restarted while the approval was running".into(),
                                action: "Press Refresh to check whether the approval was recorded. If not, approve again; the approval tool refuses a duplicate.".into() });
                        }
                        Task::Signing => r.fail("sign", "the service restarted while signing was running; the nonce may be burned".into(),
                            "Do not retry this operation. Create a new proposal.", at),
                        Task::Broadcasting => {
                            // The attempt was journalled before the network call: outcome unknown.
                            r.note(at, None, "service restarted during the broadcast; outcome unknown, polling the chain");
                            if r.state == State::Signed { r.go(State::Broadcast, at)?; }
                            if let Some(b) = r.broadcast.as_mut() { b.uncertain = true; }
                        }
                    }
                    Ok(())
                }).map_err(|e| e.message)?;
                poll = poll || task == Task::Broadcasting;
            }
            if poll { self.spawn_poller(id); }
        }
        Ok(())
    }

    // ---------------------------------------------------------------- vaults

    pub async fn create_vault(&self, name: &str, chain_id: &str) -> Res<VaultView> {
        let name = name.trim();
        if name.is_empty() || name.len() > 64 { return Err(ApiError::bad("name must be 1 to 64 characters", "Choose a shorter name.")); }
        let chain = self.chain(chain_id)?;
        let node = self.0.node.clone();
        let group = blocking(move || node.group()).await?.map_err(|e| ApiError::node(format!("cannot read this node's group: {e}")))?;
        if group.threshold < 2 || group.members.len() < group.threshold as usize || !group.members.contains(&group.local) {
            return Err(ApiError::node("the node's group descriptor is not a usable threshold group"));
        }
        let key_hex = hex(&group.group_key);
        let rec = {
            let d = self.0.data.lock().unwrap();
            if d.vaults.values().any(|v| v.group_key_hex == key_hex) {
                return Err(ApiError::new(409, "vault_exists", "a vault already exists for this group",
                    "Use the existing vault; a group has exactly one vault and one chain."));
            }
            VaultRec { id: format!("vault-{}", random_hex(4)), name: name.into(), chain: chain.id().into(),
                address: chain.address(&group.group_key), group_key_hex: key_hex, threshold: group.threshold,
                members: group.members.iter().enumerate().map(|(i, m)| MemberRec { index: i, agent: holochain_b64(m),
                    raw_hex: hex(m), local: *m == group.local }).collect(),
                created_at: self.now() }
        };
        self.0.store.save("vaults", &rec.id, &rec).map_err(ApiError::store)?;
        self.0.data.lock().unwrap().vaults.insert(rec.id.clone(), rec.clone());
        self.event("vault.created", None, format!("vault {} ({}) on {}", rec.name, rec.address, rec.chain));
        Ok(self.vault_view(&rec, None))
    }

    fn vault_view(&self, v: &VaultRec, balance: Option<Result<Money, ChainError>>) -> VaultView {
        let (balance, balance_error) = match balance {
            Some(Ok(m)) => (Some(m), None),
            Some(Err(e)) => (None, Some(e.message)),
            None => (None, None),
        };
        VaultView { id: v.id.clone(), name: v.name.clone(), chain: v.chain.clone(), address: v.address.clone(),
            group_public_key: v.group_key_hex.clone(),
            members: v.members.iter().map(|m| MemberView { index: m.index, agent: m.agent.clone(), local: m.local }).collect(),
            threshold: v.threshold, group_status: "descriptor_present", balance, balance_error,
            created_at: rfc3339(v.created_at), notes: NOTES.to_vec() }
    }

    pub async fn get_vault(&self, id: &str) -> Res<VaultView> {
        let v = self.vault_of(id)?;
        let chain = self.chain(&v.chain)?;
        let address = v.address.clone();
        let balance = blocking(move || chain.balance(&address)).await?;
        Ok(self.vault_view(&v, Some(balance)))
    }

    pub fn list_vaults(&self) -> Vec<VaultView> {
        self.0.data.lock().unwrap().vaults.values().map(|v| self.vault_view(v, None)).collect()
    }

    // -------------------------------------------------------------- proposals

    async fn build(&self, vault: &VaultRec, req: &NewProposal) -> Res<(Vec<u8>, Summary)> {
        let amount = req.amount.trim();
        if amount.is_empty() || amount.len() > 20 || !amount.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ApiError::bad("amount must be a whole number of base units", "Enter digits only, for example 1000000."));
        }
        let amount: u64 = amount.parse().map_err(|_| ApiError::bad("amount is too large", "Enter a smaller amount."))?;
        if amount == 0 { return Err(ApiError::bad("amount must be positive", "Enter an amount above zero.")); }
        if req.memo.as_deref().map_or(false, |m| m.len() > 140) { return Err(ApiError::bad("memo is longer than 140 bytes", "Shorten the memo.")); }
        let chain = self.chain(&vault.chain)?;
        let (key, recipient, memo) = (vault.key(), req.recipient.trim().to_owned(), req.memo.clone());
        let c = chain.clone();
        let bytes = blocking(move || c.build_transfer(&key, &recipient, amount, memo.as_deref())).await?.map_err(ApiError::chain)?;
        let summary = self.decode_checked(&chain, vault, &bytes)?;
        Ok((bytes, summary))
    }

    /// The only way a summary comes into existence: decoded from the bytes.
    fn decode_checked(&self, chain: &Arc<dyn Chain>, vault: &VaultRec, bytes: &[u8]) -> Res<Summary> {
        if bytes.len() > MAX_MESSAGE {
            return Err(ApiError::new(413, "message_too_large", "the transaction is larger than the 8 KiB signing limit",
                "Build a smaller transaction."));
        }
        let summary = chain.decode(&vault.key(), bytes)
            .map_err(|e| ApiError::bad(format!("cannot decode the transaction: {e}"), "The vault signs only transactions it fully understands."))?;
        if summary.from != vault.address {
            return Err(ApiError::bad("the transaction does not spend from the vault address", "Refused: it would sign a transaction for someone else."));
        }
        Ok(summary)
    }

    pub async fn preview(&self, req: &NewProposal) -> Res<Preview> {
        let vault = self.vault_of(&req.vault_id)?;
        let (bytes, summary) = self.build(&vault, req).await?;
        Ok(Preview { summary, message_sha256: hex(&sha256(&bytes)), message_len: bytes.len() })
    }

    fn selected(&self, vault: &VaultRec, req: &Option<Vec<String>>) -> Res<Vec<MemberRec>> {
        let chosen: Vec<MemberRec> = match req {
            Some(list) => list.iter().map(|a| vault.members.iter().find(|m| &m.agent == a).cloned()
                .ok_or_else(|| ApiError::bad(format!("{a} is not a member of this vault"), "Choose members listed on the vault."))).collect::<Res<_>>()?,
            None => vec![vault.local().clone(), vault.members.iter().find(|m| !m.local).cloned()
                .ok_or_else(|| ApiError::bad("the vault has no other member", "This group cannot reach its threshold."))?],
        };
        let unique: BTreeSet<_> = chosen.iter().map(|m| m.index).collect();
        if unique.len() != chosen.len() || chosen.len() < vault.threshold as usize {
            return Err(ApiError::bad(format!("select at least {} distinct members", vault.threshold), "Pick the signers again."));
        }
        Ok(chosen)
    }

    fn refuse_replay(&self, operation_id: &str, message_sha: &str) -> Res<()> {
        let d = self.0.data.lock().unwrap();
        for p in d.proposals.values() {
            if p.operation_id == operation_id {
                return Err(ApiError::new(409, "replay", "this operation id is already known", "An operation id is single-use. Create a new proposal."));
            }
            if p.message_sha256 == message_sha && !matches!(p.state, State::Rejected | State::Expired | State::Failed) {
                return Err(ApiError::new(409, "replay", format!("the same transaction bytes are already in proposal {}", p.id),
                    "Use that proposal instead of creating another for the same bytes."));
            }
        }
        Ok(())
    }

    fn new_record(&self, vault: &VaultRec, origin: Origin, plan: Value, view: &PlanView, bytes: &[u8], summary: Summary,
                  expires_in: Option<u64>) -> Res<ProposalRec> {
        let expiry = expires_in.unwrap_or(self.0.cfg.default_expiry_secs);
        if !(60..=604_800).contains(&expiry) { return Err(ApiError::bad("expiry must be 60 to 604800 seconds", "Choose an expiry in range.")); }
        let at = self.now();
        let signers = view.selected.iter().map(|raw| {
            let local = vault.local().raw_hex == hex(raw);
            SignerRec { agent: holochain_b64(raw), raw_hex: hex(raw), local, approved: if local { Some(false) } else { None } }
        }).collect();
        let mut rec = ProposalRec { id: format!("prop-{}", random_hex(6)), vault_id: vault.id.clone(), state: State::Proposed,
            local_task: None, origin, created_at: at, updated_at: at, expires_at: at + expiry, operation_id: hex(&view.operation_id),
            message_hex: hex(bytes), message_sha256: hex(&sha256(bytes)), plan, summary, signers, observed_at: at,
            local_approved: false, signing_started: false, signature_hex: None, wire_hex: None, broadcast: None,
            failure: None, timeline: Vec::new() };
        rec.note(at, None, match origin { Origin::Created => "proposal created on this node", Origin::Imported => "proposal imported from another node" });
        Ok(rec)
    }

    fn insert(&self, rec: ProposalRec) -> Res<ProposalRec> {
        self.0.store.save("proposals", &rec.id, &rec).map_err(ApiError::store)?;
        self.0.store.work_dir(&rec.id).map_err(ApiError::store)?;
        self.0.data.lock().unwrap().proposals.insert(rec.id.clone(), rec.clone());
        Ok(rec)
    }

    pub async fn create_proposal(&self, req: &NewProposal) -> Res<ProposalView> {
        let vault = self.vault_of(&req.vault_id)?;
        let (bytes, summary) = self.build(&vault, req).await?;
        let selected = self.selected(&vault, &req.selected_signers)?;
        self.refuse_replay("", &hex(&sha256(&bytes)))?;
        let id_hint = random_hex(6);
        let work = self.0.store.work_dir(&format!("plan-{id_hint}")).map_err(ApiError::store)?;
        let node = self.0.node.clone();
        let (message, raw) = (bytes.clone(), selected.iter().map(|m| unhex(&m.raw_hex).unwrap()).collect::<Vec<_>>());
        let plan = blocking(move || node.make_plan(&message, &raw, &work)).await?.map_err(|e| ApiError::node(format!("make-intent failed: {e}")))?;
        let view = PlanView::parse(&plan).map_err(ApiError::node)?;
        // Trust nothing the plan tool returned without re-checking it against what we built.
        if view.message != bytes || view.group_key != vault.key() || view.selected.len() != selected.len()
            || !selected.iter().all(|m| view.selected.contains(&unhex(&m.raw_hex).unwrap())) {
            return Err(ApiError::node("the plan does not match the transaction that was built; nothing was stored"));
        }
        self.refuse_replay(&hex(&view.operation_id), &hex(&sha256(&bytes)))?;
        let rec = self.insert(self.new_record(&vault, Origin::Created, plan, &view, &bytes, summary, req.expires_in_secs)?)?;
        self.event("proposal.created", Some(&rec.id), format!("{} to {}", rec.summary.amount.display, rec.summary.recipient));
        self.view(&rec)
    }

    pub async fn import_proposal(&self, vault_id: &str, plan: Value, expires_in: Option<u64>) -> Res<ProposalView> {
        let vault = self.vault_of(vault_id)?;
        let view = PlanView::parse(&plan).map_err(|e| ApiError::bad(e, "Import the plan file exactly as the proposing node exported it."))?;
        let members: Vec<Vec<u8>> = vault.members.iter().map(|m| unhex(&m.raw_hex).unwrap()).collect();
        if view.group_key != vault.key() || view.participants != members {
            return Err(ApiError::bad("the plan belongs to another group", "Import it into the vault of that group."));
        }
        let chain = self.chain(&vault.chain)?;
        let summary = self.decode_checked(&chain, &vault, &view.message)?;
        self.refuse_replay(&hex(&view.operation_id), &hex(&sha256(&view.message)))?;
        let rec = self.insert(self.new_record(&vault, Origin::Imported, plan, &view, &view.message.clone(), summary, expires_in)?)?;
        self.event("proposal.imported", Some(&rec.id), format!("{} to {}", rec.summary.amount.display, rec.summary.recipient));
        self.view(&rec)
    }

    /// Time-based transitions. Signing that has started is never expired.
    pub fn tick(&self) {
        let now = self.now();
        let due: Vec<String> = self.0.data.lock().unwrap().proposals.values()
            .filter(|p| matches!(p.state, State::Proposed | State::Approved) && now >= p.expires_at
                && !p.signing_started && p.local_task != Some(Task::Approving) && p.local_task != Some(Task::Signing))
            .map(|p| p.id.clone()).collect();
        for id in due {
            let done = self.mutate(&id, |r, at| {
                if !matches!(r.state, State::Proposed | State::Approved) || r.signing_started { return Ok(false); }
                r.go(State::Expired, at)?;
                r.note(at, None, "expired before it was signed");
                Ok(true)
            });
            if let Ok(true) = done { self.event("proposal.expired", Some(&id), "expired before it was signed"); }
        }
    }

    pub fn list_proposals(&self, vault_id: Option<&str>, state: Option<State>) -> Res<Vec<ProposalView>> {
        self.tick();
        let mut recs: Vec<ProposalRec> = self.0.data.lock().unwrap().proposals.values()
            .filter(|p| vault_id.map_or(true, |v| p.vault_id == v) && state.map_or(true, |s| p.state == s)).cloned().collect();
        recs.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        recs.iter().map(|r| self.view(r)).collect()
    }

    pub fn get_proposal(&self, id: &str) -> Res<ProposalView> {
        self.tick();
        self.view(&self.proposal_of(id)?)
    }

    pub fn plan_of(&self, id: &str) -> Res<Value> { Ok(self.proposal_of(id)?.plan) }

    fn integrity(&self, vault: &VaultRec, rec: &ProposalRec) -> Integrity {
        let mismatch = |d: &str| Integrity { status: "mismatch", detail: Some(d.into()) };
        let Some(bytes) = unhex(&rec.message_hex) else { return mismatch("stored bytes are not valid hex") };
        if hex(&sha256(&bytes)) != rec.message_sha256 { return mismatch("the stored bytes do not match their recorded hash"); }
        let Ok(chain) = self.chain(&vault.chain) else { return mismatch("the vault's chain is not configured") };
        match chain.decode(&vault.key(), &bytes) {
            Err(e) => return mismatch(&format!("the stored bytes no longer decode: {e}")),
            Ok(s) if s != rec.summary => return mismatch("the summary decoded from the bytes differs from the stored summary"),
            Ok(_) => {}
        }
        match PlanView::parse(&rec.plan) {
            Ok(p) if p.message == bytes && hex(&p.operation_id) == rec.operation_id => Integrity { status: "verified", detail: None },
            _ => mismatch("the signing plan's message differs from the proposal's bytes"),
        }
    }

    fn view(&self, rec: &ProposalRec) -> Res<ProposalView> {
        let vault = self.vault_of(&rec.vault_id)?;
        let chain = self.chain(&vault.chain)?;
        let approvers = rec.approvers();
        Ok(ProposalView { id: rec.id.clone(), vault_id: rec.vault_id.clone(), state: rec.state, local_task: rec.local_task,
            origin: rec.origin, created_at: rfc3339(rec.created_at), updated_at: rfc3339(rec.updated_at),
            expires_at: rfc3339(rec.expires_at), operation_id: rec.operation_id.clone(), message_sha256: rec.message_sha256.clone(),
            message_len: rec.message_hex.len() / 2,
            signers: rec.signers.iter().map(|s| SignerView { agent: s.agent.clone(), local: s.local, approved: s.approved }).collect(),
            confirmations: ConfirmationsView { count: approvers.len(), required: vault.threshold, approvers,
                observed_at: rfc3339(rec.observed_at) },
            summary: rec.summary.clone(), integrity: self.integrity(&vault, rec),
            signature: rec.signature_hex.clone(),
            broadcast: rec.broadcast.as_ref().map(|b| BroadcastView { attempted_at: rfc3339(b.attempted_at), uncertain: b.uncertain,
                txid: b.txid.clone(), url: b.txid.as_deref().and_then(|t| chain.explorer_url(t)) }),
            failure: rec.failure.clone(),
            timeline: rec.timeline.iter().map(|t| TimelineView { at: rfc3339(t.at), node: t.node.clone(), event: t.event.clone() }).collect() })
    }

    // -------------------------------------------------------------- approval

    pub async fn approve(&self, id: &str, confirm: bool, message_sha256: &str) -> Res<ProposalView> {
        self.tick();
        let rec = self.proposal_of(id)?;
        let vault = self.vault_of(&rec.vault_id)?;
        let integrity = self.integrity(&vault, &rec);
        if integrity.status != "verified" {
            return Err(ApiError::new(409, "bytes_summary_mismatch", format!("refused: {}", integrity.detail.unwrap_or_default()),
                "Do not approve. The stored proposal was altered; ask the proposer to create a new one."));
        }
        match rec.state {
            State::Expired => return Err(ApiError::new(409, "expired", "this proposal has expired", "Create a new proposal.")),
            State::Proposed | State::Approved => {}
            s => return Err(ApiError::new(409, "bad_state", format!("a {s:?} proposal cannot be approved").to_lowercase(), "Nothing to do for this proposal.")),
        }
        let me = rec.signers.iter().find(|s| s.local)
            .ok_or_else(|| ApiError::new(403, "not_selected", "this node is not one of the selected signers", "Only a selected signer can approve; ask the proposer to select this node."))?;
        if !confirm { return Err(ApiError::bad("explicit confirmation is required", "Send confirm: true after reading the decoded transaction.")); }
        if message_sha256 != rec.message_sha256 {
            return Err(ApiError::new(409, "hash_mismatch", "the hash you confirmed is not the hash of the bytes to be signed",
                "Reload the proposal and review it again before approving."));
        }
        if rec.local_approved || me.approved == Some(true) {
            return Err(ApiError::new(409, "already_approved", "this node already approved this proposal", "Wait for the other signer."));
        }
        self.mutate(id, |r, at| {
            if r.local_task.is_some() { return Err(ApiError::new(409, "busy", "another action is running on this proposal", "Wait for it to finish.")); }
            r.local_task = Some(Task::Approving);
            r.failure = None;
            r.note(at, Some(&vault.local().agent), "approval started");
            Ok(())
        })?;
        let engine = self.clone();
        let id_owned = id.to_owned();
        tokio::spawn(async move { engine.run_approval(&id_owned).await });
        self.view(&self.proposal_of(id)?)
    }

    async fn run_approval(&self, id: &str) {
        let Ok(rec) = self.proposal_of(id) else { return };
        let Ok(vault) = self.vault_of(&rec.vault_id) else { return };
        let local = vault.local().agent.clone();
        let (node, plan, message) = (self.0.node.clone(), rec.plan.clone(), unhex(&rec.message_hex).unwrap_or_default());
        let work = match self.0.store.work_dir(&rec.id) { Ok(w) => w, Err(e) => return self.approval_failed(id, e) };
        let result = blocking(move || node.approve(&plan, &message, &work)).await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return self.approval_failed(id, e.0),
            Err(e) => return self.approval_failed(id, e.message),
        }
        let started = self.mutate(id, |r, at| {
            r.local_approved = true;
            r.signing_started = true;
            r.local_task = Some(Task::Signing);
            for s in r.signers.iter_mut().filter(|s| s.local) { s.approved = Some(true); }
            r.observed_at = at;
            if r.state == State::Proposed || r.state == State::Approved { r.go(State::Approved, at)?; }
            r.note(at, Some(&local), "approved on this node");
            Ok(())
        });
        if started.is_err() { return; }
        self.event("proposal.approved", Some(id), format!("approved on this node ({local})"));
        self.run_signing(id, &vault).await;
    }

    fn approval_failed(&self, id: &str, reason: String) {
        let _ = self.mutate(id, |r, at| {
            r.local_task = None;
            r.failure = Some(Failure { step: "approve".into(), reason: reason.clone(), action:
                "Nothing was signed. Read the reason; if the approval tool says it already approved, press Refresh. Otherwise approve again.".into() });
            r.note(at, None, format!("approval failed: {reason}"));
            Ok(())
        });
        self.event("proposal.approve_failed", Some(id), reason);
    }

    async fn run_signing(&self, id: &str, vault: &VaultRec) {
        let Ok(rec) = self.proposal_of(id) else { return };
        let budget = rec.expires_at.saturating_sub(self.now()).max(30);
        let (node, plan) = (self.0.node.clone(), rec.plan.clone());
        let work = match self.0.store.work_dir(&rec.id) { Ok(w) => w, Err(e) => return self.signing_failed(id, e) };
        let signed = blocking(move || node.sign(&plan, &work, budget)).await;
        let output = match signed {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => return self.signing_failed(id, e.0),
            Err(e) => return self.signing_failed(id, e.message),
        };
        let signature = output.signature;
        // A chain verifies the signature over the transaction bytes themselves. If the group signed anything else
        // (the current signing profile signs a domain-separated wrapper), the signature is useless on chain.
        if output.signed_message != unhex(&rec.message_hex).unwrap_or_default() {
            return self.attach_failed(id, "the group signed different bytes than the transaction: the signing profile signs a domain-separated \
                wrapper (signed-message.bin), not the raw message, so no chain can verify this signature".into());
        }
        // Never keep or broadcast a signature that does not verify over these exact bytes.
        let chain = match self.chain(&vault.chain) { Ok(c) => c, Err(e) => return self.signing_failed(id, e.message) };
        let (key, bytes) = (vault.key(), unhex(&rec.message_hex).unwrap_or_default());
        let c = chain.clone();
        let wire = match blocking(move || c.attach_signature(&key, &bytes, &signature)).await {
            Ok(Ok(w)) => w,
            Ok(Err(e)) => return self.attach_failed(id, e.message),
            Err(e) => return self.attach_failed(id, e.message),
        };
        let stored = self.mutate(id, |r, at| {
            r.signature_hex = Some(hex(&signature));
            r.wire_hex = Some(hex(&wire));
            r.local_task = None;
            // The protocol signs only after every selected signer approved.
            for s in r.signers.iter_mut() { s.approved = Some(true); }
            r.observed_at = at;
            r.go(State::Signed, at)?;
            r.note(at, None, "group signature produced and verified under the vault key");
            Ok(())
        });
        if stored.is_err() { return; }
        self.event("proposal.signed", Some(id), "group signature produced and verified");
        let auto = rec.origin == Origin::Created && self.0.cfg.auto_broadcast;
        if auto {
            let _ = self.broadcast_once(id).await;
        } else {
            self.spawn_poller(id.to_owned());
        }
    }

    fn signing_failed(&self, id: &str, reason: String) {
        let _ = self.mutate(id, |r, at| {
            r.fail("sign", reason.clone(), "Do not retry this operation: its nonce may be burned. Create a new proposal.", at);
            Ok(())
        });
        self.event("proposal.failed", Some(id), format!("signing failed: {reason}"));
    }

    fn attach_failed(&self, id: &str, reason: String) {
        let _ = self.mutate(id, |r, at| {
            r.fail("attach", reason.clone(), "The signature did not verify under the vault key; nothing was broadcast. Create a new proposal.", at);
            Ok(())
        });
        self.event("proposal.failed", Some(id), format!("signature rejected: {reason}"));
    }

    // ---------------------------------------------------------------- reject

    pub fn reject(&self, id: &str, reason: Option<&str>) -> Res<ProposalView> {
        self.tick();
        let rec = self.proposal_of(id)?;
        let vault = self.vault_of(&rec.vault_id)?;
        let reason = reason.unwrap_or("").chars().take(200).collect::<String>();
        let local = vault.local().agent.clone();
        self.mutate(id, |r, at| {
            if r.local_approved || r.local_task.is_some() {
                return Err(ApiError::new(409, "already_approved", "this node already approved or is acting on this proposal",
                    "An approval cannot be retracted. The proposal can only expire or complete."));
            }
            if !matches!(r.state, State::Proposed | State::Approved) {
                return Err(ApiError::new(409, "bad_state", "only an open proposal can be rejected", "Nothing to do for this proposal."));
            }
            r.go(State::Rejected, at)?;
            r.note(at, Some(&local), if reason.is_empty() { "rejected on this node".to_owned() } else { format!("rejected on this node: {reason}") });
            Ok(())
        })?;
        self.event("proposal.rejected", Some(id), "rejected on this node");
        self.view(&self.proposal_of(id)?)
    }

    // --------------------------------------------------------------- refresh

    pub async fn refresh(&self, id: &str) -> Res<ProposalView> {
        self.tick();
        let rec = self.proposal_of(id)?;
        match rec.state {
            State::Proposed | State::Approved => {
                let (node, plan) = (self.0.node.clone(), rec.plan.clone());
                let work = self.0.store.work_dir(&rec.id).map_err(ApiError::store)?;
                let status = blocking(move || node.signing_status(&plan, &work)).await?
                    .map_err(|e| ApiError::node(format!("signing-status failed: {e}")))?;
                self.mutate(id, |r, at| {
                    if !matches!(r.state, State::Proposed | State::Approved) { return Ok(()); }
                    for s in r.signers.iter_mut() {
                        if let Some((_, ok)) = status.approvals.iter().find(|(a, _)| hex(a) == s.raw_hex) {
                            // An approval is never un-observed.
                            s.approved = Some(*ok || s.approved == Some(true));
                        }
                    }
                    r.observed_at = at;
                    if r.signers.iter().any(|s| s.approved == Some(true)) { r.go(State::Approved, at)?; }
                    Ok(())
                })?;
            }
            State::Signed | State::Broadcast => { self.poll_once(id).await?; }
            _ => {}
        }
        self.view(&self.proposal_of(id)?)
    }

    // ------------------------------------------------------------- broadcast

    /// The explicit API call. Refused unless the proposal is signed and was never broadcast.
    pub async fn broadcast(&self, id: &str) -> Res<ProposalView> {
        self.broadcast_once(id).await?;
        self.view(&self.proposal_of(id)?)
    }

    async fn broadcast_once(&self, id: &str) -> Res<()> {
        let rec = self.proposal_of(id)?;
        let vault = self.vault_of(&rec.vault_id)?;
        let integrity = self.integrity(&vault, &rec);
        if integrity.status != "verified" {
            return Err(ApiError::new(409, "bytes_summary_mismatch", "refused: stored bytes and summary disagree",
                "Do not broadcast. The stored proposal was altered."));
        }
        if rec.broadcast.is_some() {
            return Err(ApiError::new(409, "broadcast_attempted", "a broadcast was already attempted for this proposal",
                "Never resend. Press Refresh to see whether the transaction landed."));
        }
        if rec.state != State::Signed {
            return Err(ApiError::new(409, "bad_state", "only a signed proposal can be broadcast", "Wait until the proposal is signed."));
        }
        let chain = self.chain(&vault.chain)?;
        let sig: [u8; 64] = rec.signature_hex.as_deref().and_then(unhex_exact).ok_or_else(|| ApiError::new(500, "internal", "signed proposal has no signature", "Report this bug."))?;
        let wire = rec.wire_hex.as_deref().and_then(unhex).ok_or_else(|| ApiError::new(500, "internal", "signed proposal has no wire transaction", "Report this bug."))?;
        let txid = chain.txid(&sig);
        // Someone else may already have sent it. Reading is safe.
        let c = chain.clone();
        let t = txid.clone();
        if let Ok(Ok(TxStatus::Confirmed)) = blocking(move || c.status(&t)).await {
            self.mutate(id, |r, at| {
                r.go(State::Confirmed, at)?;
                r.note(at, None, "already on chain (sent by another node); nothing was broadcast here");
                Ok(())
            })?;
            self.event("proposal.confirmed", Some(id), "already on chain");
            return Ok(());
        }
        // Journal the attempt BEFORE the network call: after a crash the outcome is unknown, never "not sent".
        self.mutate(id, |r, at| {
            if r.broadcast.is_some() || r.state != State::Signed {
                return Err(ApiError::new(409, "broadcast_attempted", "a broadcast was already attempted", "Never resend."));
            }
            r.broadcast = Some(BroadcastRec { attempted_at: at, uncertain: true, txid: Some(txid.clone()) });
            r.local_task = Some(Task::Broadcasting);
            r.note(at, None, "broadcast attempt journalled");
            Ok(())
        })?;
        let c = chain.clone();
        let outcome = blocking(move || c.broadcast(&wire)).await;
        let outcome = outcome.unwrap_or_else(|e| Err(BroadcastError::Uncertain(e.message)));
        match outcome {
            Ok(_) => {
                self.mutate(id, |r, at| {
                    r.local_task = None;
                    if let Some(b) = r.broadcast.as_mut() { b.uncertain = false; }
                    r.go(State::Broadcast, at)?;
                    r.note(at, None, "broadcast accepted by the network");
                    Ok(())
                })?;
                self.event("proposal.broadcast", Some(id), format!("broadcast {txid}"));
                self.spawn_poller(id.to_owned());
            }
            Err(BroadcastError::Uncertain(why)) => {
                self.mutate(id, |r, at| {
                    r.local_task = None;
                    r.go(State::Broadcast, at)?;
                    r.note(at, None, format!("broadcast outcome unknown: {why}. Polling the chain; it will not be resent."));
                    Ok(())
                })?;
                self.event("proposal.broadcast", Some(id), format!("broadcast outcome unknown ({why}); polling"));
                self.spawn_poller(id.to_owned());
            }
            Err(BroadcastError::Rejected(why)) => {
                // A rejection like "already processed" can mean it landed: read before declaring failure.
                let c = chain.clone();
                let t = txid.clone();
                let landed = matches!(blocking(move || c.status(&t)).await, Ok(Ok(TxStatus::Confirmed)));
                self.mutate(id, |r, at| {
                    r.local_task = None;
                    if let Some(b) = r.broadcast.as_mut() { b.uncertain = false; }
                    if landed {
                        r.go(State::Confirmed, at)?;
                        r.note(at, None, format!("network said \"{why}\" but the transaction is on chain"));
                    } else {
                        r.fail("broadcast", format!("the network rejected the transaction: {why}"),
                            "Nothing was sent. Do not resend. Create a new proposal.", at);
                    }
                    Ok(())
                })?;
                self.event(if landed { "proposal.confirmed" } else { "proposal.failed" }, Some(id), format!("broadcast rejected: {why}"));
            }
        }
        Ok(())
    }

    // --------------------------------------------------------------- polling

    fn spawn_poller(&self, id: String) {
        if !self.0.data.lock().unwrap().pollers.insert(id.clone()) { return; }
        let engine = self.clone();
        tokio::spawn(async move {
            let deadline = Instant::now() + engine.0.cfg.confirm_budget;
            loop {
                match engine.poll_once(&id).await {
                    Ok(true) | Err(_) => break,
                    Ok(false) => {}
                }
                if Instant::now() >= deadline {
                    let _ = engine.mutate(&id, |r, at| {
                        r.note(at, None, "not yet seen on chain; stopped watching. Press Refresh to look again.");
                        Ok(())
                    });
                    break;
                }
                tokio::time::sleep(engine.0.cfg.confirm_poll).await;
            }
            engine.0.data.lock().unwrap().pollers.remove(&id);
        });
    }

    /// One read of the chain. `Ok(true)` once the proposal is final.
    async fn poll_once(&self, id: &str) -> Res<bool> {
        let rec = self.proposal_of(id)?;
        if !matches!(rec.state, State::Signed | State::Broadcast) { return Ok(true); }
        let vault = self.vault_of(&rec.vault_id)?;
        let chain = self.chain(&vault.chain)?;
        let sig: [u8; 64] = rec.signature_hex.as_deref().and_then(unhex_exact).ok_or_else(|| ApiError::new(500, "internal", "no signature", "Report this bug."))?;
        let txid = chain.txid(&sig);
        let status = blocking(move || chain.status(&txid)).await?;
        match status {
            Ok(TxStatus::Confirmed) => {
                self.mutate(id, |r, at| {
                    if !matches!(r.state, State::Signed | State::Broadcast) { return Ok(()); }
                    r.go(State::Confirmed, at)?;
                    r.note(at, None, "confirmed on chain");
                    Ok(())
                })?;
                self.event("proposal.confirmed", Some(id), "confirmed on chain");
                Ok(true)
            }
            Ok(TxStatus::Failed(why)) => {
                self.mutate(id, |r, at| {
                    if !matches!(r.state, State::Signed | State::Broadcast) { return Ok(()); }
                    r.fail("confirm", format!("the chain reports the transaction failed: {why}"),
                        "The transaction is final and failed. Do not resend. Create a new proposal.", at);
                    Ok(())
                })?;
                self.event("proposal.failed", Some(id), format!("failed on chain: {why}"));
                Ok(true)
            }
            Ok(TxStatus::Pending) => Ok(false),
            Err(e) => Err(ApiError::chain(e)),
        }
    }

    // ------------------------------------------------------------ introspect

    pub fn events(&self, after: u64, limit: usize) -> Vec<Event> {
        self.0.data.lock().unwrap().events.iter().filter(|e| e.seq > after).take(limit).cloned().collect()
    }

    /// Test and shutdown helper: wait until a predicate holds on a proposal.
    pub async fn wait_for(&self, id: &str, what: impl Fn(&ProposalView) -> bool, timeout: Duration) -> Res<ProposalView> {
        let end = Instant::now() + timeout;
        loop {
            let v = self.get_proposal(id)?;
            if what(&v) { return Ok(v); }
            if Instant::now() > end {
                return Err(ApiError::new(500, "timeout", format!("timed out; state={:?} task={:?}", v.state, v.local_task), "none"));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Test hook: overwrite a stored proposal (simulates disk tampering).
    pub fn tamper<F: FnOnce(&mut ProposalRec)>(&self, id: &str, f: F) {
        let mut d = self.0.data.lock().unwrap();
        f(d.proposals.get_mut(id).expect("proposal"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transitions() {
        use State::*;
        let all = [Proposed, Approved, Signed, Broadcast, Confirmed, Rejected, Expired, Failed];
        for t in [Confirmed, Rejected, Expired, Failed] {
            assert!(t.is_terminal());
            assert!(all.iter().all(|to| !t.can_go(*to)), "{t:?} is terminal");
        }
        assert!(Proposed.can_go(Approved) && Approved.can_go(Signed) && Signed.can_go(Broadcast) && Broadcast.can_go(Confirmed));
        assert!(!Proposed.can_go(Signed), "no signature without an approval");
        assert!(!Signed.can_go(Approved) && !Broadcast.can_go(Signed) && !Broadcast.can_go(Rejected));
        assert!(!Signed.can_go(Expired), "signed proposals never expire");
    }
}
