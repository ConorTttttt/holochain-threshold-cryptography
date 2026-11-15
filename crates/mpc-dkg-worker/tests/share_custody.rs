//! Phase 7 durable share custody. Three MAC-authenticated, SQLite-journaled
//! controllers complete a 2-of-3 DKG over an in-memory network, every worker
//! is dropped (a process exit), and the sealed shares are reopened from disk
//! to produce an approved threshold signature.
//!
//! OFFLINE ONLY: synthetic agents and master keys, an in-memory stand-in for
//! authenticated zome responses, temporary databases. No conductor or Lair.
use holochain_mpc_core::{commitment, Envelope, SessionSpec};
use holochain_mpc_dkg_worker::conductor_bridge::KeyEvidence;
use holochain_mpc_dkg_worker::ipc::{AuthChannel, ChannelContext, Role};
use holochain_mpc_dkg_worker::relay::{LocalDkgNode, MpcTransport, Phase, RelayEngine, SendReceipt};
use holochain_mpc_dkg_worker::{recover_completed_share, AuthenticatedController, Command,
    PeerKeyBinding, Reply};
use holochain_mpc_frost_ed25519::{self as frost, Binding, ControlledSigner};
use holochain_mpc_runtime::{MasterKey, RuntimeStore};
use holochain_mpc_security::activation::{GroupActivation, GroupDescriptor, IntentApprovals,
    SigningIntent, SigningProfile};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Network { inbox: BTreeMap<Vec<u8>, Vec<Envelope>>, keys: Vec<KeyEvidence> }
struct Transport { shared: Arc<Mutex<Network>>, local: Vec<u8> }
impl MpcTransport for Transport {
    async fn register_key(&mut self, key: [u8;32]) -> Result<Vec<u8>,String> {
        let action = vec![self.local[0].wrapping_add(9); 39];
        self.shared.lock().unwrap().keys.push(KeyEvidence {
            author: self.local.clone(), action: action.clone(), public_key: key });
        Ok(action)
    }
    async fn get_inbox(&mut self) -> Result<Vec<Envelope>,String> {
        Ok(self.shared.lock().unwrap().inbox.get(&self.local).cloned().unwrap_or_default())
    }
    async fn get_encryption_keys(&mut self) -> Result<Vec<KeyEvidence>,String> {
        Ok(self.shared.lock().unwrap().keys.clone())
    }
    async fn publish(&mut self, env: &Envelope) -> Result<SendReceipt,String> {
        let recipient = env.recipient.clone().ok_or("no recipient")?;
        self.shared.lock().unwrap().inbox.entry(recipient).or_default().push(env.clone());
        Ok(SendReceipt { action: vec![8; 39], already_stored: false })
    }
}

/// The durable worker behind its authenticated IPC gate, as `mpc-node` runs it.
struct DurablePort { id: Vec<u8>, binding: Binding, host: AuthChannel, worker: AuthenticatedController }
impl DurablePort {
    fn invoke(&mut self, cmd: Command) -> Result<Reply,String> {
        let frame = self.host.seal(cmd)?;
        let reply = self.worker.handle(frame)?;
        self.host.open(reply)
    }
}
impl LocalDkgNode for DurablePort {
    fn abort(&mut self) -> Result<(), String> {
        self.worker.abort_on_disconnect().map(|_| ())
    }
    fn initialize(&mut self) -> Result<([u8;32],Vec<Envelope>),String> {
        let Reply::Initialized { local_public_key, outbound } = self.invoke(
            Command::Init { binding: self.binding.clone(), local: self.id.clone() })? else {
            return Err("wrong initialized reply".into());
        };
        Ok((local_public_key, outbound))
    }
    fn deliver(&mut self, env: Envelope) -> Result<Vec<Envelope>,String> {
        let Reply::Delivered { outbound } = self.invoke(Command::Deliver {
            authenticated_sender: env.sender.clone(), envelope: env })? else {
            return Err("wrong deliver reply".into());
        };
        Ok(outbound)
    }
    fn attest(&mut self) -> Result<Vec<Envelope>,String> {
        let Reply::Attesting { outbound } = self.invoke(Command::Attest)? else {
            return Err("wrong attest reply".into());
        };
        Ok(outbound)
    }
    fn round_two(&mut self, records: &[KeyEvidence], _own_key: [u8;32])
        -> Result<([u8;32],Vec<Envelope>),String> {
        let pinned_keys = records.iter().map(|r| PeerKeyBinding {
            member: r.author.clone(), public_key: r.public_key, action: r.action.clone() }).collect();
        let Reply::RoundTwo { transcript_hash, outbound } =
            self.invoke(Command::BeginRoundTwo { pinned_keys })? else {
            return Err("wrong round two reply".into());
        };
        Ok((transcript_hash, outbound))
    }
    fn finalize(&mut self) -> Result<GroupDescriptor,String> {
        let Reply::Completed { descriptor } = self.invoke(Command::Finalize)? else {
            return Err("wrong finalize reply".into());
        };
        Ok(descriptor)
    }
    fn validate_outbound(&self, out: &[Envelope]) -> Result<(),String> {
        out.iter().try_for_each(|env| env.validate_against(&self.binding.spec).map_err(|e| e.to_string()))
    }
}

fn binding() -> Binding {
    Binding::new(vec![0xd7; 39], SessionSpec {
        session_id: commitment("phase7-custody-session", b"test"),
        application_id: "org.example.phase7.custody".into(),
        protocol_id: frost::PROTOCOL_ID.into(), protocol_version: frost::PROTOCOL_VERSION,
        context_hash: commitment("phase7-custody-context", b"test"),
        participants: (1u8..=3).map(|i| vec![i; 39]).collect(),
        threshold: 2, max_round: 6,
    }).unwrap()
}
fn context(binding: &Binding, member: &[u8]) -> ChannelContext {
    ChannelContext { worker_agent: member.to_vec(), proposal_action: binding.proposal_action.clone(),
        session_id: binding.spec.session_id, channel_id: [member[0]; 32] }
}
fn master(member: &[u8]) -> MasterKey { MasterKey::from_bytes([0x40 + member[0]; 32]) }
fn journal(dir: &Path, member: &[u8]) -> PathBuf { dir.join(format!("journal-{}.sqlite", member[0])) }

/// Run the durable 3-party DKG to completion, then drop every worker.
async fn complete_durable_dkg(dir: &Path, binding: &Binding) -> GroupDescriptor {
    let shared = Arc::new(Mutex::new(Network::default()));
    let mut relays = Vec::new();
    for member in &binding.spec.participants {
        let ctx = context(binding, member);
        let worker = AuthenticatedController::new_durable([member[0]; 32], ctx.clone(),
            &journal(dir, member), master(member)).unwrap();
        let port = DurablePort { id: member.clone(), binding: binding.clone(),
            host: AuthChannel::new([member[0]; 32], ctx, Role::Host).unwrap(), worker };
        let transport = Transport { shared: shared.clone(), local: member.clone() };
        relays.push(RelayEngine::new(port, transport, binding.clone(), member.clone()).unwrap());
    }
    for relay in &mut relays { relay.start().await.unwrap(); }
    for _ in 0..20 {
        for relay in &mut relays {
            if relay.phase() != Phase::Complete { relay.poll_once().await.unwrap(); }
        }
        if relays.iter().all(|r| r.phase() == Phase::Complete) { break; }
    }
    assert!(relays.iter().all(|r| r.phase() == Phase::Complete), "durable DKG must complete");
    let descriptor = relays[0].descriptor().unwrap().clone();
    assert!(relays.iter().all(|r| r.descriptor() == Some(&descriptor)));
    descriptor
}

#[tokio::test]
async fn sealed_shares_survive_worker_exit_and_produce_threshold_signature() {
    let dir = tempfile::tempdir().unwrap();
    let binding = binding();
    let descriptor = complete_durable_dkg(dir.path(), &binding).await;
    let members = binding.spec.participants.clone();

    let mut recovered = BTreeMap::new();
    for member in &members {
        let store = RuntimeStore::open(&journal(dir.path(), member), master(member)).unwrap();
        let custody = recover_completed_share(&store, &context(&binding, member), &descriptor).unwrap();
        assert_eq!(custody.binding, binding);
        recovered.insert(member.clone(), custody);
    }

    let mut activation = GroupActivation::new(descriptor.clone()).unwrap();
    for member in &members { activation.attest(member, descriptor.digest().unwrap()).unwrap(); }
    let active = activation.finalize().unwrap();
    let op = commitment("operation", b"phase7 recovered-share signing");
    let msg = b"approved after every worker process exited";
    let intent = SigningIntent::new(&active, op, msg, members[..2].to_vec(),
        SigningProfile::ContextBoundV1).unwrap();
    let mut votes = IntentApprovals::new(intent.clone());
    for member in &members[..2] { votes.approve(member, intent.digest().unwrap()).unwrap(); }
    let approved = votes.finalize().unwrap();

    let mut signers = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for member in &members[..2] {
        let custody = recovered.remove(member).unwrap();
        let id = binding.id_of(member).unwrap();
        let mut store = RuntimeStore::open(&journal(dir.path(), member), master(member)).unwrap();
        let mut signer = ControlledSigner::new(binding.clone(), member, custody.key_package,
            &custody.public_key_package, active.clone()).unwrap();
        store.start_deadline(&binding.proposal_action, &op, 1000).unwrap();
        commitments.insert(id, signer.prepare(&mut store, &approved, msg, 100).unwrap());
        signers.insert(id, (signer, store));
    }
    let package = frost::signing_package(&binding, op, msg, commitments).unwrap();
    let mut collector = frost::AuthenticatedShareCollector::new(binding.clone(), &package).unwrap();
    for (id, (signer, store)) in signers.iter_mut() {
        let share = signer.sign(store, &approved, msg, &package, 100).unwrap();
        collector.ingest(binding.member_for(*id).unwrap(), share, &package).unwrap();
    }
    let public = &recovered.values().next().unwrap().public_key_package;
    let artifact = collector.aggregate(&binding, op, msg, &package, public, &active).unwrap();
    frost::verify_activated_artifact(&binding, msg, &artifact, &active).unwrap();
    assert_eq!(artifact.public_key, descriptor.group_verifying_key);
    assert!(frost::verify_activated_artifact(&binding, b"tampered", &artifact, &active).is_err());
}

#[tokio::test]
async fn recovery_refuses_wrong_descriptor_key_owner_or_second_seal() {
    let dir = tempfile::tempdir().unwrap();
    let binding = binding();
    let descriptor = complete_durable_dkg(dir.path(), &binding).await;
    let member = binding.spec.participants[0].clone();
    let path = journal(dir.path(), &member);
    let store = RuntimeStore::open(&path, master(&member)).unwrap();
    let ctx = context(&binding, &member);

    let mut other_epoch = descriptor.clone();
    other_epoch.epoch = 1;
    let mut other_transcript = descriptor.clone();
    other_transcript.dkg_transcript_hash[0] ^= 1;
    let mut other_key = descriptor.clone();
    other_key.group_verifying_key[0] ^= 1;
    for tampered in [other_epoch, other_transcript, other_key] {
        assert!(recover_completed_share(&store, &ctx, &tampered).is_err());
    }
    // Another member's context has no completed journal in this store.
    let peer = context(&binding, &binding.spec.participants[1]);
    assert!(recover_completed_share(&store, &peer, &descriptor).is_err());
    drop(store);
    // A different master key cannot read the journal or the share.
    let wrong = RuntimeStore::open(&path, MasterKey::from_bytes([0x77; 32])).unwrap();
    assert!(recover_completed_share(&wrong, &ctx, &descriptor).is_err());
    drop(wrong);
    // The custody slot is write-once: nothing can replace the sealed share.
    let mut store = RuntimeStore::open(&path, master(&member)).unwrap();
    assert!(store.seal_share(&binding.proposal_action, descriptor.epoch, &member,
        descriptor.digest().unwrap(), b"replacement").is_err());
    assert!(recover_completed_share(&store, &ctx, &descriptor).is_ok());
}

/// The real `mpc-dkg-worker` child process with a persistent journal.
struct ChildPort {
    id: Vec<u8>, binding: Binding, host: AuthChannel,
    stdin: std::process::ChildStdin, stdout: std::io::BufReader<std::process::ChildStdout>,
}
impl ChildPort {
    fn spawn(binding: &Binding, member: &[u8], db: &Path) -> (Self, std::process::Child) {
        use holochain_mpc_dkg_worker::ipc::{TestBootstrap, TestPersistence};
        use std::io::Write;
        use std::process::{Command as Process, Stdio};
        let ctx = context(binding, member);
        let mut child = Process::new(env!("CARGO_BIN_EXE_mpc-dkg-worker"))
            .arg("--test-authenticated-stdio")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
            .spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        serde_json::to_writer(&mut stdin, &TestBootstrap { context: ctx.clone(), secret: [member[0]; 32],
            persistence: Some(TestPersistence { database_path: db.to_path_buf(),
                master_key: [0x40 + member[0]; 32] }) }).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
        let stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        (Self { id: member.to_vec(), binding: binding.clone(),
            host: AuthChannel::new([member[0]; 32], ctx, Role::Host).unwrap(), stdin, stdout }, child)
    }
    fn invoke(&mut self, cmd: Command) -> Result<Reply,String> {
        use std::io::{BufRead, Write};
        let frame = self.host.seal(cmd)?;
        serde_json::to_writer(&mut self.stdin, &frame).map_err(|e| e.to_string())?;
        self.stdin.write_all(b"\n").and_then(|_| self.stdin.flush()).map_err(|e| e.to_string())?;
        let mut line = String::new();
        if self.stdout.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("worker process exited".into());
        }
        self.host.open(serde_json::from_str(&line).map_err(|e| e.to_string())?)
    }
}
impl LocalDkgNode for ChildPort {
    fn abort(&mut self) -> Result<(), String> {
        // Test-only stdio fixture: the running tombstone forbids restart even
        // when this child is killed before an explicit terminal transition.
        Err("stdio fixture has no authenticated abort command".into())
    }
    fn initialize(&mut self) -> Result<([u8;32],Vec<Envelope>),String> {
        let Reply::Initialized { local_public_key, outbound } = self.invoke(
            Command::Init { binding: self.binding.clone(), local: self.id.clone() })? else {
            return Err("wrong initialized reply".into());
        };
        Ok((local_public_key, outbound))
    }
    fn deliver(&mut self, env: Envelope) -> Result<Vec<Envelope>,String> {
        let Reply::Delivered { outbound } = self.invoke(Command::Deliver {
            authenticated_sender: env.sender.clone(), envelope: env })? else {
            return Err("wrong deliver reply".into());
        };
        Ok(outbound)
    }
    fn attest(&mut self) -> Result<Vec<Envelope>,String> {
        let Reply::Attesting { outbound } = self.invoke(Command::Attest)? else {
            return Err("wrong attest reply".into());
        };
        Ok(outbound)
    }
    fn round_two(&mut self, records: &[KeyEvidence], _own_key: [u8;32])
        -> Result<([u8;32],Vec<Envelope>),String> {
        let pinned_keys = records.iter().map(|r| PeerKeyBinding {
            member: r.author.clone(), public_key: r.public_key, action: r.action.clone() }).collect();
        let Reply::RoundTwo { transcript_hash, outbound } =
            self.invoke(Command::BeginRoundTwo { pinned_keys })? else {
            return Err("wrong round two reply".into());
        };
        Ok((transcript_hash, outbound))
    }
    fn finalize(&mut self) -> Result<GroupDescriptor,String> {
        let Reply::Completed { descriptor } = self.invoke(Command::Finalize)? else {
            return Err("wrong finalize reply".into());
        };
        Ok(descriptor)
    }
    fn validate_outbound(&self, out: &[Envelope]) -> Result<(),String> {
        out.iter().try_for_each(|env| env.validate_against(&self.binding.spec).map_err(|e| e.to_string()))
    }
}

#[tokio::test]
async fn shares_survive_sigkill_of_separate_worker_processes() {
    let dir = tempfile::tempdir().unwrap();
    let binding = binding();
    let shared = Arc::new(Mutex::new(Network::default()));
    let mut children = Vec::new();
    let mut relays = Vec::new();
    for member in &binding.spec.participants {
        let (port, child) = ChildPort::spawn(&binding, member, &journal(dir.path(), member));
        children.push(child);
        let transport = Transport { shared: shared.clone(), local: member.clone() };
        relays.push(RelayEngine::new(port, transport, binding.clone(), member.clone()).unwrap());
    }
    for relay in &mut relays { relay.start().await.unwrap(); }
    for _ in 0..20 {
        for relay in &mut relays {
            if relay.phase() != Phase::Complete { relay.poll_once().await.unwrap(); }
        }
        if relays.iter().all(|r| r.phase() == Phase::Complete) { break; }
    }
    assert!(relays.iter().all(|r| r.phase() == Phase::Complete), "process DKG must complete");
    let descriptor = relays[0].descriptor().unwrap().clone();
    // SIGKILL every worker: no destructor, flush or graceful shutdown runs.
    for child in &mut children { child.kill().unwrap(); child.wait().unwrap(); }
    drop(relays);
    for member in &binding.spec.participants {
        let store = RuntimeStore::open(&journal(dir.path(), member), master(member)).unwrap();
        let custody = recover_completed_share(&store, &context(&binding, member), &descriptor).unwrap();
        assert_eq!(custody.key_package.identifier(), &binding.id_of(member).unwrap());
    }
}

#[test]
fn aborted_ceremony_seals_nothing_recoverable() {
    let dir = tempfile::tempdir().unwrap();
    let binding = binding();
    let member = binding.spec.participants[0].clone();
    let ctx = context(&binding, &member);
    let path = journal(dir.path(), &member);
    let mut host = AuthChannel::new([member[0]; 32], ctx.clone(), Role::Host).unwrap();
    let mut worker = AuthenticatedController::new_durable([member[0]; 32], ctx.clone(), &path,
        master(&member)).unwrap();
    let init = host.seal(Command::Init { binding: binding.clone(), local: member.clone() }).unwrap();
    assert!(worker.handle(init).is_ok());
    // Finalize before any Round-2 share fails closed and aborts the journal.
    assert!(worker.handle(host.seal(Command::Finalize).unwrap()).is_err());
    drop(worker);
    let store = RuntimeStore::open(&path, master(&member)).unwrap();
    let stand_in = GroupDescriptor {
        proposal_action: binding.proposal_action.clone(), spec: binding.spec.clone(), epoch: 0,
        dkg_transcript_hash: [1; 32], public_key_package_hash: [2; 32],
        group_verifying_key: vec![3; 32], encryption_key_binding_actions: vec![vec![4; 39]; 3],
    };
    let refused = recover_completed_share(&store, &ctx, &stand_in).err().unwrap();
    assert!(refused.contains("did not complete"), "{refused}");
}

// ---- v0.4.0 Phase 7 custody hardening ----------------------------------
//
// These tests run the DKG through real `mpc-node serve` processes, exactly as
// the relay service drives them, and reopen shares through `recover_share`,
// the path `mpc-sign` and `activate-group` use. Synthetic agents, temporary
// directories, an in-memory stand-in for the conductor; no Lair.

use holochain_mpc_dkg_worker::conductor_bridge::ConductorBridge;
use holochain_mpc_dkg_worker::node_service::{provision, recover_share, write_descriptor};
use holochain_mpc_dkg_worker::signing::{activated_group, approved_intent, run_signing, ActivationEvidence,
    ApprovalEvidence, SigningPlan, SigningPoll, SigningSession, SigningTransport, PLAN_SCHEMA};
use holochain_mpc_frost_ed25519::SignedArtifact;
use holochain_mpc_security::activation::{ActivatedGroup, ApprovedIntent};
use std::process::Stdio;
use std::time::{Duration, Instant};

/// Provision three node directories as `mpc-node provision` does and complete
/// the DKG through three `mpc-node serve` processes; every process has exited
/// when this returns, and each directory holds the group descriptor.
async fn served_dkg(root: &Path, binding: &Binding) -> (Vec<PathBuf>, GroupDescriptor) {
    let shared = Arc::new(Mutex::new(Network::default()));
    let (mut children, mut relays, mut dirs) = (Vec::new(), Vec::new(), Vec::new());
    for member in &binding.spec.participants {
        let dir = root.join(format!("node-{}", member[0]));
        let ctx = context(binding, member);
        provision(&dir, ctx.clone()).unwrap();
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mpc-node")).arg("serve").arg(&dir)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap();
        let since = Instant::now();
        let bridge = loop {
            match ConductorBridge::connect(&dir, ctx.clone(), binding.clone()) {
                Ok(bridge) => break bridge,
                Err(e) => {
                    assert!(child.try_wait().unwrap().is_none(), "mpc-node serve exited early: {e}");
                    assert!(since.elapsed() < Duration::from_secs(10), "node socket unavailable: {e}");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        let transport = Transport { shared: shared.clone(), local: member.clone() };
        relays.push(RelayEngine::new(bridge, transport, binding.clone(), member.clone()).unwrap());
        children.push(child);
        dirs.push(dir);
    }
    for relay in &mut relays { relay.start().await.unwrap(); }
    for _ in 0..20 {
        for relay in &mut relays {
            if relay.phase() != Phase::Complete { relay.poll_once().await.unwrap(); }
        }
        if relays.iter().all(|r| r.phase() == Phase::Complete) { break; }
    }
    assert!(relays.iter().all(|r| r.phase() == Phase::Complete), "served DKG must complete");
    let descriptor = relays[0].descriptor().unwrap().clone();
    for dir in &dirs { write_descriptor(dir, &descriptor).unwrap(); }
    drop(relays); // closes each node's only connection, so `serve` returns
    for child in &mut children { assert!(child.wait().unwrap().success(), "mpc-node serve must exit cleanly"); }
    (dirs, descriptor)
}

/// In-memory stand-in for the pinned conductor's authenticated responses.
#[derive(Default)]
struct SignNet {
    activations: Vec<ActivationEvidence>,
    approvals: Vec<ApprovalEvidence>,
    inbox: BTreeMap<Vec<u8>, Vec<Envelope>>,
}
struct SignTransport { net: Arc<Mutex<SignNet>>, local: Vec<u8> }
impl SigningTransport for SignTransport {
    async fn activations(&mut self) -> Result<Vec<ActivationEvidence>, String> {
        Ok(self.net.lock().unwrap().activations.clone())
    }
    async fn approvals(&mut self) -> Result<Vec<ApprovalEvidence>, String> {
        Ok(self.net.lock().unwrap().approvals.clone())
    }
    async fn inbox(&mut self) -> Result<Vec<Envelope>, String> {
        Ok(self.net.lock().unwrap().inbox.get(&self.local).cloned().unwrap_or_default())
    }
    async fn publish(&mut self, env: &Envelope) -> Result<(), String> {
        let recipient = env.recipient.clone().ok_or("no recipient")?;
        self.net.lock().unwrap().inbox.entry(recipient).or_default().push(env.clone());
        Ok(())
    }
    async fn publish_result(&mut self, _: &SignedArtifact) -> Result<(), String> { Ok(()) }
}

fn plan(descriptor: &GroupDescriptor, op: &[u8], selected: &[u8]) -> SigningPlan {
    SigningPlan { schema: PLAN_SCHEMA, descriptor: descriptor.clone(),
        operation_id: commitment("phase7-hardening-operation", op),
        message: b"custody hardening test transfer".to_vec(),
        selected: selected.iter().map(|m| vec![*m; 39]).collect() }
}
/// Every member attests the group, and every selected signer approves `plan`.
fn authorize(net: &Arc<Mutex<SignNet>>, plan: &SigningPlan) {
    let d = &plan.descriptor;
    let mut net = net.lock().unwrap();
    net.activations = d.spec.participants.iter().map(|m| ActivationEvidence { author: m.clone(), epoch: d.epoch,
        descriptor_hash: d.digest().unwrap(), dkg_transcript_hash: d.dkg_transcript_hash,
        public_key_package_hash: d.public_key_package_hash }).collect();
    let active = activated_group(d, &net.activations).unwrap().unwrap();
    for who in &plan.selected {
        net.approvals.push(ApprovalEvidence { author: who.clone(), operation_id: plan.operation_id,
            group_descriptor_hash: active.digest(), intent_hash: plan.intent(&active).unwrap().digest().unwrap() });
    }
}
fn authorizations(plan: &SigningPlan) -> (ActivatedGroup, ApprovedIntent) {
    let net = Arc::new(Mutex::new(SignNet::default()));
    authorize(&net, plan);
    let net = net.lock().unwrap();
    let active = activated_group(&plan.descriptor, &net.activations).unwrap().unwrap();
    let approved = approved_intent(plan, &active, &net.approvals).unwrap().unwrap();
    (active, approved)
}
fn poll() -> SigningPoll { SigningPoll { interval: Duration::from_millis(5), max_polls: 200 } }
fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}
/// The two selected nodes reopen their shares through `recover_share`, as
/// `mpc-sign` does, and sign. Returns the verified group signature.
async fn sign(dirs: &[PathBuf], plan: &SigningPlan) -> Result<SignedArtifact, String> {
    let net = Arc::new(Mutex::new(SignNet::default()));
    authorize(&net, plan);
    let (a, b) = (plan.selected[0][0], plan.selected[1][0]);
    let dir = |m: u8| &dirs[usize::from(m) - 1];
    let (_, mut store_a, share_a) = recover_share(dir(a), &plan.descriptor).map_err(|e| e.to_string())?;
    let (_, mut store_b, share_b) = recover_share(dir(b), &plan.descriptor).map_err(|e| e.to_string())?;
    let (agent_a, agent_b) = ([a; 39], [b; 39]);
    let mut ta = SignTransport { net: net.clone(), local: agent_a.to_vec() };
    let mut tb = SignTransport { net: net.clone(), local: agent_b.to_vec() };
    let (ra, rb) = tokio::join!(
        run_signing(&mut ta, &mut store_a, share_a, &agent_a, plan.clone(), poll()),
        run_signing(&mut tb, &mut store_b, share_b, &agent_b, plan.clone(), poll()));
    let (ra, rb) = (ra?, rb?);
    assert_eq!(ra, rb, "independent aggregators must agree");
    frost::verify_artifact(&plan.binding()?, &plan.message, &ra, &plan.descriptor.group_verifying_key)
        .map_err(|e| e.to_string())?;
    Ok(ra)
}
fn journal_side(dir: &Path, suffix: &str) -> PathBuf { dir.join(format!("journal.sqlite{suffix}")) }
/// An operator's file-level copy of a stopped node's journal.
fn copy_journal(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    ["", "-wal", "-shm"].iter().map(|s| journal_side(dir, s))
        .filter_map(|p| std::fs::read(&p).ok().map(|bytes| (p, bytes))).collect()
}
fn restore_journal(dir: &Path, files: &[(PathBuf, Vec<u8>)]) {
    use std::os::unix::fs::OpenOptionsExt;
    for s in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(journal_side(dir, s)); }
    for (path, bytes) in files {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
        std::io::Write::write_all(&mut file, bytes).unwrap();
    }
}

/// Task 1 (R3): an operator restores an older copy of node 1's journal after
/// node 1 burned a nonce in a completed signing. The signer must refuse to
/// reopen the share. Uses only the pre-hardening API, so it also runs, and
/// fails, against the Phase 8 tree.
#[tokio::test]
async fn restored_journal_snapshot_is_refused_after_a_nonce_was_burned() {
    let root = tempfile::tempdir().unwrap();
    let binding = binding();
    let (dirs, descriptor) = served_dkg(root.path(), &binding).await;
    let snapshot = copy_journal(&dirs[0]);
    let plan = plan(&descriptor, b"burned", &[1, 3]);
    sign(&dirs, &plan).await.unwrap();
    restore_journal(&dirs[0], &snapshot);
    match recover_share(&dirs[0], &descriptor) {
        Err(refused) => assert!(refused.to_string().contains("anti-rollback"), "{refused}"),
        Ok((context, mut store, custody)) => {
            let (active, approved) = authorizations(&plan);
            let now = now_ms();
            let again = SigningSession::begin(custody, &context.worker_agent, plan.clone(), active, approved,
                &mut store, now, now + 60_000);
            panic!("the restored journal was accepted; a second signing session for the burned operation was {}",
                if again.is_ok() { "started" } else { "refused by the journal itself" });
        }
    }
}

const CRASH_STEPS: [&str; 6] = ["deadline", "reserved", "published", "signed", "aborted", "expired"];
fn crash(step: &str) -> ! {
    println!("CRASH-POINT {step}");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    std::process::abort();
}

/// Child half of `nonce_is_never_reissued_after_a_crash_at_any_journal_step`:
/// runs one operation's journal steps up to `MPC_CRASH_STEP`, then aborts the
/// process (SIGABRT: no destructor, flush or rollback runs). Does nothing
/// unless that test re-runs this binary with the variable set.
#[tokio::test]
async fn zz_crash_child_for_journal_steps() {
    let Ok(step) = std::env::var("MPC_CRASH_STEP") else { return };
    let var = |name: &str| PathBuf::from(std::env::var(name).unwrap());
    let plan: SigningPlan = serde_json::from_slice(&std::fs::read(var("MPC_CRASH_PLAN")).unwrap()).unwrap();
    let (context, mut store, custody) = recover_share(&var("MPC_CRASH_DIR"), &plan.descriptor).unwrap();
    let (active, approved) = authorizations(&plan);
    let (proposal, op, epoch) = (plan.descriptor.proposal_action.clone(), plan.operation_id, plan.descriptor.epoch);
    let local = context.worker_agent.clone();
    let now = now_ms();
    if step == "deadline" || step == "reserved" {
        store.start_deadline(&proposal, &op, now + 60_000).unwrap();
        if step == "deadline" { crash(&step) }
        store.reserve_nonce(&proposal, epoch, &op, &local, now).unwrap();
        crash(&step)
    }
    let binding = plan.binding().unwrap();
    let mut signer = ControlledSigner::new(binding.clone(), &local, custody.key_package,
        &custody.public_key_package, active.clone()).unwrap();
    let deadline = if step == "expired" { now + 1 } else { now + 60_000 };
    store.start_deadline(&proposal, &op, deadline).unwrap();
    // Reserve, commit in memory, burn ("published"); only then is it released.
    let own = signer.prepare(&mut store, &approved, &plan.message, now).unwrap();
    match step.as_str() {
        "published" => crash(&step),
        "aborted" => {
            store.record_abort(&proposal, &op, "failed after the commitment left").unwrap();
            crash(&step)
        }
        "expired" => {
            std::thread::sleep(Duration::from_millis(5));
            assert!(store.expire_at(&proposal, &op, now_ms()).unwrap());
            crash(&step)
        }
        "signed" => {
            // The peer commits too, so this node can compute its share.
            let (peer, mut peer_store, peer_share) = recover_share(&var("MPC_CRASH_PEER"), &plan.descriptor).unwrap();
            let mut peer_signer = ControlledSigner::new(binding.clone(), &peer.worker_agent, peer_share.key_package,
                &peer_share.public_key_package, active).unwrap();
            peer_store.start_deadline(&proposal, &op, deadline).unwrap();
            let theirs = peer_signer.prepare(&mut peer_store, &approved, &plan.message, now).unwrap();
            let commitments = BTreeMap::from([(binding.id_of(&local).unwrap(), own),
                (binding.id_of(&peer.worker_agent).unwrap(), theirs)]);
            let package = frost::signing_package(&binding, op, &plan.message, commitments).unwrap();
            signer.sign(&mut store, &approved, &plan.message, &package, now_ms()).unwrap();
            crash(&step) // the share never leaves the process
        }
        other => panic!("unknown crash step {other}"),
    }
}

fn nonce_state(dir: &Path, plan: &SigningPlan, signer: &[u8]) -> Option<String> {
    use rusqlite::OptionalExtension;
    rusqlite::Connection::open(dir.join("journal.sqlite")).unwrap()
        .query_row("SELECT state FROM nonces WHERE operation=?1 AND signer=?2",
            rusqlite::params![plan.operation_id.as_slice(), signer], |r| r.get(0)).optional().unwrap()
}

/// Task 2: the signer process is killed right after each journal step of one
/// operation. After every crash the journal is still accepted by its anchor
/// (a crash is not a rollback), the operation can never be started again, and
/// a nonce slot that was reserved or burned is never reserved again.
#[tokio::test]
async fn nonce_is_never_reissued_after_a_crash_at_any_journal_step() {
    let root = tempfile::tempdir().unwrap();
    let binding = binding();
    let (dirs, descriptor) = served_dkg(root.path(), &binding).await;
    for step in CRASH_STEPS {
        let plan = plan(&descriptor, step.as_bytes(), &[1, 2]);
        let plan_file = root.path().join(format!("plan-{step}.json"));
        std::fs::write(&plan_file, serde_json::to_vec(&plan).unwrap()).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["zz_crash_child_for_journal_steps", "--exact", "--nocapture", "--test-threads=1"])
            .env("MPC_CRASH_STEP", step).env("MPC_CRASH_DIR", &dirs[0]).env("MPC_CRASH_PEER", &dirs[1])
            .env("MPC_CRASH_PLAN", &plan_file).output().unwrap();
        assert!(!child.status.success(), "{step}: the child must crash");
        assert!(String::from_utf8_lossy(&child.stdout).contains(&format!("CRASH-POINT {step}")),
            "{step}: the child did not reach its crash point: {}", String::from_utf8_lossy(&child.stderr));

        let (context, mut store, custody) = recover_share(&dirs[0], &descriptor)
            .unwrap_or_else(|e| panic!("{step}: a crashed node must reopen: {e}"));
        let expected = match step {
            "deadline" => None,
            "reserved" => Some("reserved"),
            "published" | "signed" => Some("published"),
            _ => Some("burned"),
        };
        assert_eq!(nonce_state(&dirs[0], &plan, &context.worker_agent).as_deref(), expected, "{step}");
        let (active, approved) = authorizations(&plan);
        let now = now_ms();
        assert!(SigningSession::begin(custody, &context.worker_agent, plan.clone(), active, approved,
            &mut store, now, now + 60_000).is_err(), "{step}: the operation must not start again");
        if expected.is_some() {
            assert!(store.reserve_nonce(&descriptor.proposal_action, descriptor.epoch, &plan.operation_id,
                &context.worker_agent, now).is_err(), "{step}: the nonce slot must not be reserved again");
        }
    }
    // Each crash cost only its own operation: a new one still signs 2-of-3.
    sign(&dirs, &plan(&descriptor, b"after the crashes", &[1, 2])).await.unwrap();
}

fn custody_check(dir: &Path) -> std::process::Output {
    std::process::Command::new("bash")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/custody_check.sh"))
        .arg(dir).output().unwrap()
}
fn listing(root: &Path) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        out.push(format!("{} {:o} {} {}", path.display(), meta.mode(), meta.len(), meta.mtime_nsec()));
        if meta.is_dir() { out.extend(listing(&path)); }
    }
    out.sort();
    out
}

/// Task 3: `mpc-node serve` refuses an unsafe custody layout before touching
/// any DKG state, and `scripts/custody_check.sh` reports the same directory
/// without changing anything.
#[test]
fn serve_refuses_unsafe_custody_and_custody_check_reports_it() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let binding = binding();
    let dir = root.path().join("node-1");
    provision(&dir, context(&binding, &binding.spec.participants[0])).unwrap();
    let serve = || std::process::Command::new(env!("CARGO_BIN_EXE_mpc-node")).arg("serve").arg(&dir).output().unwrap();
    let chmod = |path: &Path, mode: u32| std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();

    let before = listing(root.path());
    let audit = custody_check(&dir);
    let report = String::from_utf8_lossy(&audit.stdout).to_string();
    assert!(audit.status.success(), "{report}{}", String::from_utf8_lossy(&audit.stderr));
    assert!(report.contains("WARN") && report.contains("development layout"), "{report}");
    assert_eq!(listing(root.path()), before, "custody_check.sh must not change anything");

    let key = dir.join("storage.key");
    chmod(&key, 0o644);
    let refused = serve();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("unsafe custody layout"),
        "{}", String::from_utf8_lossy(&refused.stderr));
    let audit = custody_check(&dir);
    assert_eq!(audit.status.code(), Some(1), "{}", String::from_utf8_lossy(&audit.stdout));
    assert!(String::from_utf8_lossy(&audit.stdout).contains("FAIL"));
    chmod(&key, 0o600);

    let anchor = root.path().join("node-1.custody-anchor");
    std::fs::rename(&anchor, root.path().join("elsewhere")).unwrap();
    let refused = serve();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("anti-rollback"),
        "{}", String::from_utf8_lossy(&refused.stderr));
    assert_eq!(custody_check(&dir).status.code(), Some(1));
    std::fs::rename(root.path().join("elsewhere"), &anchor).unwrap();
    assert!(!dir.join("journal.sqlite").exists() && !dir.join("controller.sock").exists(),
        "refused before any DKG state or socket was created");
}

/// Task 4: an encrypted backup restores a lost node, which then signs 2-of-3
/// with another node; the same backup is refused once it is older than the
/// node's anti-rollback evidence.
#[tokio::test]
async fn restored_backup_signs_two_of_three_and_a_stale_backup_is_refused() {
    use holochain_mpc_runtime::custody::{self, Custody};
    let root = tempfile::tempdir().unwrap();
    let binding = binding();
    let (dirs, descriptor) = served_dkg(root.path(), &binding).await;
    // The operator keeps the master key apart from the encrypted bundle.
    let key = custody::read_key_file(&dirs[0].join("storage.key")).unwrap();
    let bundle = root.path().join("node-1.backup");
    Custody::load(&dirs[0]).unwrap().backup(&bundle).unwrap();

    std::fs::remove_dir_all(&dirs[0]).unwrap(); // node 1's state directory is lost
    custody::restore(&bundle, &dirs[0], &key).unwrap();
    assert!(!dirs[0].join("ipc.key").exists(), "the DKG-only IPC key is not backed up");
    let artifact = sign(&dirs, &plan(&descriptor, b"after restore", &[1, 3])).await.unwrap();
    assert_eq!(artifact.public_key, descriptor.group_verifying_key);

    // Node 1 burned a nonce after the backup: the bundle is now stale.
    std::fs::remove_dir_all(&dirs[0]).unwrap();
    let refused = custody::restore(&bundle, &dirs[0], &key).err().unwrap().to_string();
    assert!(refused.contains("anti-rollback") && refused.contains("older"), "{refused}");
    assert!(!dirs[0].exists());
}

/// Task 5: retiring an epoch on a node stops it signing in that epoch; the
/// other two nodes still form a quorum. Erasure cannot be undone by restoring
/// a backup taken before it.
#[tokio::test]
async fn retired_epoch_stops_one_node_and_erasure_survives_a_restore_attempt() {
    use holochain_mpc_runtime::custody::{self, Custody};
    use holochain_mpc_runtime::lifecycle::EpochState;
    let root = tempfile::tempdir().unwrap();
    let binding = binding();
    let (dirs, descriptor) = served_dkg(root.path(), &binding).await;
    let key = custody::read_key_file(&dirs[1].join("storage.key")).unwrap();
    let bundle = root.path().join("node-2.backup");
    Custody::load(&dirs[1]).unwrap().backup(&bundle).unwrap();

    let custody = Custody::load(&dirs[1]).unwrap();
    let mut store = custody.open_journal().unwrap();
    store.retire_epoch(&descriptor.proposal_action, descriptor.epoch, now_ms(), "rotated to a new group").unwrap();
    drop(store);
    let refused = recover_share(&dirs[1], &descriptor).err().unwrap().to_string();
    assert!(refused.contains("retired"), "{refused}");
    assert!(sign(&dirs, &plan(&descriptor, b"needs node 2", &[2, 3])).await.is_err());
    sign(&dirs, &plan(&descriptor, b"nodes 1 and 3", &[1, 3])).await.unwrap();

    let mut store = custody.open_journal().unwrap();
    assert_eq!(store.erase_share(&descriptor.proposal_action, descriptor.epoch, now_ms()).unwrap(), 1);
    assert_eq!(store.epoch_state(&descriptor.proposal_action, descriptor.epoch).unwrap(), EpochState::Erased);
    drop(store);
    let elsewhere = root.path().join("node-2-restored");
    let refused = custody::restore(&bundle, &elsewhere, &key).err().unwrap().to_string();
    assert!(refused.contains("anti-rollback"), "{refused}");
}
