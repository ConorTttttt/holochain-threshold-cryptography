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
