//! Phase 8 approved 2-of-3 signing between independent signing sessions,
//! using shares sealed by a durable DKG and reopened from disk.
//!
//! OFFLINE ONLY: synthetic agents and master keys, an in-memory stand-in for
//! authenticated zome responses, temporary databases. No conductor or Lair.
use holochain_mpc_core::{commitment, Envelope, SessionSpec};
use holochain_mpc_dkg_worker::conductor_bridge::KeyEvidence;
use holochain_mpc_dkg_worker::ipc::{AuthChannel, ChannelContext, Role};
use holochain_mpc_dkg_worker::relay::{LocalDkgNode, MpcTransport, Phase, RelayEngine, SendReceipt};
use holochain_mpc_dkg_worker::signing::{activated_group, run_signing, signed_message, ActivationEvidence,
    ApprovalEvidence, SigningPlan, SigningPoll, SigningSession, SigningTransport, PLAN_SCHEMA};
use holochain_mpc_dkg_worker::{recover_completed_share, AuthenticatedController, Command,
    PeerKeyBinding, Reply, ShareCustody};
use holochain_mpc_frost_ed25519::{self as frost, Binding, SignedArtifact};
use holochain_mpc_runtime::{MasterKey, RuntimeStore};
use holochain_mpc_security::activation::GroupDescriptor;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    Binding::new(vec![0xe8; 39], SessionSpec {
        session_id: commitment("phase8-signing-session", b"test"),
        application_id: "org.example.phase8.signing".into(),
        protocol_id: frost::PROTOCOL_ID.into(), protocol_version: frost::PROTOCOL_VERSION,
        context_hash: commitment("phase8-signing-context", b"test"),
        participants: (1u8..=3).map(|i| vec![i; 39]).collect(),
        threshold: 2, max_round: 6,
    }).unwrap()
}
fn context(binding: &Binding, member: &[u8]) -> ChannelContext {
    ChannelContext { worker_agent: member.to_vec(), proposal_action: binding.proposal_action.clone(),
        session_id: binding.spec.session_id, channel_id: [member[0]; 32] }
}
fn master(member: &[u8]) -> MasterKey { MasterKey::from_bytes([0x50 + member[0]; 32]) }
fn journal(dir: &Path, member: &[u8]) -> PathBuf { dir.join(format!("journal-{}.sqlite", member[0])) }
fn store(dir: &Path, member: &[u8]) -> RuntimeStore { RuntimeStore::open(&journal(dir, member), master(member)).unwrap() }

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
    }
    assert!(relays.iter().all(|r| r.phase() == Phase::Complete));
    relays[0].descriptor().unwrap().clone()
}

/// In-memory stand-in for the pinned conductor's authenticated responses.
#[derive(Default)]
struct SignNet {
    activations: Vec<ActivationEvidence>,
    approvals: Vec<ApprovalEvidence>,
    inbox: BTreeMap<Vec<u8>, Vec<Envelope>>,
    results: Vec<(Vec<u8>, SignedArtifact)>,
    tamper_shares: bool,
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
        let mut net = self.net.lock().unwrap();
        let mut env = env.clone();
        if net.tamper_shares && env.round == 6 {
            // Swap in a well-formed share for the wrong value: aggregation must reject it.
            let mut frame: frost::Frame = serde_json::from_slice(&env.payload).unwrap();
            if let frost::Message::SignatureShare(share) = &frame.message {
                let mut bytes = share.serialize();
                bytes[0] ^= 1;
                frame.message = frost::Message::SignatureShare(frost::SignatureShare::deserialize(&bytes).unwrap());
            }
            env.payload = serde_json::to_vec(&frame).unwrap();
            env.payload_hash = commitment("envelope-payload", &env.payload);
        }
        net.inbox.entry(env.recipient.clone().ok_or("no recipient")?).or_default().push(env);
        Ok(())
    }
    async fn publish_result(&mut self, artifact: &SignedArtifact) -> Result<(), String> {
        self.net.lock().unwrap().results.push((self.local.clone(), artifact.clone()));
        Ok(())
    }
}

struct Fixture { dir: tempfile::TempDir, binding: Binding, descriptor: GroupDescriptor }
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let binding = binding();
    let descriptor = complete_durable_dkg(dir.path(), &binding).await;
    Fixture { dir, binding, descriptor }
}
impl Fixture {
    fn custody(&self, member: &[u8]) -> ShareCustody {
        recover_completed_share(&store(self.dir.path(), member), &context(&self.binding, member),
            &self.descriptor).unwrap()
    }
    fn plan(&self, op: u8, selected: &[u8]) -> SigningPlan {
        SigningPlan { schema: PLAN_SCHEMA, descriptor: self.descriptor.clone(),
            operation_id: commitment("operation", &[op]), message: b"approve transfer #42".to_vec(),
            selected: selected.iter().map(|m| vec![*m; 39]).collect() }
    }
    fn activate_all(&self, net: &Arc<Mutex<SignNet>>) {
        for member in &self.binding.spec.participants {
            net.lock().unwrap().activations.push(ActivationEvidence { author: member.clone(),
                epoch: self.descriptor.epoch, descriptor_hash: self.descriptor.digest().unwrap(),
                dkg_transcript_hash: self.descriptor.dkg_transcript_hash,
                public_key_package_hash: self.descriptor.public_key_package_hash });
        }
    }
    fn approve(&self, net: &Arc<Mutex<SignNet>>, plan: &SigningPlan, who: &[u8]) {
        let active = activated_group(&self.descriptor, &net.lock().unwrap().activations).unwrap().unwrap();
        net.lock().unwrap().approvals.push(ApprovalEvidence { author: vec![who[0]; 39],
            operation_id: plan.operation_id, group_descriptor_hash: active.digest(),
            intent_hash: plan.intent(&active).unwrap().digest().unwrap() });
    }
}
fn poll() -> SigningPoll { SigningPoll { interval: Duration::from_millis(5), max_polls: 200 } }

#[tokio::test]
async fn two_independent_sessions_produce_one_verified_group_signature() {
    let f = fixture().await;
    let net = Arc::new(Mutex::new(SignNet::default()));
    let plan = f.plan(1, &[1, 3]);
    f.activate_all(&net);
    for who in [1, 3] { f.approve(&net, &plan, &[who]); }
    let (mut s1, mut s3) = (store(f.dir.path(), &[1; 39]), store(f.dir.path(), &[3; 39]));
    let mut t1 = SignTransport { net: net.clone(), local: vec![1; 39] };
    let mut t3 = SignTransport { net: net.clone(), local: vec![3; 39] };
    let (a1, a3) = tokio::join!(
        run_signing(&mut t1, &mut s1, f.custody(&[1; 39]), &[1; 39], plan.clone(), poll()),
        run_signing(&mut t3, &mut s3, f.custody(&[3; 39]), &[3; 39], plan.clone(), poll()));
    let (a1, a3) = (a1.unwrap(), a3.unwrap());
    assert_eq!(a1, a3, "independent aggregators must agree byte for byte");
    assert_eq!(a1.public_key, f.descriptor.group_verifying_key);
    frost::verify_artifact(&f.binding, &plan.message, &a1, &f.descriptor.group_verifying_key).unwrap();
    // A plain Ed25519 signature over the domain-separated message (the
    // rehearsal re-checks it with OpenSSL, an independent RFC 8032 verifier).
    assert_eq!(a1.signature.len(), 64);
    assert!(signed_message(&plan).unwrap().starts_with(b"holochain-mpc-frost/ed25519/signature/v1"));
    assert_eq!(net.lock().unwrap().results.len(), 2);

    // The same operation can never be signed again: the deadline and nonce
    // slots are already registered in each signer's journal.
    let active = activated_group(&f.descriptor, &net.lock().unwrap().activations).unwrap().unwrap();
    let approved = holochain_mpc_dkg_worker::signing::approved_intent(&plan, &active,
        &net.lock().unwrap().approvals).unwrap().unwrap();
    assert!(SigningSession::begin(f.custody(&[1; 39]), &[1; 39], plan, active, approved,
        &mut s1, 100, i64::MAX).is_err());
}

#[tokio::test]
async fn no_signature_without_every_selected_approval_or_from_outsiders() {
    let f = fixture().await;
    let net = Arc::new(Mutex::new(SignNet::default()));
    let plan = f.plan(2, &[1, 2]);
    f.activate_all(&net);
    f.approve(&net, &plan, &[1]);
    f.approve(&net, &plan, &[3]); // not selected: grants nothing
    let mut t1 = SignTransport { net: net.clone(), local: vec![1; 39] };
    let short = SigningPoll { interval: Duration::from_millis(1), max_polls: 20 };
    let refused = run_signing(&mut t1, &mut store(f.dir.path(), &[1; 39]), f.custody(&[1; 39]),
        &[1; 39], plan.clone(), short).await.unwrap_err();
    assert!(refused.contains("signing approval"), "{refused}");
    // A non-selected member cannot start a session for this plan.
    let mut t3 = SignTransport { net: net.clone(), local: vec![3; 39] };
    f.approve(&net, &plan, &[2]);
    assert!(run_signing(&mut t3, &mut store(f.dir.path(), &[3; 39]), f.custody(&[3; 39]),
        &[3; 39], plan, poll()).await.is_err());
    assert!(net.lock().unwrap().inbox.is_empty(), "no commitment left any node");
}

#[tokio::test]
async fn conflicting_approval_or_activation_fails_closed() {
    let f = fixture().await;
    let plan = f.plan(3, &[1, 2]);
    let net = Arc::new(Mutex::new(SignNet::default()));
    f.activate_all(&net);
    f.approve(&net, &plan, &[1]);
    // Signer 2 approves a different intent for the same operation id.
    let mut other = plan.clone();
    other.message = b"a different message".to_vec();
    f.approve(&net, &other, &[2]);
    let mut t1 = SignTransport { net: net.clone(), local: vec![1; 39] };
    assert!(run_signing(&mut t1, &mut store(f.dir.path(), &[1; 39]), f.custody(&[1; 39]),
        &[1; 39], plan.clone(), poll()).await.is_err());

    let mut forged = vec![ActivationEvidence { author: vec![2; 39], epoch: 0, descriptor_hash: [9; 32],
        dkg_transcript_hash: f.descriptor.dkg_transcript_hash,
        public_key_package_hash: f.descriptor.public_key_package_hash }];
    assert!(activated_group(&f.descriptor, &forged).is_err(), "attestation of another descriptor");
    forged[0].descriptor_hash = f.descriptor.digest().unwrap();
    assert!(activated_group(&f.descriptor, &forged).unwrap().is_none(), "partial activation waits");
}

#[tokio::test]
async fn tampered_signature_shares_never_yield_a_signature() {
    let f = fixture().await;
    let net = Arc::new(Mutex::new(SignNet { tamper_shares: true, ..SignNet::default() }));
    let plan = f.plan(4, &[2, 3]);
    f.activate_all(&net);
    for who in [2, 3] { f.approve(&net, &plan, &[who]); }
    let (mut s2, mut s3) = (store(f.dir.path(), &[2; 39]), store(f.dir.path(), &[3; 39]));
    let mut t2 = SignTransport { net: net.clone(), local: vec![2; 39] };
    let mut t3 = SignTransport { net: net.clone(), local: vec![3; 39] };
    let (a2, a3) = tokio::join!(
        run_signing(&mut t2, &mut s2, f.custody(&[2; 39]), &[2; 39], plan.clone(), poll()),
        run_signing(&mut t3, &mut s3, f.custody(&[3; 39]), &[3; 39], plan, poll()));
    assert!(a2.is_err() && a3.is_err());
    assert!(net.lock().unwrap().results.is_empty());
}
