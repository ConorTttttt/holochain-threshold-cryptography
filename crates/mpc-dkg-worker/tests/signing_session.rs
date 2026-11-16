//! Phase 8 approved 2-of-3 signing between independent signing sessions,
//! using shares sealed by a durable DKG and reopened from disk.
//!
//! OFFLINE ONLY: synthetic agents and master keys, an in-memory stand-in for
//! authenticated zome responses, temporary databases. No conductor or Lair.
use holochain_mpc_core::{commitment, Envelope, SessionSpec};
use holochain_mpc_dkg_worker::conductor_bridge::KeyEvidence;
use holochain_mpc_dkg_worker::inbox_slots::{InboxSlots, WithheldSlot, StoredVariant};
use holochain_zome_types::prelude::ActionHash;
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
    async fn get_inbox_slots(&mut self) -> Result<InboxSlots,String> {
        Ok(InboxSlots {envelopes:self.shared.lock().unwrap().inbox.get(&self.local)
            .cloned().unwrap_or_default(),..Default::default()})
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
    conflicts: BTreeMap<Vec<u8>,Vec<WithheldSlot>>,
    over_quota: BTreeMap<Vec<u8>,Vec<WithheldSlot>>,
    late_conflict: Option<(Vec<u8>,usize,WithheldSlot)>,
    read_counts: BTreeMap<Vec<u8>,usize>,
}
struct SignTransport { net: Arc<Mutex<SignNet>>, local: Vec<u8> }
impl SigningTransport for SignTransport {
    async fn activations(&mut self) -> Result<Vec<ActivationEvidence>, String> {
        Ok(self.net.lock().unwrap().activations.clone())
    }
    async fn approvals(&mut self) -> Result<Vec<ApprovalEvidence>, String> {
        Ok(self.net.lock().unwrap().approvals.clone())
    }
    async fn inbox_slots(&mut self) -> Result<InboxSlots, String> {
        let mut net=self.net.lock().unwrap();
        let read={let n=net.read_counts.entry(self.local.clone()).or_default();*n+=1;*n};
        let mut slots=InboxSlots {envelopes:net.inbox.get(&self.local).cloned().unwrap_or_default(),
            conflicts:net.conflicts.get(&self.local).cloned().unwrap_or_default(),
            over_quota:net.over_quota.get(&self.local).cloned().unwrap_or_default()};
        if let Some((recipient,after,withheld))=&net.late_conflict {
            if recipient==&self.local && read>=*after {
                slots.envelopes.retain(|env| !(env.sender==withheld.sender &&
                    env.round==withheld.round && env.sequence==withheld.sequence));
                slots.conflicts.push(withheld.clone());
            }
        }
        Ok(slots)
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

fn conflicting_slot(first:Envelope,second:Envelope)->WithheldSlot {
    WithheldSlot {sender:first.sender.clone(),round:first.round,sequence:first.sequence,
        variants:vec![StoredVariant {envelope:first,storage_actions:vec![ActionHash::from_raw_32(vec![91;32])]},
            StoredVariant {envelope:second,storage_actions:vec![ActionHash::from_raw_32(vec![92;32])]}]}
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
async fn selected_signer_late_equivocation_aborts_and_burns_nonce() {
    let f=fixture().await;
    let net=Arc::new(Mutex::new(SignNet::default()));
    let plan=f.plan(30,&[1,3]);
    f.activate_all(&net);
    for who in [1,3] {f.approve(&net,&plan,&[who]);}
    // First poll accepts an authentic commitment from selected peer 3.
    let mut peer=frost::Signer::new(f.binding.clone(),&[3;39],f.custody(&[3;39]).key_package).unwrap();
    let frame=frost::Frame {proposal_action:f.binding.proposal_action.clone(),operation_id:plan.operation_id,
        message:frost::Message::SigningCommitment(peer.commit(plan.operation_id,&plan.message).unwrap())};
    let original=frame.encode(&f.binding,&[3;39],&[1;39],plan.sequence()).unwrap();
    let mut variant=original.clone();variant.payload=b"equivocated signing commitment".to_vec();
    variant.payload_hash=commitment("envelope-payload",&variant.payload);
    net.lock().unwrap().inbox.entry(vec![1;39]).or_default().push(original.clone());
    net.lock().unwrap().late_conflict=Some((vec![1;39],2,conflicting_slot(original,variant)));
    let mut journal=store(f.dir.path(),&[1;39]);
    let mut transport=SignTransport {net:net.clone(),local:vec![1;39]};
    let error=run_signing(&mut transport,&mut journal,f.custody(&[1;39]),&[1;39],
        plan.clone(),poll()).await.unwrap_err();
    assert!(error.contains("conflicting authenticated signing"),"{error}");
    assert!(journal.expire_at(&plan.descriptor.proposal_action,&plan.operation_id,1).unwrap(),
        "late evidence abort must be durable; nonce must not be reusable");
    assert!(net.lock().unwrap().results.is_empty());
}

#[tokio::test]
async fn selected_signing_over_quota_slot_fails_closed() {
    let f=fixture().await;
    let net=Arc::new(Mutex::new(SignNet::default()));
    let plan=f.plan(32,&[1,3]);
    f.activate_all(&net);
    for who in [1,3] {f.approve(&net,&plan,&[who]);}
    let env=Envelope::new(&f.binding.spec,vec![3;39],Some(vec![1;39]),
        6,plan.sequence(),b"withheld share".to_vec()).unwrap();
    net.lock().unwrap().over_quota.entry(vec![1;39]).or_default().push(WithheldSlot {
        sender:env.sender.clone(),round:env.round,sequence:env.sequence,
        variants:vec![StoredVariant {envelope:env,
            storage_actions:vec![ActionHash::from_raw_32(vec![42;32])]}]});
    let mut journal=store(f.dir.path(),&[1;39]);
    let mut transport=SignTransport {net:net.clone(),local:vec![1;39]};
    let error=run_signing(&mut transport,&mut journal,f.custody(&[1;39]),&[1;39],
        plan.clone(),poll()).await.unwrap_err();
    assert!(error.contains("over sender quota"),"{error}");
    assert!(net.lock().unwrap().results.is_empty());
}

#[tokio::test]
async fn unrelated_signing_conflict_does_not_veto_selected_signers() {
    let f=fixture().await;
    let net=Arc::new(Mutex::new(SignNet::default()));
    let plan=f.plan(31,&[1,3]);
    f.activate_all(&net);
    for who in [1,3] {f.approve(&net,&plan,&[who]);}
    // Member 2 is not selected and cannot veto a valid 1+3 signature.
    for recipient in [1_u8,3] {
        let original=Envelope::new(&f.binding.spec,vec![2;39],Some(vec![recipient;39]),
            4,plan.sequence(),b"unselected commitment".to_vec()).unwrap();
        let mut variant=original.clone();variant.payload=b"unselected other commitment".to_vec();
        variant.payload_hash=commitment("envelope-payload",&variant.payload);
        net.lock().unwrap().conflicts.entry(vec![recipient;39]).or_default()
            .push(conflicting_slot(original,variant));
    }
    let (mut s1,mut s3)=(store(f.dir.path(),&[1;39]),store(f.dir.path(),&[3;39]));
    let mut t1=SignTransport {net:net.clone(),local:vec![1;39]};
    let mut t3=SignTransport {net:net.clone(),local:vec![3;39]};
    let (a1,a3)=tokio::join!(
        run_signing(&mut t1,&mut s1,f.custody(&[1;39]),&[1;39],plan.clone(),poll()),
        run_signing(&mut t3,&mut s3,f.custody(&[3;39]),&[3;39],plan,poll())
    );
    assert_eq!(a1.unwrap(),a3.unwrap());
}

// Security review 2026-10-22 R1: approval binds to the operator's own copy
// of the message, never to whatever a public plan file carries.
#[tokio::test]
async fn approval_review_binds_the_operators_own_message() {
    use holochain_mpc_dkg_worker::signing::approval_review;
    use sha2::Digest;
    let f = fixture().await;
    let mut plan = f.plan(5, &[1, 2]);
    let intended = plan.message.clone();
    let review = approval_review(&plan, &intended).unwrap();
    let sha: String = sha2::Sha256::digest(&intended).iter().map(|b| format!("{b:02x}")).collect();
    assert!(review.contains(&format!("message_sha256={sha}")), "{review}");
    plan.message = b"approve transfer #43".to_vec(); // altered in transit
    assert!(approval_review(&plan, &intended).is_err(), "a substituted message must not be approvable");
    plan.message = b"\x1b[2Jpay \x07all".to_vec();
    let review = approval_review(&plan, &plan.message.clone()).unwrap();
    assert!(!review.bytes().any(|b| b == 0x1b || b == 0x07), "control bytes reach the terminal: {review:?}");
}

// R5: a plan that validates must fit the 64 KiB plan and policy readers.
#[tokio::test]
async fn plans_that_validate_fit_every_reader() {
    let f = fixture().await;
    let mut plan = f.plan(6, &[1, 2]);
    plan.message = vec![0xff; 8 * 1024];
    plan.validate().unwrap();
    assert!(serde_json::to_vec(&plan).unwrap().len() <= 48 * 1024);
    plan.message = vec![0xff; 16 * 1024];
    assert!(plan.validate().is_err(), "a plan no reader can load must not validate");
}

// R3: frames from a non-selected member carry no authority and cannot veto.
#[tokio::test]
async fn non_selected_member_frames_are_ignored() {
    let f = fixture().await;
    let net = Arc::new(Mutex::new(SignNet::default()));
    let plan = f.plan(7, &[1, 3]);
    f.activate_all(&net);
    for who in [1, 3] { f.approve(&net, &plan, &[who]); }
    // Member 2 is not selected but knows the public plan and holds grants.
    let mut outsider = frost::Signer::new(f.binding.clone(), &[2; 39], f.custody(&[2; 39]).key_package).unwrap();
    let frame = frost::Frame { proposal_action: f.binding.proposal_action.clone(), operation_id: plan.operation_id,
        message: frost::Message::SigningCommitment(outsider.commit(plan.operation_id, &plan.message).unwrap()) };
    for to in [[1; 39], [3; 39]] {
        let env = frame.encode(&f.binding, &[2; 39], &to, plan.sequence()).unwrap();
        net.lock().unwrap().inbox.entry(to.to_vec()).or_default().push(env);
    }
    let (mut s1, mut s3) = (store(f.dir.path(), &[1; 39]), store(f.dir.path(), &[3; 39]));
    let mut t1 = SignTransport { net: net.clone(), local: vec![1; 39] };
    let mut t3 = SignTransport { net: net.clone(), local: vec![3; 39] };
    let (a1, a3) = tokio::join!(
        run_signing(&mut t1, &mut s1, f.custody(&[1; 39]), &[1; 39], plan.clone(), poll()),
        run_signing(&mut t3, &mut s3, f.custody(&[3; 39]), &[3; 39], plan.clone(), poll()));
    assert_eq!(a1.unwrap(), a3.unwrap());
}

// R4: a run that fails after registering its deadline journals the abort.
#[tokio::test]
async fn failed_run_journals_the_abort() {
    let f = fixture().await;
    let net = Arc::new(Mutex::new(SignNet::default()));
    let plan = f.plan(8, &[1, 2]);
    f.activate_all(&net);
    for who in [1, 2] { f.approve(&net, &plan, &[who]); }
    let mut s1 = store(f.dir.path(), &[1; 39]);
    let mut t1 = SignTransport { net: net.clone(), local: vec![1; 39] };
    let short = SigningPoll { interval: Duration::from_millis(1), max_polls: 20 };
    // Signer 2 never runs, so signer 1 commits and then runs out of budget.
    let err = run_signing(&mut t1, &mut s1, f.custody(&[1; 39]), &[1; 39], plan.clone(), short)
        .await.unwrap_err();
    assert!(err.contains("signature not reached"), "{err}");
    assert!(s1.expire_at(&plan.descriptor.proposal_action, &plan.operation_id, 1).unwrap(),
        "the journal must record the operation as aborted, not open");
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

// Phase 7 hardening, task 2: whatever journal state an earlier attempt at an
// operation left behind when its process ended (deadline only, nonce
// reserved, commitment published, aborted, expired), a new session for that
// operation is refused, and other operations still sign.
#[tokio::test]
async fn begin_refuses_every_prior_journal_state_of_the_operation() {
    use holochain_mpc_dkg_worker::signing::approved_intent;
    use holochain_mpc_frost_ed25519::ControlledSigner;
    let f = fixture().await;
    let net = Arc::new(Mutex::new(SignNet::default()));
    f.activate_all(&net);
    let active = activated_group(&f.descriptor, &net.lock().unwrap().activations).unwrap().unwrap();
    let local = [1_u8; 39];
    for (op, state) in [(20_u8, "deadline"), (21, "reserved"), (22, "published"), (23, "aborted"), (24, "expired")] {
        let plan = f.plan(op, &[1, 2]);
        for who in [1, 2] { f.approve(&net, &plan, &[who]); }
        let approved = approved_intent(&plan, &active, &net.lock().unwrap().approvals).unwrap().unwrap();
        {
            let mut s = store(f.dir.path(), &local);
            let (proposal, id) = (&plan.descriptor.proposal_action, plan.operation_id);
            s.start_deadline(proposal, &id, if state == "expired" { 150 } else { i64::MAX }).unwrap();
            if state == "reserved" { s.reserve_nonce(proposal, plan.descriptor.epoch, &id, &local, 100).unwrap(); }
            if matches!(state, "published" | "aborted" | "expired") {
                let share = f.custody(&local);
                let mut signer = ControlledSigner::new(f.binding.clone(), &local, share.key_package,
                    &share.public_key_package, active.clone()).unwrap();
                signer.prepare(&mut s, &approved, &plan.message, 100).unwrap();
            }
            if state == "aborted" { s.record_abort(proposal, &id, "peer vanished").unwrap(); }
            if state == "expired" { assert!(s.expire_at(proposal, &id, 200).unwrap()); }
        } // the process ends here; only the journal remains
        let mut s = store(f.dir.path(), &local);
        assert!(SigningSession::begin(f.custody(&local), &local, plan.clone(), active.clone(), approved,
            &mut s, 100, i64::MAX).is_err(), "{state}: the operation must not start again");
    }
    let fresh = f.plan(25, &[1, 2]);
    for who in [1, 2] { f.approve(&net, &fresh, &[who]); }
    let (mut s1, mut s2) = (store(f.dir.path(), &[1; 39]), store(f.dir.path(), &[2; 39]));
    let mut t1 = SignTransport { net: net.clone(), local: vec![1; 39] };
    let mut t2 = SignTransport { net: net.clone(), local: vec![2; 39] };
    let (a1, a2) = tokio::join!(
        run_signing(&mut t1, &mut s1, f.custody(&[1; 39]), &[1; 39], fresh.clone(), poll()),
        run_signing(&mut t2, &mut s2, f.custody(&[2; 39]), &[2; 39], fresh, poll()));
    assert_eq!(a1.unwrap(), a2.unwrap());
}

#[tokio::test]
async fn one_locally_completed_share_is_never_implicitly_activated_for_signing() {
    let dir = tempfile::tempdir().unwrap();
    let binding = binding();
    let shared = Arc::new(Mutex::new(Network::default()));
    let mut relays = Vec::new();
    for member in &binding.spec.participants {
        let ctx = context(&binding, member);
        let worker = AuthenticatedController::new_durable([member[0]; 32], ctx.clone(),
            &journal(dir.path(), member), master(member)).unwrap();
        let port = DurablePort { id: member.clone(), binding: binding.clone(),
            host: AuthChannel::new([member[0]; 32], ctx, Role::Host).unwrap(), worker };
        let transport = Transport { shared: shared.clone(), local: member.clone() };
        relays.push(RelayEngine::new(port, transport, binding.clone(), member.clone()).unwrap());
    }
    for relay in &mut relays { relay.start().await.unwrap(); }
    // Deliver broadcasts and attestations until every worker has entered the
    // encrypted-share phase. Do not poll peers further after they enter Shares.
    for _ in 0..20 {
        for relay in &mut relays {
            if !matches!(relay.phase(), Phase::Shares | Phase::Complete) {
                relay.poll_once().await.unwrap();
            }
        }
        if relays.iter().all(|r| r.phase() == Phase::Shares) { break; }
    }
    assert!(relays.iter().all(|r| r.phase() == Phase::Shares));
    // Only participant 1 sees all of its shares and journals Finalize.
    assert_eq!(relays[0].poll_once().await.unwrap().phase, Phase::Complete);
    assert!(relays[1..].iter().all(|r| r.phase() == Phase::Shares));
    let descriptor = relays[0].descriptor().unwrap().clone();
    drop(relays);

    let member = &binding.spec.participants[0];
    let checkpoint = store(dir.path(), member).dkg_checkpoint(&binding.proposal_action,
        member, &binding.spec.session_id).unwrap().unwrap();
    assert_eq!(checkpoint.state, holochain_mpc_runtime::dkg::DkgState::Completed);
    for peer in &binding.spec.participants[1..] {
        let peer_store = store(dir.path(), peer);
        assert_eq!(peer_store.dkg_checkpoint(&binding.proposal_action, peer,
            &binding.spec.session_id).unwrap().unwrap().state,
            holochain_mpc_runtime::dkg::DkgState::Running);
        assert!(recover_completed_share(&peer_store, &context(&binding, peer),
            &descriptor).is_err());
    }
    let custody = recover_completed_share(&store(dir.path(), member),
        &context(&binding, member), &descriptor).unwrap();
    // Share persistence is not a group activation certificate.
    let one_vote = ActivationEvidence { author: member.clone(), epoch: descriptor.epoch,
        descriptor_hash: descriptor.digest().unwrap(),
        dkg_transcript_hash: descriptor.dkg_transcript_hash,
        public_key_package_hash: descriptor.public_key_package_hash };
    assert!(activated_group(&descriptor, &[one_vote.clone()]).unwrap().is_none());

    let net = Arc::new(Mutex::new(SignNet::default()));
    net.lock().unwrap().activations.push(one_vote);
    let plan = SigningPlan { schema: PLAN_SCHEMA, descriptor: descriptor.clone(),
        operation_id: commitment("unactivated-partial-dkg-op", b"test"),
        message: b"must remain unsigned".to_vec(),
        selected: binding.spec.participants[..2].to_vec() };
    let mut transport = SignTransport { net: net.clone(), local: member.clone() };
    let mut local_store = store(dir.path(), member);
    let refused = run_signing(&mut transport, &mut local_store, custody, member, plan,
        SigningPoll { interval: Duration::from_millis(1), max_polls: 3 })
        .await.unwrap_err();
    assert!(refused.contains("group activation"), "{refused}");
    let observed = net.lock().unwrap();
    assert!(observed.inbox.is_empty(), "unactivated share must emit no signing commitments");
    assert!(observed.results.is_empty(), "unactivated share must produce no signature");
}


//
// Sprint 1.7 Agent 23 — legacy signing-slot aliasing and finite proposal inbox.
// These tests intentionally retain the v1 sequence and coordinator wire format.
// Native transport below is simulated; no Holochain conductor runs here.
//

fn colliding_plan(f: &Fixture, op: u8, selected: &[u8]) -> (SigningPlan, SigningPlan) {
    let first = f.plan(op, selected);
    let mut second = first.clone();
    second.operation_id[8] ^= 0x80;
    assert_ne!(first.operation_id, second.operation_id);
    assert_eq!(&first.operation_id[..8], &second.operation_id[..8]);
    first.validate().unwrap();
    second.validate().unwrap();
    (first, second)
}

#[tokio::test]
async fn distinct_operation_ids_can_collide_on_legacy_sequence() {
    let f = fixture().await;
    let (a, b) = colliding_plan(&f, 80, &[1, 3]);
    assert_eq!(a.sequence(), b.sequence(),
        "a 64-bit legacy sequence cannot injectively encode 256-bit operation IDs");
    let active = {
        let net = Arc::new(Mutex::new(SignNet::default()));
        f.activate_all(&net);
        let activations = net.lock().unwrap().activations.clone();
        activated_group(&f.descriptor, &activations).unwrap().unwrap()
    };
    assert_ne!(a.intent(&active).unwrap().digest().unwrap(),
               b.intent(&active).unwrap().digest().unwrap(),
               "the signed intent must still bind the full operation ID");
}

#[tokio::test]
async fn colliding_operations_never_cross_authorize() {
    let f = fixture().await;
    let (a, b) = colliding_plan(&f, 81, &[1, 3]);
    let net = Arc::new(Mutex::new(SignNet::default()));
    f.activate_all(&net);
    let active = activated_group(&f.descriptor, &net.lock().unwrap().activations)
        .unwrap().unwrap();
    f.approve(&net, &a, &[1]);
    f.approve(&net, &a, &[3]);
    let old = net.lock().unwrap().approvals.clone();
    assert!(holochain_mpc_dkg_worker::signing::approved_intent(&a, &active, &old)
        .unwrap().is_some());
    assert!(holochain_mpc_dkg_worker::signing::approved_intent(&b, &active, &old)
        .unwrap().is_none(), "approvals for another full operation ID grant nothing");
    f.approve(&net, &b, &[1]);
    assert!(holochain_mpc_dkg_worker::signing::approved_intent(
        &b, &active, &net.lock().unwrap().approvals).unwrap().is_none());
    f.approve(&net, &b, &[3]);
    assert!(holochain_mpc_dkg_worker::signing::approved_intent(
        &b, &active, &net.lock().unwrap().approvals).unwrap().is_some());
}

#[tokio::test]
async fn colliding_operations_cannot_cross_aggregate() {
    let f = fixture().await;
    let (a, b) = colliding_plan(&f, 82, &[1, 3]);
    let net = Arc::new(Mutex::new(SignNet::default()));
    f.activate_all(&net);
    for who in [1, 3] { f.approve(&net, &a, &[who]); }
    let (mut s1, mut s3) = (store(f.dir.path(), &[1; 39]), store(f.dir.path(), &[3; 39]));
    let mut t1 = SignTransport { net: net.clone(), local: vec![1; 39] };
    let mut t3 = SignTransport { net: net.clone(), local: vec![3; 39] };
    let (r1, r3) = tokio::join!(
        run_signing(&mut t1, &mut s1, f.custody(&[1; 39]), &[1; 39], a.clone(), poll()),
        run_signing(&mut t3, &mut s3, f.custody(&[3; 39]), &[3; 39], a.clone(), poll())
    );
    let artifact = r1.unwrap();
    assert_eq!(r3.unwrap(), artifact);
    frost::verify_artifact(&f.binding, &a.message, &artifact,
        &f.descriptor.group_verifying_key).unwrap();
    assert_ne!(artifact.operation_id, b.operation_id);
    assert_eq!(a.sequence(), b.sequence());

    // The old completed operation's authentic signing frames remain in the
    // cumulative inbox. Even if the new request is separately approved,
    // these cannot be interpreted as authorisation, shares or an aggregate
    // for B. A real coordinator additionally withholds conflicting slots.
    for who in [1, 3] { f.approve(&net, &b, &[who]); }
    let (mut s1b, mut s3b) = (store(f.dir.path(), &[1; 39]), store(f.dir.path(), &[3; 39]));
    let mut t1b = SignTransport { net: net.clone(), local: vec![1; 39] };
    let mut t3b = SignTransport { net: net.clone(), local: vec![3; 39] };
    let (e1, e3) = tokio::join!(
        run_signing(&mut t1b, &mut s1b, f.custody(&[1; 39]), &[1; 39], b.clone(), poll()),
        run_signing(&mut t3b, &mut s3b, f.custody(&[3; 39]), &[3; 39], b.clone(), poll())
    );
    for result in [e1, e3] {
        let error = result.expect_err("cross-operation frames must never aggregate");
        assert!(error.contains("another operation in this slot"), "{error}");
    }
    assert_eq!(net.lock().unwrap().results.len(), 2,
        "the only published artifacts belong to the first operation");
}

fn inbox_quota_envelope(sender: u8, recipient: u8, sequence: u64) -> Envelope {
    let spec = binding().spec;
    Envelope::new(&spec, vec![sender; 39], Some(vec![recipient; 39]),
        4, sequence, b"synthetic-quota-record".to_vec()).unwrap()
}

fn inbox_quota_action(index: u64) -> ActionHash {
    let mut bytes = vec![0_u8; 32];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    bytes[31] = 1;
    ActionHash::from_raw_32(bytes)
}

#[test]
fn per_sender_quota_is_isolated() {
    let quota = mpc::sender_quota(&binding().spec);
    assert_eq!(quota, 2048);
    let mut records = Vec::new();
    for n in 1..=quota as u64 + 1 {
        records.push((inbox_quota_action(n), inbox_quota_envelope(1, 2, n)));
    }
    records.push((inbox_quota_action(quota as u64 + 2),
        inbox_quota_envelope(3, 2, 1)));
    let slots = mpc::partition_inbox(records, quota);
    assert_eq!(slots.envelopes.len(), quota + 1,
        "sender 3's independent slot remains served");
    assert_eq!(slots.over_quota.len(), 1);
    assert_eq!(slots.over_quota[0].sender, vec![1; 39]);
    assert_eq!(slots.over_quota[0].sequence, quota as u64 + 1);
    assert!(slots.envelopes.iter().any(|e| e.sender == vec![3; 39]));
    assert!(slots.conflicts.is_empty());
}

#[test]
fn honest_sender_quota_exhaustion_is_detected() {
    let quota = mpc::sender_quota(&binding().spec);
    let records = (1..=quota as u64 + 1).map(|n|
        (inbox_quota_action(n), inbox_quota_envelope(1, 2, n))
    ).collect::<Vec<_>>();
    let slots = mpc::partition_inbox(records, quota);
    assert_eq!(slots.envelopes.len(), quota);
    assert_eq!(slots.over_quota.len(), 1,
        "relaxed racing writes above quota must be withheld on read");
    assert_eq!(slots.over_quota[0].sequence, quota as u64 + 1);
    // A non-racing receive would return InboxFailure::SenderQuota instead.
    // This is a detection test, not an SDK preflight-expiry implementation.
}

#[tokio::test]
async fn group_renewal_uses_fresh_proposal() {
    let f = fixture().await;
    let net = Arc::new(Mutex::new(SignNet::default()));
    f.activate_all(&net);
    let old_evidence = net.lock().unwrap().activations.clone();
    assert!(activated_group(&f.descriptor, &old_evidence).unwrap().is_some());
    let mut next = f.descriptor.clone();
    next.proposal_action = vec![0xed; 39];
    // Keep the epoch equal deliberately: a fresh proposal must be distinct
    // even if an implementation starts the new group's epoch from the same value.
    next.dkg_transcript_hash = commitment("fresh-proposal-test", b"new transcript");
    next.public_key_package_hash = commitment("fresh-proposal-test", b"new public package");
    assert_ne!(f.descriptor.digest().unwrap(), next.digest().unwrap());
    // Fabricated descriptor/votes exercise only group binding, not a real DKG.
    assert!(!matches!(activated_group(&next, &old_evidence), Ok(Some(_))),
        "old votes cannot activate a fresh proposal even at the same epoch");
    let mut activation = holochain_mpc_security::activation::GroupActivation::new(next.clone()).unwrap();
    let digest = next.digest().unwrap();
    for member in &next.spec.participants { activation.attest(member, digest).unwrap(); }
    assert_eq!(activation.finalize().unwrap().digest(), digest);
}

/// Known-red lifecycle acceptance test. The current API takes only descriptor
/// and attestations; it has no group-expired/remaining-capacity input.
/// Unignore only after a reviewed, durable group-expiration gate is integrated.
#[tokio::test]
#[ignore = "S1-M03 OPEN: exhausted group has no durable expiry/rekey admission gate"]
async fn old_exhausted_group_is_not_silently_reactivated() {
    let f = fixture().await;
    let net = Arc::new(Mutex::new(SignNet::default()));
    f.activate_all(&net);
    let votes = net.lock().unwrap().activations.clone();
    let _consumed_sender_budget = mpc::sender_quota(&f.binding.spec);
    assert!(activated_group(&f.descriptor, &votes).unwrap().is_none(),
        "KNOWN RED: old activation remains valid without an independent expiration gate");
}
