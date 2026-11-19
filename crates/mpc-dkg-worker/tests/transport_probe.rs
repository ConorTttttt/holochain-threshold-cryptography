//! OFFLINE ONLY: synthetic identities/credentials, temporary DBs and a mock
//! coordinator. No Lair, websocket, conductor, source-chain write or DKG start.
use holochain_mpc_core::{commitment, Envelope, SealedPacket};
use holochain_mpc_dkg_worker::{
    capability_exchange::CeremonyRecord,
    conductor_bridge::KeyEvidence,
    lair_signer::{SignerPolicy, SignerPolicyFile},
    probe_signer::*,
    relay::{MpcTransport, SendReceipt},
    signed_call_policy::validate_signed_envelope,
    socket_signer::{SignerBinding, SignerRequest},
    transport_channel::DurableTransportChannel,
    transport_probe::*,
};
use holochain_mpc_runtime::{
    transport_key::TransportKeyBinding, MasterKey, Received, RuntimeStore,
};
use holochain_zome_types::prelude::*;
use std::{
    path::{Path, PathBuf},
    process::Command,
};

const MESSAGE: &[u8] = b"synthetic offline probe";
fn raw_agent(n: u8) -> Vec<u8> {
    AgentPubKey::from_raw_32(vec![n; 32]).get_raw_39().to_vec()
}
fn binding(p: &ProbePlan, who: &[u8]) -> TransportKeyBinding {
    TransportKeyBinding {
        dna: p.record.dna_hash.as_slice().try_into().unwrap(),
        agent: who.try_into().unwrap(),
        proposal: p.record.proposal_action.as_slice().try_into().unwrap(),
        session: p.record.spec.session_id,
    }
}
fn master(p: &ProbePlan, who: &[u8]) -> MasterKey {
    MasterKey::from_bytes(if who == p.sender { [7; 32] } else { [8; 32] })
}
fn db(root: &Path, p: &ProbePlan, who: &[u8]) -> PathBuf {
    root.join(if who == p.sender {
        "a.sqlite"
    } else {
        "b.sqlite"
    })
}
fn load(root: &Path, p: &ProbePlan, who: &[u8]) -> (RuntimeStore, DurableTransportChannel) {
    let s = RuntimeStore::open(&db(root, p, who), master(p, who)).unwrap();
    let c = DurableTransportChannel::recover(&s, &binding(p, who)).unwrap();
    (s, c)
}
fn endpoint(root: &Path, p: &ProbePlan, who: &[u8]) -> ProbeEndpoint {
    let (s, c) = load(root, p, who);
    ProbeEndpoint::new(
        p.clone(),
        who.to_vec(),
        s,
        binding(p, who),
        c,
        &p.approved_keys,
    )
    .unwrap()
}
fn fixture() -> (tempfile::TempDir, ProbePlan) {
    let temp = tempfile::tempdir().unwrap();
    let a = raw_agent(1);
    let b = raw_agent(2);
    let mut members = vec![a.clone(), b.clone()];
    members.sort();
    let mut p = ProbePlan {
        schema: 1,
        record: CeremonyRecord {
            schema: 1,
            installed_app_id: "offline-probe".into(),
            dna_hash: DnaHash::from_raw_32(vec![3; 32]).get_raw_39().to_vec(),
            proposal_action: ActionHash::from_raw_32(vec![4; 32]).get_raw_39().to_vec(),
            spec: holochain_mpc_core::SessionSpec {
                session_id: [5; 32],
                application_id: "org.test.probe".into(),
                protocol_id: PROTOCOL.into(),
                protocol_version: 1,
                context_hash: [6; 32],
                participants: members,
                threshold: 2,
                max_round: 1,
            },
        },
        sender: a.clone(),
        recipient: b.clone(),
        max_plaintext: 128,
        expected_payload_hash: commitment("mpc-transport-probe/payload/v1", MESSAGE),
        approved_keys: vec![],
    };
    for (i, who) in [&a, &b].into_iter().enumerate() {
        let mut s = RuntimeStore::open(&db(temp.path(), &p, who), master(&p, who)).unwrap();
        let c = DurableTransportChannel::provision_new(&mut s, &binding(&p, who)).unwrap();
        p.approved_keys.push(KeyEvidence {
            author: who.clone(),
            action: ActionHash::from_raw_32(vec![11 + i as u8; 32])
                .get_raw_39()
                .to_vec(),
            public_key: c.public_key(),
        });
    }
    p.approved_keys.sort_by(|x, y| x.author.cmp(&y.author));
    p.validate().unwrap();
    (temp, p)
}
fn signer_binding(p: &ProbePlan) -> SignerBinding {
    SignerBinding {
        installed_app_id: p.record.installed_app_id.clone(),
        role: "mpc".into(),
        dna_hash: p.record.dna_hash.clone(),
        agent: p.sender.clone(),
        proposal_action: p.record.proposal_action.clone(),
        session_id: p.record.spec.session_id,
        channel_id: [20; 32],
    }
}
fn policy_file(p: &ProbePlan) -> ProbeSignerPolicyFile {
    ProbeSignerPolicyFile {
        profile: "mpc-transport-probe-v1".into(),
        binding: signer_binding(p),
        record: p.record.clone(),
        own_public_key: p.key(&p.sender).unwrap(),
        send_plan: Some(p.clone()),
        capability: Some(ProbeCapability {
            purpose: "mpc-transport-probe-v1".into(),
            proposal: p.record.proposal_action.clone(),
            grant_action: ActionHash::from_raw_32(vec![21; 32]).get_raw_39().to_vec(),
            grantor: p.recipient.clone(),
            grantee: p.sender.clone(),
            cap_secret: CapSecret::from([22; 64]),
        }),
    }
}
fn request(p: &ProbePlan, env: Option<Envelope>, op: &str) -> SignerRequest {
    SignerRequest {
        version: 1,
        operation: op.into(),
        binding: signer_binding(p),
        envelope: env,
        public_key: None,
        result: None,
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Ack,
    AcceptThenFail,
    InvalidReceipt,
    Hang,
}
struct MockConductor {
    plan: ProbePlan,
    policy: ProbeSignerPolicy,
    inbox: Vec<Envelope>,
    calls: usize,
    mode: Mode,
}
impl MockConductor {
    fn new(p: &ProbePlan, mode: Mode) -> Self {
        Self {
            plan: p.clone(),
            policy: ProbeSignerPolicy::new(policy_file(p)).unwrap(),
            inbox: vec![],
            calls: 0,
            mode,
        }
    }
}
impl MpcTransport for MockConductor {
    async fn register_key(&mut self, _: [u8; 32]) -> Result<Vec<u8>, String> {
        panic!("probe must not auto-register")
    }
    // Structured slots carry only what this mock genuinely stores: served
    // envelopes. It never records conflicts or quota withholding.
    async fn get_inbox_slots(&mut self)
        -> Result<holochain_mpc_dkg_worker::inbox_slots::InboxSlots, String> {
        Ok(holochain_mpc_dkg_worker::inbox_slots::InboxSlots {
            envelopes: self.inbox.clone(), conflicts: vec![], over_quota: vec![] })
    }
    async fn get_encryption_keys(&mut self) -> Result<Vec<KeyEvidence>, String> {
        Ok(self.plan.approved_keys.clone())
    }
    async fn publish(&mut self, env: &Envelope) -> Result<SendReceipt, String> {
        self.calls += 1;
        if matches!(self.mode, Mode::Hang) {
            std::future::pending::<()>().await;
        }
        let (op, params) = self.policy.authorize(&request(
            &self.plan,
            Some(env.clone()),
            "send_protocol_message",
        ))?;
        assert_eq!(op.name(), "send_protocol_message");
        let (bytes, _) = params.serialize_and_hash().unwrap();
        // Deliberately fake signature: this test does not prove Ed25519/Lair or
        // real conductor acceptance. It checks the actual signed-byte policy.
        let signed = holochain_conductor_api::ZomeCallParamsSigned::new(bytes, Signature([0; 64]));
        validate_signed_envelope(&self.policy.pin(), env, &signed)?;
        #[derive(serde::Deserialize)]
        struct Wire {
            proposal: ActionHash,
            recipient: AgentPubKey,
            round: u32,
            sequence: u64,
            payload: Vec<u8>,
            recipient_cap_secret: CapSecret,
        }
        impl std::fmt::Debug for Wire {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("redacted mock wire")
            }
        }
        let w: Wire = params.payload.decode().unwrap();
        assert_eq!(w.proposal.get_raw_39(), self.plan.record.proposal_action);
        assert_eq!(w.recipient_cap_secret, CapSecret::from([22; 64]));
        // Same reconstruction as existing send_protocol_message: protocol
        // comes from the accepted proposal, sender from the cell provenance.
        let reconstructed = Envelope::new(
            &self.plan.record.spec,
            params.provenance.get_raw_39().to_vec(),
            Some(w.recipient.get_raw_39().to_vec()),
            w.round,
            w.sequence,
            w.payload,
        )
        .unwrap();
        assert_eq!(&reconstructed, env);
        self.plan.validate_envelope(&reconstructed)?;
        self.inbox.push(reconstructed);
        if matches!(self.mode, Mode::AcceptThenFail) {
            return Err("synthetic lost acknowledgement".into());
        }
        Ok(SendReceipt {
            action: if matches!(self.mode, Mode::InvalidReceipt) {
                vec![]
            } else {
                ActionHash::from_raw_32(vec![30; 32]).get_raw_39().to_vec()
            },
            already_stored: false,
        })
    }
}

#[tokio::test]
async fn signed_mock_delivery_replay_and_admission_are_durable() {
    let (t, p) = fixture();
    let mut a = endpoint(t.path(), &p, &p.sender);
    let mut net = MockConductor::new(&p, Mode::Ack);
    a.send_once(&mut net, MESSAGE).await.unwrap();
    assert_eq!(a.attempt().unwrap().unwrap().state, "acknowledged");
    assert!(a.send_once(&mut net, MESSAGE).await.is_err());
    assert_eq!(net.calls, 1);
    let mut b = endpoint(t.path(), &p, &p.recipient);
    assert_eq!(b.receive(&net.inbox[0]).unwrap(), Received::Inserted);
    drop(b);
    let mut b = endpoint(t.path(), &p, &p.recipient);
    assert_eq!(b.receive(&net.inbox[0]).unwrap(), Received::Duplicate);
    assert!(!t.path().join("journal.sqlite").exists());
}
#[tokio::test]
async fn uncertain_or_invalid_ack_never_retries_even_after_reopen() {
    for mode in [Mode::AcceptThenFail, Mode::InvalidReceipt] {
        let (t, p) = fixture();
        let mut a = endpoint(t.path(), &p, &p.sender);
        let mut net = MockConductor::new(&p, mode);
        assert!(a.send_once(&mut net, MESSAGE).await.is_err());
        assert_eq!(a.attempt().unwrap().unwrap().state, "uncertain");
        drop(a);
        let mut a = endpoint(t.path(), &p, &p.sender);
        assert!(a.send_once(&mut net, MESSAGE).await.is_err());
        assert_eq!(net.calls, 1);
        let mut b = endpoint(t.path(), &p, &p.recipient);
        assert_eq!(b.receive(&net.inbox[0]).unwrap(), Received::Inserted);
    }
}
#[tokio::test]
async fn cancellation_leaves_terminal_pending_admission() {
    let (t, p) = fixture();
    let mut a = endpoint(t.path(), &p, &p.sender);
    let mut net = MockConductor::new(&p, Mode::Hang);
    tokio::select! { _=a.send_once(&mut net,MESSAGE)=>panic!("mock cannot complete"),
    _=tokio::time::sleep(std::time::Duration::from_millis(10))=>{} }
    assert_eq!(a.attempt().unwrap().unwrap().state, "pending");
    drop(a);
    let mut a = endpoint(t.path(), &p, &p.sender);
    assert!(a.send_once(&mut net, MESSAGE).await.is_err());
    assert_eq!(net.calls, 1);
}
#[test]
fn tampering_wrong_identity_and_pins_cannot_poison_recipient_replay() {
    let (t, p) = fixture();
    let env = endpoint(t.path(), &p, &p.sender).admit(MESSAGE).unwrap();
    let mut b = endpoint(t.path(), &p, &p.recipient);
    let mut wrong = env.clone();
    wrong.protocol_id = "frost-ed25519".into();
    assert!(b.receive(&wrong).is_err());
    wrong = env.clone();
    wrong.sender = p.recipient.clone();
    assert!(b.receive(&wrong).is_err());
    wrong = env.clone();
    wrong.recipient = Some(p.sender.clone());
    assert!(b.receive(&wrong).is_err());
    wrong = env.clone();
    wrong.sequence = 2;
    assert!(b.receive(&wrong).is_err());
    wrong = env.clone();
    wrong.session_id = [99; 32];
    assert!(b.receive(&wrong).is_err());
    let mut packet: SealedPacket = serde_json::from_slice(&env.payload).unwrap();
    packet.ciphertext[0] ^= 1;
    wrong = Envelope::new(
        &p.record.spec,
        p.sender.clone(),
        Some(p.recipient.clone()),
        1,
        1,
        serde_json::to_vec(&packet).unwrap(),
    )
    .unwrap();
    assert!(b.receive(&wrong).is_err());
    assert_eq!(b.receive(&env).unwrap(), Received::Inserted);
    let mut observed = p.approved_keys.clone();
    observed[0].action = ActionHash::from_raw_32(vec![88; 32]).get_raw_39().to_vec();
    let (s, c) = load(t.path(), &p, &p.sender);
    assert!(ProbeEndpoint::new(
        p.clone(),
        p.sender.clone(),
        s,
        binding(&p, &p.sender),
        c,
        &observed
    )
    .is_err());
    let mut changed = p.clone();
    changed.expected_payload_hash = [90; 32];
    assert!(endpoint(t.path(), &changed, &changed.sender)
        .admit(b"other")
        .is_err());
}
#[test]
fn authenticated_inner_bindings_and_conflicting_ciphertext_are_checked() {
    let (t, p) = fixture();
    let env = endpoint(t.path(), &p, &p.sender).admit(MESSAGE).unwrap();
    let (_, a) = load(t.path(), &p, &p.sender);
    let (_, bkey) = load(t.path(), &p, &p.recipient);
    let packet: SealedPacket = serde_json::from_slice(&env.payload).unwrap();
    let clear = bkey
        .native()
        .open(
            &p.ceremony(),
            &p.header(),
            p.key(&p.sender).unwrap(),
            &packet,
        )
        .unwrap();
    let original: serde_json::Value = serde_json::from_slice(&clear).unwrap();
    let mut b = endpoint(t.path(), &p, &p.recipient);
    for field in [
        "dna",
        "ceremony",
        "registrations",
        "plan",
        "message_id",
        "payload_hash",
    ] {
        let mut v = original.clone();
        v[field][0] = serde_json::json!(v[field][0].as_u64().unwrap() ^ 1);
        let forged = a
            .native()
            .seal(
                &p.ceremony(),
                p.header(),
                p.key(&p.recipient).unwrap(),
                &serde_json::to_vec(&v).unwrap(),
            )
            .unwrap();
        let e = Envelope::new(
            &p.record.spec,
            p.sender.clone(),
            Some(p.recipient.clone()),
            1,
            1,
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();
        assert!(b.receive(&e).is_err(), "inner {field}");
    }
    let mut v = original.clone();
    v["domain"] = serde_json::json!("frost-ed25519");
    let forged = a
        .native()
        .seal(
            &p.ceremony(),
            p.header(),
            p.key(&p.recipient).unwrap(),
            &serde_json::to_vec(&v).unwrap(),
        )
        .unwrap();
    let e = Envelope::new(
        &p.record.spec,
        p.sender.clone(),
        Some(p.recipient.clone()),
        1,
        1,
        serde_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    assert!(b.receive(&e).is_err());
    assert_eq!(b.receive(&env).unwrap(), Received::Inserted);
    let alternative = a
        .native()
        .seal(
            &p.ceremony(),
            p.header(),
            p.key(&p.recipient).unwrap(),
            &clear,
        )
        .unwrap();
    let e = Envelope::new(
        &p.record.spec,
        p.sender.clone(),
        Some(p.recipient.clone()),
        1,
        1,
        serde_json::to_vec(&alternative).unwrap(),
    )
    .unwrap();
    assert!(
        b.receive(&e).is_err(),
        "same identity with different valid ciphertext is equivocation"
    );
}
#[test]
fn probe_and_frost_signers_are_separate_and_status_is_exact() {
    let (t, p) = fixture();
    let env = endpoint(t.path(), &p, &p.sender).admit(MESSAGE).unwrap();
    let probe = ProbeSignerPolicy::new(policy_file(&p)).unwrap();
    let req = request(&p, Some(env.clone()), "send_protocol_message");
    let (_, first) = probe.authorize(&req).unwrap();
    let (_, second) = probe.authorize(&req).unwrap();
    assert_ne!(first.nonce, second.nonce);
    assert!(first.expires_at > Timestamp::now());
    let frost = SignerPolicy::new(SignerPolicyFile {
        binding: signer_binding(&p),
        recipients: vec![],
        spec: None,
    })
    .unwrap();
    assert!(frost.authorize(&req).is_err());
    assert!(frost
        .authorize(&request(&p, None, "get_session_status"))
        .is_err());
    for op in [
        "accept_session",
        "prepare_inbox_grant",
        "delete_entry",
        "init",
    ] {
        assert!(probe.authorize(&request(&p, None, op)).is_err());
    }
    for change in [0, 1, 2, 3] {
        let mut bad = req.clone();
        match change {
            0 => bad.binding.dna_hash = DnaHash::from_raw_32(vec![91; 32]).get_raw_39().to_vec(),
            1 => {
                bad.binding.proposal_action =
                    ActionHash::from_raw_32(vec![91; 32]).get_raw_39().to_vec()
            }
            2 => bad.binding.session_id = [91; 32],
            _ => bad.binding.agent = raw_agent(91),
        };
        assert!(probe.authorize(&bad).is_err());
    }
    let mut bad = req.clone();
    bad.envelope.as_mut().unwrap().protocol_id = "frost-ed25519".into();
    assert!(probe.authorize(&bad).is_err());
    assert!(holochain_mpc_frost_ed25519::Binding::new(
        p.record.proposal_action.clone(),
        p.record.spec.clone()
    )
    .is_err());
    let mut pf = policy_file(&p);
    pf.profile = "frost-ed25519".into();
    assert!(ProbeSignerPolicy::new(pf).is_err());
    let mut pf = policy_file(&p);
    pf.capability.as_mut().unwrap().purpose = "frost-ed25519".into();
    assert!(ProbeSignerPolicy::new(pf).is_err());
    let mut pf = policy_file(&p);
    pf.capability = None;
    let no_cap = ProbeSignerPolicy::new(pf).unwrap();
    assert!(no_cap.authorize(&req).is_err());
    verify_status(&p.record, &p.record.spec, &p.record.spec.participants, true).unwrap();
    let mut other = p.record.spec.clone();
    other.protocol_id = "frost-ed25519".into();
    assert!(verify_status(&p.record, &other, &other.participants, true).is_err());
    assert!(verify_status(
        &p.record,
        &p.record.spec,
        &p.record.spec.participants[..1],
        true
    )
    .is_err());
    assert!(verify_status(
        &p.record,
        &p.record.spec,
        &p.record.spec.participants,
        false
    )
    .is_err());
}
#[test]
fn concurrent_outbound_admission_only_one_wins() {
    let (t, p) = fixture();
    let path = t.path().to_owned();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let p = p.clone();
            let path = path.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                let mut a = endpoint(&path, &p, &p.sender);
                b.wait();
                a.admit(MESSAGE).is_ok()
            })
        })
        .collect();
    let n = workers
        .into_iter()
        .map(|h| h.join().unwrap() as usize)
        .sum::<usize>();
    assert_eq!(n, 1);
}

#[test]
fn process_child_step() {
    let Some(root) = std::env::var_os("MPC_PROBE_SYNTHETIC_FIXTURE") else {
        return;
    };
    let root = PathBuf::from(root);
    let p: ProbePlan =
        serde_json::from_slice(&std::fs::read(root.join("plan.json")).unwrap()).unwrap();
    let mode = std::env::var("MPC_PROBE_TEST_STEP").unwrap();
    match mode.as_str() {
        "admit-and-wait" => {
            let mut a = endpoint(&root, &p, &p.sender);
            let env = a.admit(MESSAGE).unwrap();
            std::fs::write(
                root.join("envelope.json"),
                serde_json::to_vec(&env).unwrap(),
            )
            .unwrap();
            // Keep SQLite open: parent kills the process without destructors.
            loop {
                std::thread::park();
            }
        }
        "admit" => {
            let env = endpoint(&root, &p, &p.sender).admit(MESSAGE).unwrap();
            std::fs::write(
                root.join("envelope.json"),
                serde_json::to_vec(&env).unwrap(),
            )
            .unwrap();
        }
        "retry" => {
            let mut a = endpoint(&root, &p, &p.sender);
            assert_eq!(a.attempt().unwrap().unwrap().state, "pending");
            assert!(a.admit(MESSAGE).is_err());
        }
        "receive" | "duplicate" => {
            let env = serde_json::from_slice(&std::fs::read(root.join("envelope.json")).unwrap())
                .unwrap();
            assert_eq!(
                endpoint(&root, &p, &p.recipient).receive(&env).unwrap(),
                if mode == "receive" {
                    Received::Inserted
                } else {
                    Received::Duplicate
                }
            );
        }
        _ => panic!("unlisted synthetic step"),
    }
}
#[test]
fn independent_process_restarts_preserve_keys_admission_and_replay() {
    let (t, p) = fixture();
    std::fs::write(t.path().join("plan.json"), serde_json::to_vec(&p).unwrap()).unwrap();
    for step in ["admit", "retry", "receive", "duplicate"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "process_child_step", "--nocapture"])
            .env("MPC_PROBE_SYNTHETIC_FIXTURE", t.path())
            .env("MPC_PROBE_TEST_STEP", step)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "synthetic child {step}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for who in [&p.sender, &p.recipient] {
        assert_eq!(load(t.path(), &p, who).1.public_key(), p.key(who).unwrap());
    }
    for file in ["a.sqlite", "b.sqlite"] {
        let conn = rusqlite::Connection::open(t.path().join(file)).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM dkg_checkpoints", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
        let n: i64 = conn
            .query_row("SELECT count(*) FROM nonces", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }
}

// Run the EXISTING coordinator and integrity code against mocked host calls.
// create/call below are mock expectations only: no source chain exists.
mod existing_zomes {
    use super::*;
    use hdk::prelude::*;
    fn info() -> ZomeInfo {
        ZomeInfo {
            name: "mpc".into(),
            id: 0.into(),
            properties: SerializedBytes::from(UnsafeBytes::from(vec![])),
            entry_defs: EntryDefs(vec![]),
            extern_fns: vec![],
            zome_types: ScopedZomeTypesSet {
                entries: ScopedZomeTypes(vec![(0.into(), (0..9).map(EntryDefIndex).collect())]),
                links: ScopedZomeTypes(vec![(0.into(), (0..8).map(LinkType).collect())]),
            },
        }
    }
    fn record(author: AgentPubKey, hash: ActionHash, entry: Entry, index: u8) -> Record {
        let action = Action {
            header: ActionHeader {
                author,
                timestamp: Timestamp::from_micros(1),
                action_seq: 5,
                prev_action: Some(ActionHash::from_raw_32(vec![77; 32])),
            },
            data: ActionData::Create(CreateData {
                entry_type: EntryType::App(AppEntryDef::new(
                    index.into(),
                    0.into(),
                    if index == 3 {
                        EntryVisibility::Private
                    } else {
                        EntryVisibility::Public
                    },
                )),
                entry_hash: EntryHash::from_raw_32(vec![78; 32]),
            }),
        };
        Record::new(
            SignedHashed::with_presigned(
                ActionHashed::with_pre_hashed(action, hash),
                Signature([0; 64]),
            ),
            RecordEntry::Present(entry),
        )
    }
    fn host(p: &ProbePlan, local: &[u8], accepted: bool) -> MockHdkT {
        let mut h = MockHdkT::new();
        h.expect_zome_info().returning(|_| Ok(info()));
        let agent = AgentPubKey::try_from_raw_39(local.to_vec()).unwrap();
        h.expect_agent_info().returning(move |_| {
            Ok(AgentInfo {
                agent_initial_pubkey: agent.clone(),
                chain_head: (
                    ActionHash::from_raw_32(vec![80; 32]),
                    5,
                    Timestamp::from_micros(1),
                ),
            })
        });
        let proposal = ActionHash::try_from_raw_39(p.record.proposal_action.clone()).unwrap();
        let proposal_entry: Entry = mpc_integrity::SessionProposal {
            spec: p.record.spec.clone(),
        }
        .try_into()
        .unwrap();
        let mut records = vec![record(
            AgentPubKey::try_from_raw_39(p.sender.clone()).unwrap(),
            proposal.clone(),
            proposal_entry,
            0,
        )];
        let mut links = vec![];
        if accepted {
            for (i, raw) in p.record.spec.participants.iter().enumerate() {
                let agent = AgentPubKey::try_from_raw_39(raw.clone()).unwrap();
                let hash = ActionHash::from_raw_32(vec![81 + i as u8; 32]);
                let entry: Entry = mpc_integrity::SessionAcceptance {
                    proposal: proposal.clone(),
                    session_id: p.record.spec.session_id,
                }
                .try_into()
                .unwrap();
                records.push(record(agent.clone(), hash.clone(), entry, 1));
                links.push(Link {
                    author: agent,
                    base: proposal.clone().into(),
                    target: hash.clone().into(),
                    timestamp: Timestamp::from_micros(1),
                    zome_index: 0.into(),
                    link_type: 0.into(),
                    tag: LinkTag::new(vec![]),
                    create_link_hash: hash,
                });
            }
        }
        h.expect_get().returning(move |inputs| {
            Ok(inputs
                .into_iter()
                .map(|i| {
                    records
                        .iter()
                        .find(|r| i.any_dht_hash == r.action_address().clone().into())
                        .cloned()
                })
                .collect())
        });
        h.expect_get_links()
            .returning(move |_| Ok(vec![links.clone()]));
        h
    }
    #[test]
    fn existing_integrity_and_coordinator_accept_probe_without_schema_changes() {
        let (t, p) = fixture();
        let env = endpoint(t.path(), &p, &p.sender).admit(MESSAGE).unwrap();
        let sender = AgentPubKey::try_from_raw_39(p.sender.clone()).unwrap();
        let proposal = ActionHash::try_from_raw_39(p.record.proposal_action.clone()).unwrap();
        let mut h = host(&p, &p.sender, true);
        let expected = env.clone();
        let dest = p.recipient.clone();
        h.expect_call().times(1).returning(move |calls| {
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].fn_name.to_string(), "receive_protocol_message");
            assert_eq!(
                calls[0].target,
                CallTarget::NetworkAgent(AgentPubKey::try_from_raw_39(dest.clone()).unwrap())
            );
            let incoming: mpc::IncomingMessage = calls[0].payload.decode().unwrap();
            assert_eq!(incoming.envelope, expected);
            Ok(vec![ZomeCallResponse::Ok(
                ExternIO::encode(mpc::DeliveryReceipt {
                    status: mpc::ReceiptStatus::Stored,
                    storage_action: ActionHash::from_raw_32(vec![90; 32]),
                })
                .unwrap(),
            )])
        });
        set_hdk(h);
        let entry: Entry = mpc_integrity::SessionProposal {
            spec: p.record.spec.clone(),
        }
        .try_into()
        .unwrap();
        let r = record(sender, proposal.clone(), entry.clone(), 0);
        assert_eq!(
            mpc_integrity::validate(Op::CreateEntry(CreateEntry {
                action: r.signed_action().clone(),
                entry
            }))
            .unwrap(),
            ValidateCallbackResult::Valid
        );
        let status = mpc::get_session_status(proposal.clone()).unwrap();
        assert_eq!(status.spec, p.record.spec);
        assert!(status.ready_observed);
        mpc::send_protocol_message(mpc::SendMessage {
            proposal,
            recipient: AgentPubKey::try_from_raw_39(p.recipient.clone()).unwrap(),
            round: 1,
            sequence: 1,
            payload: env.payload,
            recipient_cap_secret: CapSecret::from([22; 64]),
        })
        .unwrap();
    }
    #[test]
    fn existing_receiver_checks_provenance_and_consent_for_probe() {
        let (t, p) = fixture();
        let env = endpoint(t.path(), &p, &p.sender).admit(MESSAGE).unwrap();
        for (caller, accepted, success) in [
            (p.sender.clone(), true, true),
            (raw_agent(98), true, false),
            (p.sender.clone(), false, false),
        ] {
            let mut h = host(&p, &p.recipient, accepted);
            let caller = AgentPubKey::try_from_raw_39(caller).unwrap();
            h.expect_call_info().returning(move |_| {
                Ok(CallInfo {
                    provenance: caller.clone(),
                    function_name: "receive_protocol_message".into(),
                    as_at: (
                        ActionHash::from_raw_32(vec![90; 32]),
                        5,
                        Timestamp::from_micros(1),
                    ),
                    cap_grant: CapAccess::RemoteAgent(Box::new(CapGrant::new_zome_call_grant(
                        "synthetic-probe".into(),
                        GrantConstraint::Assigned {
                            secret: CapSecret::from([22; 64]),
                            assignees: [caller.clone()].into_iter().collect(),
                        },
                        GrantedFunctions::Listed(
                            [("mpc".into(), "receive_protocol_message".into())]
                                .into_iter()
                                .collect(),
                        ),
                    ))),
                })
            });
            h.expect_query().returning(|_| Ok(vec![]));
            h.expect_create()
                .times(if success { 1 } else { 0 })
                .returning(|_| Ok(ActionHash::from_raw_32(vec![91; 32])));
            set_hdk(h);
            let result = mpc::receive_protocol_message(mpc::IncomingMessage {
                proposal: ActionHash::try_from_raw_39(p.record.proposal_action.clone()).unwrap(),
                envelope: env.clone(),
            });
            assert_eq!(result.is_ok(), success);
        }
    }
}

#[test]
fn strict_profile_files_and_registration_only_mode_fail_closed() {
    let (t, p) = fixture();
    let old = serde_json::json!({"binding":signer_binding(&p),"recipients":[]});
    assert!(serde_json::from_value::<ProbeSignerPolicyFile>(old).is_err());
    let probe = serde_json::json!({"profile":"mpc-transport-probe-v1","binding":signer_binding(&p),
        "record":p.record,"own_public_key":p.key(&p.sender).unwrap(),"send_plan":null,"capability":null});
    assert!(serde_json::from_value::<SignerPolicyFile>(probe.clone()).is_err());
    let registration = ProbeSignerPolicy::new(serde_json::from_value(probe).unwrap()).unwrap();
    let mut req = request(&p, None, "register_encryption_key");
    req.public_key = Some(p.key(&p.sender).unwrap());
    assert!(registration.authorize(&req).is_ok());
    req.public_key = Some([99; 32]);
    assert!(registration.authorize(&req).is_err());
    let env = endpoint(t.path(), &p, &p.sender).admit(MESSAGE).unwrap();
    assert!(registration
        .authorize(&request(&p, Some(env), "send_protocol_message"))
        .is_err());
    let mut bad = policy_file(&p);
    bad.capability.as_mut().unwrap().cap_secret = CapSecret::from([0; 64]);
    assert!(ProbeSignerPolicy::new(bad).is_err());
    let mut bad = policy_file(&p);
    bad.capability.as_mut().unwrap().proposal =
        ActionHash::from_raw_32(vec![99; 32]).get_raw_39().to_vec();
    assert!(ProbeSignerPolicy::new(bad).is_err());
}
#[test]
fn private_probe_plan_loader_rejects_symlinks_hardlinks_and_unknown_fields() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (t, p) = fixture();
    let path = t.path().join("private-plan.json");
    std::fs::write(&path, serde_json::to_vec(&p).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_private_json::<ProbePlan>(&path).is_ok());
    let link = t.path().join("plan-link");
    symlink(&path, &link).unwrap();
    assert!(read_private_json::<ProbePlan>(&link).is_err());
    let hard = t.path().join("plan-hard");
    std::fs::hard_link(&path, &hard).unwrap();
    assert!(read_private_json::<ProbePlan>(&path).is_err());
    std::fs::remove_file(hard).unwrap();
    let mut value = serde_json::to_value(&p).unwrap();
    value["unexpected"] = serde_json::json!(true);
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(read_private_json::<ProbePlan>(&path).is_err());
    std::fs::write(&path, vec![b' '; 65537]).unwrap();
    assert!(read_private_json::<ProbePlan>(&path).is_err());
    assert!(read_private_json::<ProbePlan>(Path::new("relative-plan.json")).is_err());
}
#[test]
fn native_probe_node_recovery_never_opens_a_dkg_journal() {
    use holochain_mpc_dkg_worker::{ipc::ChannelContext, node_service};
    let (t, mut p) = fixture();
    let node = t.path().join("probe-node");
    let ctx = ChannelContext {
        worker_agent: p.sender.clone(),
        proposal_action: p.record.proposal_action.clone(),
        session_id: p.record.spec.session_id,
        channel_id: [51; 32],
    };
    node_service::provision(&node, ctx).unwrap();
    assert!(ProbeEndpoint::open_node(p.clone(), &node, &p.approved_keys).is_err());
    assert!(!node.join("transport.sqlite").exists());
    let public = node_service::transport_public_key(
        &node,
        p.record.dna_hash.as_slice().try_into().unwrap(),
        true,
    )
    .unwrap();
    for k in &mut p.approved_keys {
        if k.author == p.sender {
            k.public_key = public;
        }
    }
    let mut wrong = p.clone();
    wrong.record.proposal_action = ActionHash::from_raw_32(vec![99; 32]).get_raw_39().to_vec();
    assert!(ProbeEndpoint::open_node(wrong, &node, &p.approved_keys).is_err());
    let mut e = ProbeEndpoint::open_node(p.clone(), &node, &p.approved_keys).unwrap();
    e.admit(MESSAGE).unwrap();
    drop(e);
    let mut e = ProbeEndpoint::open_node(p.clone(), &node, &p.approved_keys).unwrap();
    assert!(e.admit(MESSAGE).is_err());
    assert!(!node.join("journal.sqlite").exists());
}

#[test]
fn payload_bounds_hold_after_nested_json_encryption() {
    let (t, mut p) = fixture();
    let payload = vec![255; 128];
    p.expected_payload_hash = commitment("mpc-transport-probe/payload/v1", &payload);
    let mut a = endpoint(t.path(), &p, &p.sender);
    assert!(a.admit(&[]).is_err());
    assert!(a.admit(&vec![255; 129]).is_err());
    assert!(a.admit(b"wrong digest").is_err());
    assert!(a.attempt().unwrap().is_none());
    let env = a.admit(&payload).unwrap();
    assert!(env.payload.len() <= MAX_PACKET);
    assert_eq!(
        endpoint(t.path(), &p, &p.recipient).receive(&env).unwrap(),
        Received::Inserted
    );
}
#[test]
fn concurrent_recipient_receipt_has_one_effect() {
    let (t, p) = fixture();
    let env = endpoint(t.path(), &p, &p.sender).admit(MESSAGE).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let p = p.clone();
            let env = env.clone();
            let dir = t.path().to_owned();
            let gate = barrier.clone();
            std::thread::spawn(move || {
                let mut b = endpoint(&dir, &p, &p.recipient);
                gate.wait();
                b.receive(&env).unwrap()
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        results.iter().filter(|r| **r == Received::Inserted).count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Received::Duplicate)
            .count(),
        1
    );
}

#[tokio::test]
async fn actual_send_deadline_is_terminal_without_resubmission() {
    let (t, p) = fixture();
    let mut a = endpoint(t.path(), &p, &p.sender);
    let mut net = MockConductor::new(&p, Mode::Hang);
    assert!(a.send_once(&mut net, MESSAGE).await.is_err());
    assert_eq!(a.attempt().unwrap().unwrap().state, "uncertain");
    assert!(a.send_once(&mut net, MESSAGE).await.is_err());
    assert_eq!(net.calls, 1);
}
#[test]
fn abrupt_probe_process_death_preserves_wal_admission() {
    let (t, p) = fixture();
    std::fs::write(t.path().join("plan.json"), serde_json::to_vec(&p).unwrap()).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "process_child_step"])
        .env("MPC_PROBE_SYNTHETIC_FIXTURE", t.path())
        .env("MPC_PROBE_TEST_STEP", "admit-and-wait")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !t.path().join("envelope.json").exists() && std::time::Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let ready = t.path().join("envelope.json").exists();
    let _ = child.kill();
    let _ = child.wait();
    assert!(ready, "synthetic crash fixture did not admit in time");
    let mut a = endpoint(t.path(), &p, &p.sender);
    assert_eq!(a.attempt().unwrap().unwrap().state, "pending");
    assert!(a.admit(MESSAGE).is_err());
    let env =
        serde_json::from_slice(&std::fs::read(t.path().join("envelope.json")).unwrap()).unwrap();
    assert_eq!(
        endpoint(t.path(), &p, &p.recipient).receive(&env).unwrap(),
        Received::Inserted
    );
}

// Security-review B1 refusal: a probe spec is rejected at every FROST entry
// point before durable DKG admission or FROST randomness. The refused Init
// keeps the existing fail-closed tombstone; it never leaves a running marker.
#[test]
fn review_b1_frost_rejects_probe_binding_before_admission() {
    use holochain_mpc_dkg_worker::{ipc, AuthenticatedController, Command, Controller};
    use holochain_mpc_frost_ed25519 as frost;
    use holochain_mpc_runtime::dkg::DkgState;
    let (t, p) = fixture();
    assert!(frost::Binding::new(p.record.proposal_action.clone(), p.record.spec.clone()).is_err());
    assert!(serde_json::from_value::<frost::Binding>(serde_json::json!({
        "proposal_action":p.record.proposal_action,"spec":p.record.spec
    }))
    .is_err());
    // Public fields still permit a struct literal; each entry point revalidates.
    let literal = frost::Binding {
        proposal_action: p.record.proposal_action.clone(),
        spec: p.record.spec.clone(),
    };
    assert!(literal.validate().is_err());
    assert!(frost::DkgParty::begin(literal.clone(), &p.sender).is_err());
    assert!(Controller::default()
        .handle(Command::Init { binding: literal.clone(), local: p.sender.clone() })
        .is_err());
    let ctx = ipc::ChannelContext {
        worker_agent: p.sender.clone(),
        proposal_action: p.record.proposal_action.clone(),
        session_id: p.record.spec.session_id,
        channel_id: [30; 32],
    };
    let journal = t.path().join("b1-journal.sqlite");
    let mut host = ipc::AuthChannel::new([31; 32], ctx.clone(), ipc::Role::Host).unwrap();
    let mut worker = AuthenticatedController::new_durable(
        [31; 32], ctx, &journal, MasterKey::from_bytes([32; 32])).unwrap();
    let init = host.seal(Command::Init { binding: literal, local: p.sender.clone() }).unwrap();
    assert!(worker.handle(init).is_err());
    drop(worker);
    let store = RuntimeStore::open(&journal, MasterKey::from_bytes([32; 32])).unwrap();
    let checkpoint = store
        .dkg_checkpoint(&p.record.proposal_action, &p.sender, &p.record.spec.session_id)
        .unwrap();
    assert!(checkpoint.map_or(true, |c| c.state == DkgState::Aborted && c.revision == 0));
}
// Security-review B2 refusal: a FROST-profile policy can no longer be built
// for the probe proposal, so a relabelled envelope never reaches signing.
#[test]
fn review_b2_frost_signer_refuses_misbound_probe_ceremony() {
    use holochain_mpc_dkg_worker::lair_signer::RecipientCapability;
    let (t, p) = fixture();
    let env = endpoint(t.path(), &p, &p.sender).admit(MESSAGE).unwrap();
    let cap = || {
        vec![RecipientCapability {
            agent: p.recipient.clone(),
            cap_secret: CapSecret::from([22; 64]),
        }]
    };
    // Capabilities without a pinned spec are refused outright.
    assert!(SignerPolicy::new(SignerPolicyFile {
        binding: signer_binding(&p),
        recipients: cap(),
        spec: None,
    })
    .is_err());
    // The actual on-chain (probe) spec is not a FROST ceremony.
    assert!(SignerPolicy::new(SignerPolicyFile {
        binding: signer_binding(&p),
        recipients: cap(),
        spec: Some(p.record.spec.clone()),
    })
    .is_err());
    // A read-only legacy policy signs neither the honest nor the relabelled send.
    let read_only = SignerPolicy::new(SignerPolicyFile {
        binding: signer_binding(&p),
        recipients: vec![],
        spec: None,
    })
    .unwrap();
    let mut relabelled = env.clone();
    relabelled.protocol_id = "frost-ed25519".into();
    for e in [env, relabelled] {
        assert!(read_only
            .authorize(&request(&p, Some(e), "send_protocol_message"))
            .is_err());
    }
}
#[test]
fn review_reproduction_capability_action_is_an_operator_assertion() {
    let (_t, p) = fixture();
    let mut file = policy_file(&p);
    let cap = file.capability.as_mut().unwrap();
    cap.grant_action = ActionHash::from_raw_32(vec![119; 32]).get_raw_39().to_vec();
    cap.cap_secret = CapSecret::from([120; 64]);
    assert!(
        ProbeSignerPolicy::new(file).is_ok(),
        "constructor verifies labels/types, not grant issuance or secret/action association"
    );
}
