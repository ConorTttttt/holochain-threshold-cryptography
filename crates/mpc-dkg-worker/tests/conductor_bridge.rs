//! v0.3.9: three separately provisioned Unix node services while conductors
//! authenticate and store EVERY peer-to-peer DKG envelope. No plaintext shares
//! or KeyPackages travel through test process / worker IPC.
use std::path::Path;
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};
use std::collections::BTreeSet;
use hdk::prelude::*;
use holochain::sweettest::*;
use holochain_mpc_core::{commitment, Envelope, SessionSpec};
use holochain_mpc_dkg_worker::conductor_bridge::{ConductorBridge, KeyEvidence};
use holochain_mpc_dkg_worker::node_service::provision;
use holochain_mpc_dkg_worker::ipc::ChannelContext;
use rand::{rngs::OsRng, RngCore};
use holochain_mpc_frost_ed25519 as frost;
use holochain_mpc_security::activation::GroupActivation;
use mpc::{DeliveryReceipt, EncryptionKeyRecord, GroupAttestationRecord, PreparedGrant,
          PublishGroupAttestation, ReceiptStatus, RegisterEncryptionKey, SendMessage, SessionStatus};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// One local bridge is bound to one independently launched mpc-node process.
/// No worker holds another worker's key or state database.
struct Worker {
    process: Child,
    bridge: ConductorBridge,
}
impl Worker {
    fn start(context: ChannelContext, binding: frost::Binding, dir: &Path) -> TestResult<Self> {
        provision(dir, context.clone())?;
        let mut process = ProcessCommand::new(env!("CARGO_BIN_EXE_mpc-node"))
            .arg("serve").arg(dir)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn()?;
        let since = Instant::now();
        let bridge = loop {
            match ConductorBridge::connect(dir, context.clone(), binding.clone()) {
                Ok(bridge) => break bridge,
                Err(e) if since.elapsed() < Duration::from_secs(5) => {
                    if let Some(status) = process.try_wait()? {
                        return Err(format!("node failed to launch: {status}; {e}").into());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(format!("node socket unavailable: {e}").into()),
            }
        };
        Ok(Self { process, bridge })
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn three_private_node_services_frost_dkg_over_three_conductors() -> TestResult<()> {
    let mut conductors = SweetConductorBatch::standard(3).await;
    let dna_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../dnas/mpc/workdir/mpc.dna");
    let dna = SweetDnaFile::from_bundle(&dna_path).await?;
    let apps = conductors.setup_app("mpc-v039-node-conductor-bridge", &[dna]).await?;
    let cells = apps.cells_flattened();
    let zomes = [cells[0].zome("mpc"), cells[1].zome("mpc"), cells[2].zome("mpc")];
    let agents: Vec<AgentPubKey> = cells.iter().map(|cell| cell.agent_pubkey().clone()).collect();
    let members: Vec<Vec<u8>> = agents.iter().map(|agent| agent.get_raw_39().to_vec()).collect();
    let mut sorted_members = members.clone();
    sorted_members.sort();
    let spec = SessionSpec {
        session_id: commitment("v035-live-dkg-session", b"three-private-node-services"),
        application_id: "org.example.mpc-core-process-dkg".into(),
        protocol_id: frost::PROTOCOL_ID.into(), protocol_version: frost::PROTOCOL_VERSION,
        context_hash: commitment("v035-process-context", b"native-service-owns-secrets"),
        participants: sorted_members, threshold: 2, max_round: 6,
    };
    let proposal: ActionHash = conductors.get(0).unwrap().call(&zomes[0], "propose_session", spec.clone()).await;
    await_consistency(&cells).await?;
    for i in 0..3 {
        let _: ActionHash = conductors.get(i).unwrap().call(&zomes[i], "accept_session", proposal.clone()).await;
    }
    await_consistency(&cells).await?;
    for i in 0..3 {
        let status: SessionStatus = conductors.get(i).unwrap().call(&zomes[i], "get_session_status", proposal.clone()).await;
        assert!(status.ready_observed);
    }
    let binding = frost::Binding::new(proposal.get_raw_39().to_vec(), spec.clone())?;
    let mut grants: Vec<PreparedGrant> = Vec::new();
    for i in 0..3 {
        grants.push(conductors.get(i).unwrap().call(&zomes[i], "prepare_inbox_grant", proposal.clone()).await);
    }

    // Each worker has a distinct encrypted SQLite journal and unique master
    // key. The harness owns provisioning and temporary filesystem isolation;
    // this is not an OS key-store or protection from a malicious test host.
    let state_dir = tempfile::tempdir()?;
    let mut workers = Vec::<Worker>::new();
    let mut public_keys = Vec::new();
    let mut announcements = Vec::new();
    for i in 0..3 {
        let mut channel_id = [0_u8; 32];
        OsRng.fill_bytes(&mut channel_id);
        let mut worker = Worker::start(ChannelContext {
            worker_agent: members[i].clone(),
            proposal_action: binding.proposal_action.clone(),
            session_id: spec.session_id,
            channel_id,
        }, binding.clone(), &state_dir.path().join(format!("node-{i}")))?;
        let (local_public_key, outbound) = worker.bridge.initialize()?;
        assert_eq!(outbound.len(), 2);
        public_keys.push(local_public_key);
        announcements.extend(outbound);
        workers.push(worker);
    }
    assert_eq!(workers.len(), 3, "each DKG participant has its own process");

    let mut binding_actions = Vec::new();
    for i in 0..3 {
        let action: ActionHash = conductors.get(i).unwrap().call(&zomes[i],
            "register_encryption_key", RegisterEncryptionKey {
                proposal: proposal.clone(), public_key: public_keys[i],
            }).await;
        binding_actions.push(action);
    }
    await_consistency(&cells).await?;
    // Each observer independently reads the full authored-key roster.
    let mut observed_key_evidence = Vec::new();
    for observer in 0..3 {
        let key_records: Vec<EncryptionKeyRecord> = conductors.get(observer).unwrap()
            .call(&zomes[observer], "get_encryption_key_bindings", proposal.clone()).await;
        assert_eq!(key_records.len(), 3, "all signed key bindings must be present");
        for i in 0..3 {
            assert_eq!(key_records.iter().filter(|record|
                record.author == agents[i] && record.action == binding_actions[i] &&
                record.public_key == public_keys[i]).count(), 1,
                "reject forked or missing encryption key bindings");
        }
        let evidence: Vec<KeyEvidence> = key_records.iter().map(|r| KeyEvidence {
            author: r.author.get_raw_39().to_vec(),
            action: r.action.get_raw_39().to_vec(),
            public_key: r.public_key,
        }).collect();
        let accepted_pins = workers[observer].bridge.pins_from_conductor(
            &evidence, public_keys[observer])?;
        assert_eq!(accepted_pins.len(), 3);
        for i in 0..3 {
            assert!(accepted_pins.iter().any(|p| p.member == members[i] &&
                p.public_key == public_keys[i] &&
                p.action == binding_actions[i].get_raw_39().to_vec()));
        }
        observed_key_evidence.push(evidence);
    }

    // The conductor's RPC host, NOT a native worker, decides the sender and
    // forwards the returned envelope to the recipient's local private chain.
    macro_rules! relay {
        ($messages:expr) => {{
            for env in $messages {
                let sender = members.iter().position(|p| p == &env.sender)
                    .ok_or("worker returned non-member sender")?;
                let recipient_id = env.recipient.as_ref().ok_or("missing recipient")?;
                let receiver = members.iter().position(|p| p == recipient_id)
                    .ok_or("worker returned non-member recipient")?;
                assert_ne!(sender, receiver);
                assert_eq!(env.session_id, spec.session_id);
                if env.round == 3 {
                    assert!(serde_json::from_slice::<frost::Frame>(&env.payload).is_err(),
                        "plaintext Round-2 shares must never reach the conductor");
                }
                let receipt: DeliveryReceipt = conductors.get(sender).unwrap().call(
                    &zomes[sender], "send_protocol_message", SendMessage {
                        proposal: proposal.clone(), recipient: agents[receiver].clone(),
                        round: env.round, sequence: env.sequence, payload: env.payload,
                        recipient_cap_secret: grants[receiver].cap_secret.clone(),
                    }).await;
                assert_eq!(receipt.status, ReceiptStatus::Stored);
            }
        }};
    }
    // ONLY decoded, trusted local conductor get_inbox responses are sent to
    // the node. The bridge cannot independently authenticate source actions.
    macro_rules! deliver {
        ($round:expr, $predicate:expr) => {{
            let mut outbound = Vec::new();
            for receiver in 0..3 {
                let inbox: Vec<Envelope> = conductors.get(receiver).unwrap()
                    .call(&zomes[receiver], "get_inbox", proposal.clone()).await;
                let selected: Vec<_> = inbox.into_iter()
                    .filter(|env| env.round == $round && ($predicate)(env)).collect();
                assert!(!selected.is_empty(), "expected messages for this phase");
                for env in selected {
                    outbound.extend(workers[receiver].bridge.deliver_from_local_inbox(env)?);
                }
            }
            outbound
        }};
    }
    relay!(announcements);
    let echoes = deliver!(1, |env: &Envelope| env.sequence == 1);
    assert_eq!(echoes.len(), 12);
    relay!(echoes);
    let unexpected = deliver!(1, |env: &Envelope| env.sequence > 1);
    assert!(unexpected.is_empty());

    let mut attests = Vec::new();
    for worker in &mut workers {
        attests.extend(worker.bridge.attest()?);
    }
    relay!(attests);
    let unexpected = deliver!(2, |_env: &Envelope| true);
    assert!(unexpected.is_empty());
    let mut encrypted_round_two = Vec::new();
    let mut transcript = None;
    for (i, worker) in workers.iter_mut().enumerate() {
        let (transcript_hash, outbound) = worker.bridge.round_two(
            &observed_key_evidence[i], public_keys[i])?;
        if let Some(hash) = transcript { assert_eq!(hash, transcript_hash); }
        transcript = Some(transcript_hash);
        encrypted_round_two.extend(outbound);
    }
    assert_eq!(encrypted_round_two.len(), 6);
    relay!(encrypted_round_two);
    let unexpected = deliver!(3, |_env: &Envelope| true);
    assert!(unexpected.is_empty());

    let mut descriptors = Vec::new();
    for worker in &mut workers {
        let descriptor = worker.bridge.finalize()?;
        assert_eq!(descriptor.dkg_transcript_hash, transcript.ok_or("missing transcript")?);
        descriptors.push(descriptor);
    }
    assert!(descriptors.windows(2).all(|pair| pair[0] == pair[1]));
    let descriptor = &descriptors[0];
    let digest = descriptor.digest()?;
    for i in 0..3 {
        let _: ActionHash = conductors.get(i).unwrap().call(&zomes[i],
            "publish_group_activation_attestation", PublishGroupAttestation {
                proposal: proposal.clone(), epoch: descriptor.epoch,
                descriptor_hash: digest, dkg_transcript_hash: descriptor.dkg_transcript_hash,
                public_key_package_hash: descriptor.public_key_package_hash,
            }).await;
    }
    await_consistency(&cells).await?;
    for observer in 0..3 {
        let records: Vec<GroupAttestationRecord> = conductors.get(observer).unwrap()
            .call(&zomes[observer], "get_group_activation_attestations", proposal.clone()).await;
        assert_eq!(records.len(), 3);
        let mut activated = GroupActivation::new(descriptor.clone())?;
        let mut authors = BTreeSet::new();
        for record in records {
            assert!(authors.insert(record.author.get_raw_39().to_vec()));
            assert_eq!(record.attestation.proposal, proposal);
            activated.attest(record.author.get_raw_39(), record.attestation.descriptor_hash)?;
        }
        assert_eq!(activated.finalize()?.digest(), digest);
    }
    // The conductor adapter never receives a native FROST KeyPackage.
    Ok(())
}
