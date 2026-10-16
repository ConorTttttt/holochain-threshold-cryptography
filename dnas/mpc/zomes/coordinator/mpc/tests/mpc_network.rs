//! Three-conductor integration scenario using the packaged Holochain 0.7 DNA.
//! `npm run build:happ` is REQUIRED before executing these tests.
use hdk::prelude::*;
use holochain::sweettest::*;
use holochain_mpc_core::{commitment, Envelope, SessionSpec};
use mpc::{DeliveryReceipt, PreparedGrant, PublishResult, ReceiptStatus, SendMessage, SessionStatus, RegisterEncryptionKey, EncryptionKeyRecord, RegisterKeyEpoch, KeyEpochRecord, PublishGroupAttestation, GroupAttestationRecord, PublishSigningApproval, SigningApprovalRecord};
use std::path::Path;

#[tokio::test(flavor = "multi_thread")]
async fn three_agents_consent_private_delivery_dedup_and_public_commitment() {
    let mut conductors = SweetConductorBatch::standard(3).await;
    let dna_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../workdir/mpc.dna");
    let dna = SweetDnaFile::from_bundle(&dna_path).await.unwrap();
    let apps = conductors.setup_app("mpc-v02", &[dna]).await.unwrap();
    let cells = apps.cells_flattened();
    let az = cells[0].zome("mpc");
    let bz = cells[1].zome("mpc");
    let cz = cells[2].zome("mpc");
    let alice = cells[0].agent_pubkey().clone();
    let bob = cells[1].agent_pubkey().clone();
    let charlie = cells[2].agent_pubkey().clone();
    let mut members = vec![alice.get_raw_39().to_vec(), bob.get_raw_39().to_vec(), charlie.get_raw_39().to_vec()];
    members.sort();
    let spec = SessionSpec {
        session_id: commitment("test-session", b"session A"),
        application_id: "org.example.not-payments".into(),
        protocol_id: "opaque-rounds".into(),
        protocol_version: 1,
        context_hash: commitment("application-context", b"session A"),
        participants: members,
        threshold: 2,
        max_round: 8,
    };

    let a = conductors.get(0).unwrap();
    let proposal: ActionHash = a.call(&az, "propose_session", spec.clone()).await;
    let _: ActionHash = a.call(&az, "accept_session", proposal.clone()).await;
    await_consistency(&cells).await.unwrap();
    let b = conductors.get(1).unwrap();
    let _: ActionHash = b.call(&bz, "accept_session", proposal.clone()).await;
    let c = conductors.get(2).unwrap();
    let _: ActionHash = c.call(&cz, "accept_session", proposal.clone()).await;
    await_consistency(&cells).await.unwrap();

    let status: SessionStatus = a.call(&az, "get_session_status", proposal.clone()).await;
    assert_eq!(status.accepted.len(), 3);
    assert!(status.ready_observed);
    assert_eq!(status.spec.session_id, spec.session_id);

    // Public encryption keys are signed by their actual registering agents;
    // consumers must pin exact ActionHashes, never select arbitrary "latest".
    let alice_key: ActionHash = a.call(&az, "register_encryption_key", RegisterEncryptionKey {
        proposal: proposal.clone(), public_key: [8; 32],
    }).await;
    let bob_key: ActionHash = b.call(&bz, "register_encryption_key", RegisterEncryptionKey {
        proposal: proposal.clone(), public_key: [9; 32],
    }).await;
    await_consistency(&cells).await.unwrap();
    let registered: Vec<EncryptionKeyRecord> = c.call(&cz, "get_encryption_key_bindings", proposal.clone()).await;
    assert_eq!(registered.len(), 2);
    assert!(registered.iter().any(|key| key.action == alice_key && key.author == alice && key.public_key == [8; 32]));
    assert!(registered.iter().any(|key| key.action == bob_key && key.author == bob && key.public_key == [9; 32]));

    // Append-only key versioning. A key rotation links the exact preceding
    // author-signed action; native controllers MUST also prove key possession.
    let first_epoch: ActionHash = a.call(&az,"register_encryption_key_epoch",RegisterKeyEpoch {
        proposal:proposal.clone(),epoch:0,public_key:[11;32],previous_binding:None
    }).await;
    let rotated: ActionHash = a.call(&az,"register_encryption_key_epoch",RegisterKeyEpoch {
        proposal:proposal.clone(),epoch:1,public_key:[12;32],previous_binding:Some(first_epoch.clone())
    }).await;
    await_consistency(&cells).await.unwrap();
    let epochs: Vec<KeyEpochRecord> = c.call(&cz,"get_encryption_key_epochs",proposal.clone()).await;
    assert!(epochs.iter().any(|e| e.action == rotated && e.entry.epoch == 1 && e.entry.previous_binding == Some(first_epoch.clone())));

    // Public declarations authenticate authorship, NOT successful FROST DKG.
    // These are example non-zero digests, not a simulated cryptographic proof.
    let hash=commitment("activation",b"native certificate example");
    let checkpoint: ActionHash = a.call(&az,"publish_group_activation_attestation",PublishGroupAttestation {
        proposal:proposal.clone(),epoch:0,descriptor_hash:hash,
        dkg_transcript_hash:commitment("echo",b"example"),
        public_key_package_hash:commitment("public",b"example")
    }).await;
    let _: ActionHash = b.call(&bz,"publish_group_activation_attestation",PublishGroupAttestation {
        proposal:proposal.clone(),epoch:0,descriptor_hash:hash,
        dkg_transcript_hash:commitment("echo",b"example"),
        public_key_package_hash:commitment("public",b"example")
    }).await;
    let _: ActionHash = a.call(&az,"publish_signing_approval",PublishSigningApproval {
        proposal:proposal.clone(),operation_id:commitment("operation",b"example"),
        group_descriptor_hash:hash,intent_hash:commitment("intent",b"example")
    }).await;
    await_consistency(&cells).await.unwrap();
    let group_votes: Vec<GroupAttestationRecord> = c.call(&cz,"get_group_activation_attestations",proposal.clone()).await;
    assert_eq!(group_votes.len(),2);
    assert!(group_votes.iter().any(|vote| vote.action==checkpoint && vote.author==alice));
    let approvals: Vec<SigningApprovalRecord> = c.call(&cz,"get_signing_approvals",proposal.clone()).await;
    assert_eq!(approvals.len(),1);
    assert_eq!(approvals[0].author,alice);

    // Bob creates a restrictive incoming capability; this test explicitly
    // provides its secret to Alice. Production clients must use a trusted
    // provisioning channel and avoid logging or storing it on the DHT.
    let bob_grant: PreparedGrant = b.call(&bz, "prepare_inbox_grant", proposal.clone()).await;
    let mk_send = |round, seq, payload: &[u8]| SendMessage {
        proposal: proposal.clone(), recipient: bob.clone(), round,
        sequence: seq, payload: payload.to_vec(),
        recipient_cap_secret: bob_grant.cap_secret.clone(),
    };

    // Deliver round 2 before round 1. Generic v0.2 transport buffers rather
    // than interpreting the meaning or order of cryptographic rounds.
    let r2: DeliveryReceipt = a.call(&az, "send_protocol_message", mk_send(2, 1, b"opaque-two")).await;
    assert_eq!(r2.status, ReceiptStatus::Stored);
    let r1: DeliveryReceipt = a.call(&az, "send_protocol_message", mk_send(1, 1, b"opaque-one")).await;
    assert_eq!(r1.status, ReceiptStatus::Stored);
    let retry: DeliveryReceipt = a.call(&az, "send_protocol_message", mk_send(2, 1, b"opaque-two")).await;
    assert_eq!(retry.status, ReceiptStatus::AlreadyStored);
    assert_eq!(r2.storage_action, retry.storage_action);

    let inbox: Vec<Envelope> = b.call(&bz, "get_inbox", proposal.clone()).await;
    assert_eq!(inbox.len(), 2);
    assert!(inbox.iter().any(|x| x.round == 2 && x.payload == b"opaque-two"));
    assert!(inbox.iter().any(|x| x.round == 1 && x.payload == b"opaque-one"));
    let charlie_inbox: Vec<Envelope> = c.call(&cz, "get_inbox", proposal.clone()).await;
    assert_eq!(charlie_inbox.len(), 0, "Private inbox must not replicate between agents");

    let output_hash: ActionHash = a.call(&az, "publish_result_commitment", PublishResult {
        proposal: proposal.clone(),
        result_bytes: b"example application result".to_vec(),
        verification_artifact: Vec::new(),
    }).await;
    assert_ne!(output_hash.get_raw_39(), &[0u8; 39]);
    await_consistency(&cells).await.unwrap();
    let seen_outputs: Vec<mpc_integrity::OutputProposal> = c.call(&cz, "get_output_commitments", proposal).await;
    assert_eq!(seen_outputs.len(), 1);
    // Not a correctness proof: only hash binding and DHT validation.
    assert_eq!(seen_outputs[0].commitment.protocol_id, "opaque-rounds");
}
