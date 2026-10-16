//! v0.3.4: real FROST DKG payloads across THREE running Sweettest conductors.
//!
//! Each conductor authenticates a sender at `receive_protocol_message`, writes
//! the envelope to its private source chain, and returns it through `get_inbox`.
//! The native test controller processes ONLY those inbox events: no direct
//! in-memory delivery between DKG participants.
//!
//! This is an integration scenario, NOT a production sidecar, secure capability
//! provisioning mechanism, authenticated restart journal, or Byzantine-liveness
//! proof. Secrets remain in the native test process; public keys and digests
//! are committed to author-signed Holochain actions.
use hdk::prelude::*;
use holochain::sweettest::*;
use holochain_mpc_core::{commitment, Envelope, SessionSpec};
use holochain_mpc_frost_ed25519 as frost_provider;
use holochain_mpc_security::{BroadcastMessage, Ceremony, EchoBroadcast, VerifiedTranscript};
use holochain_mpc_security::activation::{GroupActivation, GroupDescriptor};
use holochain_mpc_security::sealed::NativeChannelKey;
use mpc::{DeliveryReceipt, EncryptionKeyRecord, GroupAttestationRecord,
          PreparedGrant, PublishGroupAttestation, ReceiptStatus,
          RegisterEncryptionKey, SendMessage, SessionStatus};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[tokio::test(flavor = "multi_thread")]
async fn frost_dkg_rounds_really_traverse_three_conductors() -> TestResult<()> {
    let mut conductors = SweetConductorBatch::standard(3).await;
    let dna_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../workdir/mpc.dna");
    let dna = SweetDnaFile::from_bundle(&dna_path).await.unwrap();
    let apps = conductors.setup_app("mpc-v034-dkg", &[dna]).await.unwrap();
    let cells = apps.cells_flattened();
    let zomes = [cells[0].zome("mpc"), cells[1].zome("mpc"), cells[2].zome("mpc")];
    let agents: Vec<AgentPubKey> = cells.iter().map(|cell| cell.agent_pubkey().clone()).collect();
    let members: Vec<Vec<u8>> = agents.iter().map(|agent| agent.get_raw_39().to_vec()).collect();
    let mut sorted_members = members.clone();
    sorted_members.sort();

    let spec = SessionSpec {
        session_id: commitment("live-dkg-session", b"v034/three-conductor/frost-dkg"),
        application_id: "org.example.mpc-core-dkg".into(),
        protocol_id: frost_provider::PROTOCOL_ID.into(),
        protocol_version: frost_provider::PROTOCOL_VERSION,
        context_hash: commitment("live-dkg-context", b"Sweettest independent native controllers"),
        participants: sorted_members.clone(),
        threshold: 2,
        max_round: 6,
    };
    let proposal: ActionHash = conductors.get(0).unwrap()
        .call(&zomes[0], "propose_session", spec.clone()).await;
    await_consistency(&cells).await.unwrap();
    for i in 0..3 {
        let _: ActionHash = conductors.get(i).unwrap()
            .call(&zomes[i], "accept_session", proposal.clone()).await;
    }
    await_consistency(&cells).await.unwrap();
    for i in 0..3 {
        let status: SessionStatus = conductors.get(i).unwrap()
            .call(&zomes[i], "get_session_status", proposal.clone()).await;
        assert!(status.ready_observed, "all three agents must consent");
        assert_eq!(status.spec, spec);
    }

    let binding = frost_provider::Binding::new(proposal.get_raw_39().to_vec(), spec.clone())?;
    let ceremony = Ceremony { spec: spec.clone(), proposal_action: binding.proposal_action.clone() };

    // Test harness provisioning. Real applications need authenticated confidential
    // transport for these cap secrets, NOT public DHT publication or logs.
    let mut grants = Vec::<PreparedGrant>::new();
    for i in 0..3 {
        grants.push(conductors.get(i).unwrap()
            .call(&zomes[i], "prepare_inbox_grant", proposal.clone()).await);
    }

    // One native X25519 secret for each conductor's test controller. Register
    // its public key ON THAT AGENT'S CHAIN, then pin the exact action and author.
    let channel_keys: [NativeChannelKey; 3] = std::array::from_fn(|_| NativeChannelKey::generate());
    let mut key_actions = Vec::<ActionHash>::new();
    for i in 0..3 {
        let action: ActionHash = conductors.get(i).unwrap().call(
            &zomes[i], "register_encryption_key", RegisterEncryptionKey {
                proposal: proposal.clone(), public_key: channel_keys[i].public_key(),
            }).await;
        key_actions.push(action);
    }
    await_consistency(&cells).await.unwrap();
    for observer in 0..3 {
        let registered: Vec<EncryptionKeyRecord> = conductors.get(observer).unwrap()
            .call(&zomes[observer], "get_encryption_key_bindings", proposal.clone()).await;
        assert_eq!(registered.len(), 3, "missing/extra key bindings: abort rather than select latest");
        for i in 0..3 {
            assert_eq!(registered.iter().filter(|r|
                r.author == agents[i] && r.action == key_actions[i] &&
                r.public_key == channel_keys[i].public_key()).count(), 1);
        }
    }

    // Create the *actual* native FROST DKG state locally for each participant.
    let mut parties = Vec::<frost_provider::DkgParty>::new();
    let mut round_one = Vec::<frost_provider::RoundOne>::new();
    let mut broadcasts = Vec::<EchoBroadcast>::new();
    for i in 0..3 {
        let (party, public) = frost_provider::DkgParty::begin(binding.clone(), &members[i])?;
        parties.push(party);
        round_one.push(public);
        broadcasts.push(EchoBroadcast::new(ceremony.clone(), members[i].clone())?);
    }

    // PHASE A: sender-authenticated public Round-1 announcements cross the
    // three conductors. Nothing is fed directly into another native controller.
    for sender in 0..3 {
        let message = broadcasts[sender].begin(serde_json::to_vec(&round_one[sender])?)?;
        for receiver in 0..3 {
            if sender == receiver { continue; }
            let env = broadcasts[sender].outgoing(&members[receiver], 1, &message)?;
            let receipt: DeliveryReceipt = conductors.get(sender).unwrap()
                .call(&zomes[sender], "send_protocol_message", SendMessage {
                    proposal: proposal.clone(), recipient: agents[receiver].clone(),
                    round: env.round, sequence: env.sequence, payload: env.payload,
                    recipient_cap_secret: grants[receiver].cap_secret.clone(),
                }).await;
            assert_eq!(receipt.status, ReceiptStatus::Stored);
        }
    }

    // The recipient's private inbox is the ONLY source for processing messages.
    let mut generated_echoes: Vec<Vec<BroadcastMessage>> = vec![Vec::new(); 3];
    for receiver in 0..3 {
        let inbox: Vec<Envelope> = conductors.get(receiver).unwrap()
            .call(&zomes[receiver], "get_inbox", proposal.clone()).await;
        assert_eq!(inbox.len(), 2, "each recipient sees exactly two remote announcements");
        for env in &inbox {
            assert_eq!((env.round, env.sequence), (1, 1));
            // `receive_protocol_message` checked Holochain `call_info().provenance`
            // before storing this immutable private event. Here the native
            // controller trusts only its local, authenticated inbox API.
            let echo = broadcasts[receiver]
                .receive_envelope(&members[receiver], &env.sender, env)?
                .ok_or("fresh announcement did not produce an echo")?;
            assert!(matches!(echo, BroadcastMessage::EchoDigest { .. }));
            generated_echoes[receiver].push(echo);
        }
    }

    // PHASE B: per-origin compact echo digests, 4 incoming per recipient.
    for sender in 0..3 {
        assert_eq!(generated_echoes[sender].len(), 2);
        for (index, message) in generated_echoes[sender].iter().enumerate() {
            let sequence = index as u64 + 2; // distinct from announcement #1
            for receiver in 0..3 {
                if sender == receiver { continue; }
                let env = broadcasts[sender].outgoing(&members[receiver], sequence, message)?;
                let receipt: DeliveryReceipt = conductors.get(sender).unwrap()
                    .call(&zomes[sender], "send_protocol_message", SendMessage {
                        proposal: proposal.clone(), recipient: agents[receiver].clone(),
                        round: env.round, sequence: env.sequence, payload: env.payload,
                        recipient_cap_secret: grants[receiver].cap_secret.clone(),
                    }).await;
                assert_eq!(receipt.status, ReceiptStatus::Stored);
            }
        }
    }
    for receiver in 0..3 {
        let inbox: Vec<Envelope> = conductors.get(receiver).unwrap()
            .call(&zomes[receiver], "get_inbox", proposal.clone()).await;
        let echoes: Vec<_> = inbox.iter().filter(|e| e.round == 1 && e.sequence > 1).collect();
        assert_eq!(echoes.len(), 4);
        for env in echoes {
            assert!(broadcasts[receiver]
                .receive_envelope(&members[receiver], &env.sender, env)?.is_none());
        }
        assert!(broadcasts[receiver].echoes_complete());
    }

    // PHASE C: unanimous echo transcript attestation; these too traverse
    // actual conductors (not a test-created `VerifiedTranscript`).
    for sender in 0..3 {
        let message = broadcasts[sender].attest()?;
        for receiver in 0..3 {
            if sender == receiver { continue; }
            let env = broadcasts[sender].outgoing(&members[receiver], 1, &message)?;
            let receipt: DeliveryReceipt = conductors.get(sender).unwrap()
                .call(&zomes[sender], "send_protocol_message", SendMessage {
                    proposal: proposal.clone(), recipient: agents[receiver].clone(),
                    round: env.round, sequence: env.sequence, payload: env.payload,
                    recipient_cap_secret: grants[receiver].cap_secret.clone(),
                }).await;
            assert_eq!(receipt.status, ReceiptStatus::Stored);
        }
    }
    let mut gates = Vec::<VerifiedTranscript>::new();
    for receiver in 0..3 {
        let inbox: Vec<Envelope> = conductors.get(receiver).unwrap()
            .call(&zomes[receiver], "get_inbox", proposal.clone()).await;
        let votes: Vec<_> = inbox.iter().filter(|e| e.round == 2).collect();
        assert_eq!(votes.len(), 2);
        for env in votes {
            assert!(broadcasts[receiver]
                .receive_envelope(&members[receiver], &env.sender, env)?.is_none());
        }
        gates.push(broadcasts[receiver].finalize()?);
    }
    assert!(gates.windows(2).all(|pair| pair[0].hash() == pair[1].hash()));

    // PHASE D: advance each independently held FROST state using only its own
    // native gate and received, authenticated Round-1 package bytes.
    let mut per_party_round_one = Vec::<BTreeMap<frost_provider::Identifier, frost_provider::RoundOne>>::new();
    let mut outgoing = Vec::<BTreeMap<frost_provider::Identifier, frost_provider::RoundTwo>>::new();
    for i in 0..3 {
        let mut packages = BTreeMap::new();
        for origin in &sorted_members {
            let serialized = gates[i].package(origin).ok_or("gate missing participant package")?;
            let public: frost_provider::RoundOne = serde_json::from_slice(serialized)?;
            packages.insert(binding.id_of(origin)?, public);
        }
        outgoing.push(parties[i].part2(&packages, &gates[i])?);
        per_party_round_one.push(packages);
    }

    // PHASE E: encrypted, recipient-specific FROST shares, delivered over
    // Holochain. Only ciphertext reaches the coordinator's private inbox.
    for sender in 0..3 {
        for receiver in 0..3 {
            if sender == receiver { continue; }
            let id = binding.id_of(&members[receiver])?;
            let package = outgoing[sender].get(&id).ok_or("missing outgoing DKG share")?;
            let frame = frost_provider::Frame {
                proposal_action: binding.proposal_action.clone(),
                operation_id: spec.session_id,
                message: frost_provider::Message::DkgRound2(package.clone()),
            };
            let env = frost_provider::seal_dkg_round_two(
                &binding, &frame, &members[sender], &members[receiver], 1,
                &channel_keys[sender], channel_keys[receiver].public_key())?;
            assert_eq!(env.round, 3);
            assert!(serde_json::from_slice::<frost_provider::Frame>(&env.payload).is_err(),
                    "coordinator payload must not parse as a plaintext FROST frame");
            let receipt: DeliveryReceipt = conductors.get(sender).unwrap()
                .call(&zomes[sender], "send_protocol_message", SendMessage {
                    proposal: proposal.clone(), recipient: agents[receiver].clone(),
                    round: env.round, sequence: env.sequence, payload: env.payload,
                    recipient_cap_secret: grants[receiver].cap_secret.clone(),
                }).await;
            assert_eq!(receipt.status, ReceiptStatus::Stored);
        }
    }

    // Native recipients decrypt ONLY after the Holochain-authenticated inbox
    // and the independently pinned X25519 sender key agree.
    let mut local_keys = Vec::<Option<frost_provider::KeyPackage>>::new();
    let mut common_public: Option<frost_provider::PublicKeyPackage> = None;
    let mut common_descriptor: Option<GroupDescriptor> = None;
    let action_hashes: Vec<Vec<u8>> = sorted_members.iter().map(|member| {
        let i = members.iter().position(|p| p == member).expect("member index");
        key_actions[i].get_raw_39().to_vec()
    }).collect();
    for receiver in 0..3 {
        let inbox: Vec<Envelope> = conductors.get(receiver).unwrap()
            .call(&zomes[receiver], "get_inbox", proposal.clone()).await;
        let mut shares = BTreeMap::new();
        let mut sealed_events: Vec<_> = inbox.into_iter().filter(|e| e.round == 3).collect();
        assert_eq!(sealed_events.len(), 2);
        sealed_events.reverse(); // reorder Round-2 delivery; origin mapping remains stable.
        for env in &sealed_events {
            let sender = members.iter().position(|member| *member == env.sender)
                .ok_or("unauthorised Round-2 source")?;
            assert_ne!(sender, receiver);
            let frame = frost_provider::open_dkg_round_two(
                &binding, env, &members[receiver], &members[sender],
                &channel_keys[receiver], channel_keys[sender].public_key())?;
            // Wrong pinned sender provenance/key is never trusted.
            let wrong_sender = (sender + 1) % 3;
            assert!(frost_provider::open_dkg_round_two(
                &binding, env, &members[receiver], &members[wrong_sender],
                &channel_keys[receiver], channel_keys[wrong_sender].public_key()).is_err());
            let frost_provider::Message::DkgRound2(package) = frame.message else {
                return Err("decrypted message is not DKG Round 2".into());
            };
            assert!(shares.insert(binding.id_of(&members[sender])?, package).is_none());
        }
        let (secret, public, evidence) = parties[receiver].part3_with_evidence(
            &per_party_round_one[receiver], &shares, &gates[receiver])?;
        let descriptor = evidence.group_descriptor(&binding, 0, action_hashes.clone())?;
        if let Some(previous) = &common_public {
            assert_eq!(serde_json::to_vec(previous)?, serde_json::to_vec(&public)?);
        } else {
            common_public = Some(public);
        }
        if let Some(previous) = &common_descriptor {
            assert_eq!(previous, &descriptor);
        } else {
            common_descriptor = Some(descriptor);
        }
        local_keys.push(Some(secret));
    }

    // PHASE F: all three independent native DKG completions author their own
    // public Holochain attestation; inspect *record authors*, not caller data.
    let descriptor = common_descriptor.ok_or("missing group descriptor")?;
    let descriptor_hash = descriptor.digest()?;
    for i in 0..3 {
        let _: ActionHash = conductors.get(i).unwrap().call(
            &zomes[i], "publish_group_activation_attestation", PublishGroupAttestation {
                proposal: proposal.clone(), epoch: descriptor.epoch,
                descriptor_hash, dkg_transcript_hash: descriptor.dkg_transcript_hash,
                public_key_package_hash: descriptor.public_key_package_hash,
            }).await;
    }
    await_consistency(&cells).await.unwrap();
    for observer in 0..3 {
        let attestations: Vec<GroupAttestationRecord> = conductors.get(observer).unwrap()
            .call(&zomes[observer], "get_group_activation_attestations", proposal.clone()).await;
        assert_eq!(attestations.len(), 3);
        let mut seen = BTreeSet::new();
        let mut activation = GroupActivation::new(descriptor.clone())?;
        for record in attestations {
            assert!(seen.insert(record.author.get_raw_39().to_vec()), "duplicate voter");
            assert_eq!(record.attestation.proposal, proposal);
            assert_eq!(record.attestation.epoch, descriptor.epoch);
            assert_eq!(record.attestation.dkg_transcript_hash, descriptor.dkg_transcript_hash);
            assert_eq!(record.attestation.public_key_package_hash, descriptor.public_key_package_hash);
            activation.attest(record.author.get_raw_39(), record.attestation.descriptor_hash)?;
        }
        assert_eq!(activation.finalize()?.digest(), descriptor_hash);
    }

    // A native smoke test that the generated shares can sign 2-of-3.
    // This uses the in-memory test-only Signer; NOT a Holochain-mediated
    // approval/nonce-WAL signing flow (that is a separate milestone).
    let operation = commitment("v034-sign", b"check actual dkg key is usable");
    let message = b"v0.3.4 native signature after live three-conductor DKG";
    let mut signing_commitments = BTreeMap::new();
    let mut signers = Vec::new();
    for index in 0..2 {
        let id = binding.id_of(&members[index])?;
        let key = local_keys[index].take().ok_or("no local FROST key")?;
        let mut signer = frost_provider::Signer::new(binding.clone(), &members[index], key)?;
        signing_commitments.insert(id, signer.commit(operation, message)?);
        signers.push((id, signer));
    }
    let pkg = frost_provider::signing_package(&binding, operation, message, signing_commitments)?;
    let mut signature_shares = BTreeMap::new();
    for (id, signer) in &mut signers {
        signature_shares.insert(*id, signer.sign(operation, &pkg)?);
    }
    let public = common_public.ok_or("missing public key package")?;
    let artifact = frost_provider::aggregate(
        &binding, operation, message, &pkg, &signature_shares, &public)?;
    frost_provider::verify_artifact(
        &binding, message, &artifact, &public.verifying_key().serialize()?)?;
    Ok(())
}
