//! Deterministic topology, real random cryptographic participants.
//! Simulates three isolated native agents. Holochain Sweettest remains v0.2;
//! end-to-end native<->Holochain runtime integration still needs testing.
use holochain_mpc_core::{commitment, SessionSpec};
use holochain_mpc_frost_ed25519 as provider;
use provider::{aggregate, signing_package, verify_artifact, Binding, DkgParty,
               Frame, Identifier, Message, ProviderError, Signer,
               seal_dkg_round_two, open_dkg_round_two};
use holochain_mpc_security::{Ceremony, BroadcastMessage, EchoBroadcast, VerifiedTranscript};
use holochain_mpc_security::sealed::NativeChannelKey;
use std::collections::BTreeMap;

type PResult<T> = Result<T, Box<dyn std::error::Error>>;

fn fixture() -> (Binding, Vec<Vec<u8>>) {
    // Native-only placeholder identities. Holochain integration must supply
    // actual AgentPubKeys and a real signed proposal ActionHash instead.
    let members = vec![vec![1; 39], vec![2; 39], vec![3; 39]];
    let spec = SessionSpec {
        session_id: commitment("test-frost-session", b"fresh session 0"),
        application_id: "example.multiple-apps".into(),
        protocol_id: provider::PROTOCOL_ID.into(),
        protocol_version: provider::PROTOCOL_VERSION,
        context_hash: commitment("application-description", b"no payments"),
        participants: members.clone(),
        threshold: 2,
        max_round: 6,
    };
    (Binding::new(vec![7; 39], spec).expect("valid binding"), members)
}

/// Network simulator with authenticated provenance on every direct and echo
/// delivery. Produces a gate from unanimous *real messages*, not a fabricated
/// digest map. Application adapters must persist and authenticate each event.
fn verified_gate(binding: &Binding, members: &[Vec<u8>], packages: &BTreeMap<Identifier, provider::RoundOne>)
    -> PResult<VerifiedTranscript> {
    let ceremony = Ceremony { spec: binding.spec.clone(), proposal_action: binding.proposal_action.clone() };
    let mut states: Vec<EchoBroadcast> = members.iter().map(|m| EchoBroadcast::new(ceremony.clone(), m.clone()))
        .collect::<Result<_,_>>()?;
    let announces: Vec<_> = members.iter().enumerate().map(|(index,member)| {
        let pkg = serde_json::to_vec(&packages[&binding.id_of(member)?])?;
        Ok::<_, Box<dyn std::error::Error>>(states[index].begin(pkg)?)
    }).collect::<Result<_,_>>()?;
    let mut echoes = Vec::new();
    for (sender, msg) in announces.into_iter().enumerate() {
        for receiver in 0..members.len() {
            if sender == receiver { continue; }
            let echo = states[receiver].receive(&members[sender], msg.clone())?.ok_or("no echo")?;
            echoes.push((receiver, echo));
        }
    }
    echoes.reverse();
    for (forwarder, echo) in echoes {
        for receiver in 0..members.len() {
            if forwarder != receiver {
                states[receiver].receive(&members[forwarder], echo.clone())?;
            }
        }
    }
    let attestations: Vec<BroadcastMessage> = states.iter_mut().map(EchoBroadcast::attest).collect::<Result<_,_>>()?;
    for (sender, attest) in attestations.into_iter().enumerate() {
        for receiver in 0..members.len() {
            if sender != receiver {
                states[receiver].receive(&members[sender], attest.clone())?;
            }
        }
    }
    let gates: Vec<VerifiedTranscript> = states.iter().map(EchoBroadcast::finalize).collect::<Result<_,_>>()?;
    assert!(gates.windows(2).all(|s| s[0].hash() == s[1].hash()));
    Ok(gates[0].clone())
}

fn generate() -> PResult<(Binding, Vec<Vec<u8>>, BTreeMap<Identifier, provider::KeyPackage>, provider::PublicKeyPackage, [u8;32])> {
    let (binding, members) = fixture();
    let mut parties = BTreeMap::new();
    let mut public_round1 = BTreeMap::new();
    for agent in &members {
        let (p, pkg) = DkgParty::begin(binding.clone(), agent)?;
        let id = binding.id_of(agent)?;
        parties.insert(id, p);
        public_round1.insert(id, pkg);
    }

    // Real authenticated echo-and-attest messages, not synthetic attestation maps.
    let gate = verified_gate(&binding, &members, &public_round1)?;
    assert_eq!(gate.packages().len(), members.len());
    let echo_hash = gate.hash();
    let mut private_out = BTreeMap::new();
    for (id, party) in parties.iter_mut() {
        let outgoing = party.part2(&public_round1, &gate)?;
        private_out.insert(*id, outgoing);
    }
    let native_keys: Vec<_> = members.iter().map(|_| NativeChannelKey::generate()).collect();
    let mut keys = BTreeMap::new();
    let mut group = None;
    for (receiver, party) in parties.iter_mut() {
        let receiver_member = binding.member_for(*receiver)?;
        let receiver_index = members.iter().position(|m| m == receiver_member).ok_or("not member")?;
        let mut private_in = BTreeMap::new();
        for (sender_id, outgoing) in &private_out {
            if sender_id == receiver { continue; }
            let package = outgoing.get(receiver).ok_or("missing outgoing share")?;
            let sender = binding.member_for(*sender_id)?;
            let sender_index = members.iter().position(|m| m == sender).ok_or("not member")?;
            let frame = Frame { proposal_action: binding.proposal_action.clone(),
                operation_id: binding.spec.session_id,
                message: Message::DkgRound2(package.clone()) };
            let envelope = seal_dkg_round_two(&binding, &frame, sender, receiver_member, 1,
                                               &native_keys[sender_index], native_keys[receiver_index].public_key())?;
            // The Holochain coordinator sees ciphertext only; private key
            // material is decrypted in the recipient's native controller.
            assert!(!serde_json::to_vec(&envelope.payload)?.windows(12).any(|w| w == b"SecretPackage"));
            let verified = open_dkg_round_two(&binding, &envelope, receiver_member, sender,
                                               &native_keys[receiver_index], native_keys[sender_index].public_key())?;
            if let Message::DkgRound2(received) = verified.message {
                private_in.insert(*sender_id, received);
            } else { return Err("wrong message type".into()); }
            // A forged Holochain authenticated caller is rejected.
            let wrong_sender = &members[(sender_index+1)%3];
            assert!(open_dkg_round_two(&binding, &envelope, receiver_member, wrong_sender,
                &native_keys[receiver_index], native_keys[sender_index].public_key()).is_err());
        }
        let (secret_key, public_key, public_proposal) =
            party.part3_with_evidence(&public_round1, &private_in, &gate)?;
        assert_eq!(public_proposal.transcript_hash(), echo_hash);
        let descriptor = public_proposal.group_descriptor(&binding, 0,
            vec![vec![11;39],vec![12;39],vec![13;39]])?;
        assert_eq!(descriptor.group_verifying_key, public_key.verifying_key().serialize()?);
        assert_eq!(descriptor.public_key_package_hash,
            commitment("frost-public-key-package-v1", &serde_json::to_vec(&public_key)?));
        if let Some(existing) = &group {
            let existing: &provider::PublicKeyPackage = existing;
            assert_eq!(serde_json::to_vec(existing)?, serde_json::to_vec(&public_key)?);
            assert_eq!(existing.verifying_key().serialize()?, public_key.verifying_key().serialize()?);
        } else {
            group = Some(public_key);
        }
        keys.insert(*receiver, secret_key);
    }
    Ok((binding, members, keys, group.expect("group key"), echo_hash))
}

#[test]
fn three_agent_dkg_two_agent_signing_and_verification() -> PResult<()> {
    let (binding, members, mut keys, group, _) = generate()?;
    let operation_id = commitment("sign-operation", b"proposal-1");
    let message = b"example independent application: authorize object 9";
    // Two of three; every agent participated in DKG but the third need not sign.
    let mut signers = BTreeMap::new();
    let mut commits = BTreeMap::new();
    for member in &members[..2] {
        let id = binding.id_of(member)?;
        let mut signer = Signer::new(binding.clone(), member, keys.remove(&id).ok_or("missing key")?)?;
        commits.insert(id, signer.commit(operation_id, message)?);
        signers.insert(id, signer);
    }
    let pkg = signing_package(&binding, operation_id, message, commits)?;
    let mut shares = BTreeMap::new();
    for (id, signer) in signers.iter_mut() {
        shares.insert(*id, signer.sign(operation_id, &pkg)?);
        assert!(matches!(signer.sign(operation_id, &pkg), Err(ProviderError::SigningNonceUnavailable)));
    }
    let proof = aggregate(&binding, operation_id, message, &pkg, &shares, &group)?;
    let trusted = group.verifying_key().serialize()?;
    verify_artifact(&binding, message, &proof, &trusted)?;
    assert!(verify_artifact(&binding, b"altered", &proof, &trusted).is_err());
    assert!(verify_artifact(&binding, message, &proof, &[13; 32]).is_err());
    let mut mismatched = binding.clone();
    mismatched.proposal_action[0] ^= 1;
    assert!(verify_artifact(&mismatched, message, &proof, &trusted).is_err());
    Ok(())
}

#[test]
fn abort_on_broadcast_mismatch() -> PResult<()> {
    let (binding, members) = fixture();
    let mut parties = BTreeMap::new();
    let mut rounds = BTreeMap::new();
    for agent in &members {
        let (p, public) = DkgParty::begin(binding.clone(), agent)?;
        let id = binding.id_of(agent)?;
        parties.insert(id, p);
        rounds.insert(id, public);
    }
    let gate = verified_gate(&binding, &members, &rounds)?;
    let first = *parties.keys().next().unwrap();
    // Replacing a different participant's R1 package after agreement MUST
    // invalidate the gate even if the FROST map still has all participants.
    let other = *parties.keys().find(|id| **id != first).unwrap();
    let mut falsified = rounds.clone();
    falsified.insert(other, rounds[&first].clone());
    let party = parties.get_mut(&first).unwrap();
    assert!(matches!(party.part2(&falsified, &gate), Err(ProviderError::InconsistentTranscript)));
    Ok(())
}

#[test]
fn reject_forged_sender_tampered_frame_and_small_roster() -> PResult<()> {
    let (binding, members) = fixture();
    let (p, r1) = DkgParty::begin(binding.clone(), &members[0])?;
    let frame = Frame { proposal_action: binding.proposal_action.clone(),
                        operation_id: binding.spec.session_id, message: Message::DkgRound1(r1) };
    let env = frame.encode(&binding, &members[0], &members[1], 1)?;
    assert!(Frame::decode(&binding, &env, &members[1], &members[2]).is_err());
    let mut malicious = env.clone();
    malicious.round = 6;
    assert!(Frame::decode(&binding, &malicious, &members[1], &members[0]).is_err());
    let mut malicious = env.clone();
    malicious.payload[0] ^= 1;
    assert!(Frame::decode(&binding, &malicious, &members[1], &members[0]).is_err());
    assert_eq!(p.identifier(), binding.id_of(&members[0])?);
    assert!(signing_package(&binding, commitment("op",b"1"), b"hello", BTreeMap::new()).is_err());
    Ok(())
}

#[test]
fn fail_closed_when_signing_intent_is_swapped() -> PResult<()> {
    let (binding, members, mut keys, _, _) = generate()?;
    let op = commitment("op", b"intent-a");
    let id = binding.id_of(&members[0])?;
    let mut signer = Signer::new(binding.clone(), &members[0], keys.remove(&id).ok_or("missing key")?)?;
    let _commit = signer.commit(op, b"message-a")?;
    // Wrong application message: signing nonce must be consumed even though it fails.
    let wrong = frost_ed25519::SigningPackage::new(BTreeMap::new(), b"message-b");
    assert!(signer.sign(op, &wrong).is_err());
    assert!(matches!(signer.sign(op, &wrong), Err(ProviderError::SigningNonceUnavailable)));
    Ok(())
}

#[test]
fn activated_group_approved_intent_nonce_wal_and_threshold_signing() -> PResult<()> {
    use provider::{ControlledSigner,verify_activated_artifact};
    use holochain_mpc_security::activation::{GroupDescriptor,GroupActivation,
        SigningIntent,SigningProfile,IntentApprovals};
    use holochain_mpc_runtime::{MasterKey,RuntimeStore};
    let (binding,members,mut keys,public,echo_hash)=generate()?;
    let serialized=serde_json::to_vec(&public)?;
    let group_desc=GroupDescriptor {
        proposal_action:binding.proposal_action.clone(),spec:binding.spec.clone(),epoch:0,
        dkg_transcript_hash:echo_hash,
        public_key_package_hash:commitment("frost-public-key-package-v1",&serialized),
        group_verifying_key:public.verifying_key().serialize()?,
        encryption_key_binding_actions:vec![vec![11;39],vec![12;39],vec![13;39]],
    };
    let mut activation=GroupActivation::new(group_desc.clone())?;
    for m in &members { activation.attest(m,group_desc.digest()?)?; }
    let active=activation.finalize()?;
    let op=commitment("operation",b"hardened signer test");
    let msg=b"authorization for inventory transfer";
    let intent=SigningIntent::new(&active,op,msg,members[..2].to_vec(),SigningProfile::ContextBoundV1)?;
    let mut votes=IntentApprovals::new(intent.clone());
    for m in &members[..2] { votes.approve(m,intent.digest()?)?; }
    let approved=votes.finalize()?;
    let tmp=tempfile::tempdir()?;
    let mut signs=BTreeMap::new();
    let mut pubs=BTreeMap::new();
    let mut stores=BTreeMap::new();
    for member in &members[..2] {
        let id=binding.id_of(member)?;
        let signer=ControlledSigner::new(binding.clone(),member,keys.remove(&id).ok_or("missing signing key")?,
            &public,active.clone())?;
        let path=tmp.path().join(format!("signer-{:?}.db",member[0]));
        let mut state=RuntimeStore::open(&path,MasterKey::from_bytes([member[0];32]))?;
        let mut signer=signer;
        state.start_deadline(&binding.proposal_action,&op,1000)?;
        let share_commit=signer.prepare(&mut state,&approved,msg,100)?;
        // Reopening same DB must not permit a second commitment on this
        // operation/epoch/member slot.
        drop(state);
        let mut reopened=RuntimeStore::open(&path,MasterKey::from_bytes([member[0];32]))?;
        assert!(reopened.reserve_nonce(&binding.proposal_action,0,&op,member,100).is_err());
        pubs.insert(id,share_commit);
        signs.insert(id,signer);
        stores.insert(id,reopened);
    }
    let package=signing_package(&binding,op,msg,pubs)?;
    let mut shares=BTreeMap::new();
    for (id,signer) in signs.iter_mut() {
        shares.insert(*id,signer.sign(stores.get_mut(id).ok_or("missing store")?,&approved,msg,&package,100)?);
    }
    let mut collected=provider::AuthenticatedShareCollector::new(binding.clone(),&package)?;
    for (id,share) in shares {
        let authenticated_sender=binding.member_for(id)?;
        collected.ingest(authenticated_sender,share,&package)?;
    }
    let artifact=collected.aggregate(&binding,op,msg,&package,&public,&active)?;
    verify_activated_artifact(&binding,msg,&artifact,&active)?;
    assert!(verify_activated_artifact(&binding,b"tampered",&artifact,&active).is_err());
    Ok(())
}


/// Bounded deterministic input corpus; each seed/case pair gives the same
/// attacker-controlled bytes. Real FROST DKG itself continues using OsRng.
const ADVERSARIAL_SEEDS: [u64; 4] = [
    1, 0x3141_5926_5358_9793, 0x9e37_79b9_7f4a_7c15, 0xffff_ffff_ffff_fffe,
];
fn next_adversarial(state: &mut u64) -> u64 {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    (*state).wrapping_mul(0x2545_f491_4f6c_dd1d)
}

#[test]
fn bounded_frame_and_sealed_decoder_malformed_inputs_do_not_panic() -> PResult<()> {
    use holochain_mpc_core::Envelope;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let (binding, members) = fixture();
    let (_party, r1) = DkgParty::begin(binding.clone(), &members[0])?;
    let valid_frame = Frame { proposal_action: binding.proposal_action.clone(),
        operation_id: binding.spec.session_id, message: Message::DkgRound1(r1) };
    let valid = valid_frame.encode(&binding, &members[0], &members[1], 1)?;
    assert!(Frame::decode(&binding, &valid, &members[1], &members[0]).is_ok());
    for seed in ADVERSARIAL_SEEDS {
        let mut rng = seed;
        for case in 0..128usize {
            let len = 1 + (next_adversarial(&mut rng) as usize % 2048);
            let bytes = match case % 4 {
                0 => vec![b'['; len], // nesting bombs, rejected by JSON depth checks
                1 => vec![0xff; len], // invalid UTF-8
                2 => vec![b'0'; len], // huge scalar / trailing bytes
                _ => (0..len).map(|_| next_adversarial(&mut rng) as u8).collect(),
            };
            let env = Envelope::new(&binding.spec, members[0].clone(),
                Some(members[1].clone()), 1, 1, bytes.clone())?;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                Frame::decode(&binding, &env, &members[1], &members[0])
            }));
            assert!(outcome.is_ok(), "frame panic seed={seed:#x} case={case}");
            assert!(outcome.unwrap().is_err(), "malformed frame accepted seed={seed:#x} case={case}");

            let sealed_env = Envelope::new(&binding.spec, members[0].clone(),
                Some(members[1].clone()), 3, 1, bytes)?;
            let receiver = NativeChannelKey::generate();
            let sender = NativeChannelKey::generate();
            let opened = catch_unwind(AssertUnwindSafe(|| open_dkg_round_two(
                &binding, &sealed_env, &members[1], &members[0],
                &receiver, sender.public_key()
            )));
            assert!(opened.is_ok(), "sealed parser panic seed={seed:#x} case={case}");
            assert!(opened.unwrap().is_err(), "bad sealed packet accepted seed={seed:#x} case={case}");
        }
    }
    Ok(())
}

#[test]
fn frame_rejects_proposal_session_and_transport_mismatch_after_rehashing() -> PResult<()> {
    use holochain_mpc_core::Envelope;
    let (binding, members) = fixture();
    let (_party, r1) = DkgParty::begin(binding.clone(), &members[0])?;
    let good = Frame { proposal_action: binding.proposal_action.clone(),
        operation_id: binding.spec.session_id, message: Message::DkgRound1(r1) };
    let mut bad_proposal = good.clone();
    bad_proposal.proposal_action[0] ^= 1;
    let mut bad_operation = good.clone();
    bad_operation.operation_id = commitment("wrong-operation", b"wrong operation");
    for frame in [bad_proposal, bad_operation] {
        // Recreate the *correct* envelope hash so failure is in the cryptographic
        // binding layer, not merely the outer payload checksum.
        let env = Envelope::new(&binding.spec, members[0].clone(),
            Some(members[1].clone()), 1, 1, serde_json::to_vec(&frame)?)?;
        assert!(Frame::decode(&binding, &env, &members[1], &members[0]).is_err());
    }
    let mut round = good.encode(&binding, &members[0], &members[1], 1)?;
    round.round = 2;
    assert!(Frame::decode(&binding, &round, &members[1], &members[0]).is_err());
    let ok = good.encode(&binding, &members[0], &members[1], 1)?;
    assert!(Frame::decode(&binding, &ok, &members[1], &members[2]).is_err());
    assert!(Frame::decode(&binding, &ok, &members[2], &members[0]).is_err());
    let mut wrong_proposal_binding = binding.clone();
    wrong_proposal_binding.proposal_action[0] ^= 1;
    assert!(Frame::decode(&wrong_proposal_binding, &ok, &members[1], &members[0]).is_err());
    Ok(())
}

#[test]
fn tampered_round_two_peer_share_cannot_complete_dkg_or_activate() -> PResult<()> {
    let (binding, members) = fixture();
    let mut parties = BTreeMap::new();
    let mut public_rounds = BTreeMap::new();
    for member in &members {
        let (party, public) = DkgParty::begin(binding.clone(), member)?;
        let id = binding.id_of(member)?;
        parties.insert(id, party);
        public_rounds.insert(id, public);
    }
    let gate = verified_gate(&binding, &members, &public_rounds)?;
    let mut round_two = BTreeMap::new();
    for (id, party) in &mut parties {
        round_two.insert(*id, party.part2(&public_rounds, &gate)?);
    }
    let recipient = binding.id_of(&members[0])?;
    let sender_b = binding.id_of(&members[1])?;
    let sender_c = binding.id_of(&members[2])?;
    let mut incoming = BTreeMap::new();
    incoming.insert(sender_b, round_two[&sender_b][&recipient].clone());
    // The C-labelled package contains B's valid share; FROST's public
    // commitment check must reject it before yielding a usable key.
    incoming.insert(sender_c, round_two[&sender_b][&recipient].clone());
    assert!(parties.get_mut(&recipient).ok_or("missing recipient")?
        .part3_with_evidence(&public_rounds, &incoming, &gate).is_err());
    // No GroupActivation or ActivatedGroup was created from this bad input.
    Ok(())
}

#[test]
fn forged_share_attribution_cross_operation_replay_and_peer_commitments_fail() -> PResult<()> {
    use provider::AuthenticatedShareCollector;
    use holochain_mpc_security::activation::{GroupActivation, GroupDescriptor};
    let (binding, members, mut keys, public, echo_hash) = generate()?;
    let operation_a = commitment("s17-signing-operation", b"A");
    let operation_b = commitment("s17-signing-operation", b"B");
    let message = b"test fixture: no assets";
    let mut signers = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for member in &members[..2] {
        let id = binding.id_of(member)?;
        let mut signer = Signer::new(binding.clone(), member,
            keys.remove(&id).ok_or("missing key")?)?;
        commitments.insert(id, signer.commit(operation_a, message)?);
        signers.insert(id, signer);
    }
    let signing_a = signing_package(&binding, operation_a, message, commitments.clone())?;
    let mut shares = BTreeMap::new();
    for (id, signer) in &mut signers {
        shares.insert(*id, signer.sign(operation_a, &signing_a)?);
    }
    let group_desc = GroupDescriptor {
        proposal_action: binding.proposal_action.clone(), spec: binding.spec.clone(),
        epoch: 0, dkg_transcript_hash: echo_hash,
        public_key_package_hash: commitment("frost-public-key-package-v1", &serde_json::to_vec(&public)?),
        group_verifying_key: public.verifying_key().serialize()?,
        encryption_key_binding_actions: vec![vec![11; 39], vec![12; 39], vec![13; 39]],
    };
    let mut activation = GroupActivation::new(group_desc.clone())?;
    for member in &members { activation.attest(member, group_desc.digest()?)?; }
    let active = activation.finalize()?;

    let a = binding.id_of(&members[0])?;
    let b = binding.id_of(&members[1])?;
    let mut wrong_identity = AuthenticatedShareCollector::new(binding.clone(), &signing_a)?;
    // Bytes authored by signer A are delivered over B's authenticated channel,
    // and vice versa. Attribution MUST use provenance, not an untrusted label.
    wrong_identity.ingest(&members[1], shares[&a].clone(), &signing_a)?;
    wrong_identity.ingest(&members[0], shares[&b].clone(), &signing_a)?;
    assert!(wrong_identity.aggregate(&binding, operation_a, message,
        &signing_a, &public, &active).is_err());
    let mut outsider = AuthenticatedShareCollector::new(binding.clone(), &signing_a)?;
    assert!(outsider.ingest(&members[2], shares[&a].clone(), &signing_a).is_err());
    assert!(outsider.ingest(&vec![99; 39], shares[&a].clone(), &signing_a).is_err());

    let signing_b = signing_package(&binding, operation_b, message, commitments.clone())?;
    assert!(aggregate(&binding, operation_b, message, &signing_b, &shares, &public).is_err());
    assert!(aggregate(&binding, operation_b, message, &signing_a, &shares, &public).is_err());
    let frame = Frame { proposal_action: binding.proposal_action.clone(),
        operation_id: operation_a, message: Message::SignatureShare(shares[&a].clone()) };
    let wire = frame.encode(&binding, &members[0], &members[2], 101)?;
    let decoded = Frame::decode(&binding, &wire, &members[2], &members[0])?;
    // Frame::decode validates wire and ceremony context, but it has NO
    // expected-operation argument. The consuming dispatcher MUST compare
    // operation_id before ingesting a frame into any signing operation.
    assert_eq!(decoded.operation_id, operation_a);
    assert_ne!(decoded.operation_id, operation_b);

    let mut tampered_peer = commitments;
    let forged = tampered_peer[&a].clone();
    tampered_peer.insert(b, forged);
    let changed = signing_package(&binding, operation_a, message, tampered_peer)?;
    assert!(aggregate(&binding, operation_a, message, &changed, &shares, &public).is_err());

    let artifact = aggregate(&binding, operation_a, message, &signing_a, &shares, &public)?;
    verify_artifact(&binding, message, &artifact, &public.verifying_key().serialize()?)?;
    let json = serde_json::to_value(&artifact)?;
    let object = json.as_object().ok_or("artifact must be an object")?;
    // Explicit public allowlist: neither the long-term FROST share nor nonce
    // state is a field of SignedArtifact. This is NOT a memory-leak proof.
    assert_eq!(object.len(), 5);
    for key in ["proposal_action", "session_id", "operation_id", "public_key", "signature"] {
        assert!(object.contains_key(key));
    }
    Ok(())
}


// ---- Sprint 1.7 / Agent 20: Fable F-8 (A28) storage-failure regression ----
// All identities, shares and storage keys below are disposable native-test data.
// SQLite triggers fail *real* transactions before publication; no production
// fault injection API, persistence-format change or nonce recovery is needed.

use holochain_mpc_runtime::{MasterKey, RuntimeStore, RuntimeError};
use holochain_mpc_security::activation::{
    ActivatedGroup, ApprovedIntent, GroupActivation, GroupDescriptor,
    IntentApprovals, SigningIntent, SigningProfile,
};
use provider::ControlledSigner;

struct SigningStorageFaultFixture {
    binding: Binding,
    members: Vec<Vec<u8>>,
    keys: BTreeMap<Identifier, provider::KeyPackage>,
    public: provider::PublicKeyPackage,
    active: ActivatedGroup,
}
impl SigningStorageFaultFixture {
    fn new() -> PResult<Self> {
        let (binding, members, keys, public, transcript_hash) = generate()?;
        let descriptor = GroupDescriptor {
            proposal_action: binding.proposal_action.clone(),
            spec: binding.spec.clone(),
            epoch: 0,
            dkg_transcript_hash: transcript_hash,
            public_key_package_hash: commitment(
                "frost-public-key-package-v1", &serde_json::to_vec(&public)?),
            group_verifying_key: public.verifying_key().serialize()?,
            encryption_key_binding_actions: vec![vec![11;39], vec![12;39], vec![13;39]],
        };
        let mut votes = GroupActivation::new(descriptor.clone())?;
        for member in &members {
            votes.attest(member, descriptor.digest()?)?;
        }
        Ok(Self { binding, members, keys, public, active: votes.finalize()? })
    }

    fn signer(&mut self, index: usize) -> PResult<ControlledSigner> {
        let member = &self.members[index];
        let id = self.binding.id_of(member)?;
        let key = self.keys.remove(&id).ok_or("missing disposable share")?;
        Ok(ControlledSigner::new(self.binding.clone(), member, key,
                                 &self.public, self.active.clone())?)
    }

    fn approved(&self, operation: [u8;32], message: &[u8]) -> PResult<ApprovedIntent> {
        let intent = SigningIntent::new(
            &self.active, operation, message, self.members[..2].to_vec(),
            SigningProfile::ContextBoundV1)?;
        let mut votes = IntentApprovals::new(intent.clone());
        for signer in &self.members[..2] {
            votes.approve(signer, intent.digest()?)?;
        }
        Ok(votes.finalize()?)
    }

    fn sql(&self, db: &mut RuntimeStore, sequence: u64, statement: &str) -> PResult<()> {
        // apply_received allows a database-only test side effect within a
        // real SQLite transaction, avoiding public test-only RuntimeStore APIs.
        let envelope = holochain_mpc_core::Envelope::new(
            &self.binding.spec, self.members[2].clone(),
            Some(self.members[0].clone()), 1, sequence,
            format!("agent20-sql-fault-{sequence}").into_bytes())?;
        db.apply_received(
            &self.binding.proposal_action, &self.binding.spec,
            &self.members[0], &self.members[2], &envelope,
            |tx| { tx.execute_batch(statement)?; Ok(()) },
        )?;
        Ok(())
    }

    fn nonce_state(&self, db: &mut RuntimeStore, sequence: u64,
                   operation: [u8;32]) -> PResult<Option<String>> {
        let operation_hex: String = operation.iter().map(|byte| format!("{byte:02x}")).collect();
        let statement = format!(
            "SELECT state FROM nonces WHERE operation=X'{operation_hex}'");
        let mut observed = None;
        let envelope = holochain_mpc_core::Envelope::new(
            &self.binding.spec, self.members[2].clone(),
            Some(self.members[0].clone()), 1, sequence,
            format!("agent20-nonce-state-{sequence}").into_bytes())?;
        db.apply_received(
            &self.binding.proposal_action, &self.binding.spec,
            &self.members[0], &self.members[2], &envelope,
            |tx| {
                let mut query = tx.prepare(&statement)?;
                let mut rows = query.query([])?;
                if let Some(row) = rows.next()? {
                    observed = Some(row.get(0)?);
                }
                Ok(())
            },
        )?;
        Ok(observed)
    }
}

const F8_MESSAGE: &[u8] = b"agent20 disposable operator-approved intent";
const FAIL_AUTH_SQL: &str = "CREATE TRIGGER agent20_fail_auth
    BEFORE UPDATE OF state ON nonces WHEN NEW.state='published'
    BEGIN SELECT RAISE(ABORT, 'agent20 injected authorization write failure'); END";

struct FailedAuthorization {
    fixture: SigningStorageFaultFixture,
    signer: ControlledSigner,
    store: RuntimeStore,
    _dir: tempfile::TempDir,
    original: [u8;32],
    approved: ApprovedIntent,
}
fn failed_authorization() -> PResult<FailedAuthorization> {
    let mut fixture = SigningStorageFaultFixture::new()?;
    let signer = fixture.signer(0)?;
    let dir = tempfile::tempdir()?;
    let mut store = RuntimeStore::open(
        &dir.path().join("first.sqlite"), MasterKey::from_bytes([31;32]))?;
    let original = commitment("agent20-f8-operation", b"original");
    let approved = fixture.approved(original, F8_MESSAGE)?;
    store.start_deadline(&fixture.binding.proposal_action, &original, 10_000)?;
    fixture.sql(&mut store, 100, FAIL_AUTH_SQL)?;
    let mut case = FailedAuthorization {
        fixture, signer, store, _dir: dir, original, approved,
    };
    // If this returned commitments the security invariant would already fail.
    assert!(matches!(
        case.signer.prepare(&mut case.store, &case.approved, F8_MESSAGE, 100),
        Err(ProviderError::Wire(_))
    ), "SQLite UPDATE failure must never publish public commitments");
    assert_eq!(case.fixture.nonce_state(&mut case.store, 101, original)?,
               Some("reserved".into()));
    Ok(case)
}

#[test]
fn authorize_commitment_failure_does_not_publish() -> PResult<()> {
    let mut case = failed_authorization()?;
    let bogus = provider::SigningPackage::new(BTreeMap::new(), b"no approved package");
    assert!(matches!(
        case.signer.sign(&mut case.store, &case.approved, F8_MESSAGE, &bogus, 100),
        Err(ProviderError::SigningNonceUnavailable)
    ), "no authorization record means no signing authority");
    assert_eq!(case.fixture.nonce_state(&mut case.store, 102, case.original)?,
               Some("reserved".into()));
    Ok(())
}

#[test]
fn storage_failure_burns_original_operation() -> PResult<()> {
    let mut case = failed_authorization()?;
    case.fixture.sql(&mut case.store, 103, "DROP TRIGGER agent20_fail_auth")?;
    assert!(matches!(
        case.store.reserve_nonce(&case.fixture.binding.proposal_action, 0,
                                 &case.original, &case.fixture.members[0], 100),
        Err(RuntimeError::Conflict(_))
    ), "a reserved slot must remain unusable after SQLite recovers");
    assert!(case.signer.prepare(&mut case.store, &case.approved, F8_MESSAGE, 100).is_err());
    Ok(())
}

#[test]
fn failed_prepare_never_reuses_nonce() -> PResult<()> {
    let mut case = failed_authorization()?;
    case.fixture.sql(&mut case.store, 104, "DROP TRIGGER agent20_fail_auth")?;
    let next = commitment("agent20-f8-operation", b"new-disposable-intent");
    let approved = case.fixture.approved(next, F8_MESSAGE)?;
    case.store.start_deadline(&case.fixture.binding.proposal_action, &next, 10_000)?;
    // A leftover pending nonce would cause Signer::commit to return WrongState.
    let _fresh = case.signer.prepare(&mut case.store, &approved, F8_MESSAGE, 101)?;
    assert_eq!(case.fixture.nonce_state(&mut case.store, 105, case.original)?,
               Some("reserved".into()));
    assert_eq!(case.fixture.nonce_state(&mut case.store, 106, next)?,
               Some("published".into()));
    assert!(case.signer.prepare(&mut case.store, &case.approved, F8_MESSAGE, 102).is_err());
    Ok(())
}

#[test]
fn failed_prepare_restart_is_fail_closed() -> PResult<()> {
    let mut fixture = SigningStorageFaultFixture::new()?;
    let original = commitment("agent20-f8-operation", b"restart-original");
    let approved = fixture.approved(original, F8_MESSAGE)?;
    let key = fixture.keys.remove(&fixture.binding.id_of(&fixture.members[0])?)
        .ok_or("missing disposable share")?;
    // This clone is solely for simulating an independently started test signer.
    let restart_key = key.clone();
    let mut signer = ControlledSigner::new(
        fixture.binding.clone(), &fixture.members[0], key,
        &fixture.public, fixture.active.clone())?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("restart.sqlite");
    {
        let mut db = RuntimeStore::open(&path, MasterKey::from_bytes([31;32]))?;
        db.start_deadline(&fixture.binding.proposal_action, &original, 10_000)?;
        fixture.sql(&mut db, 120, FAIL_AUTH_SQL)?;
        assert!(signer.prepare(&mut db, &approved, F8_MESSAGE, 100).is_err());
    }
    drop(signer);
    let mut reopened = RuntimeStore::open(&path, MasterKey::from_bytes([31;32]))?;
    let mut restarted = ControlledSigner::new(
        fixture.binding.clone(), &fixture.members[0], restart_key,
        &fixture.public, fixture.active.clone())?;
    // Even a new process with the same long-term share cannot resurrect the
    // original operation or its destroyed ephemeral FROST nonce.
    assert!(matches!(
        restarted.prepare(&mut reopened, &approved, F8_MESSAGE, 100),
        Err(ProviderError::Wire(_))
    ));
    assert_eq!(fixture.nonce_state(&mut reopened, 121, original)?,
               Some("reserved".into()));
    // Recovery after a real SQLite reopen is a *new* operation with its own
    // unanimous activation and independently approved exact signing intent.
    fixture.sql(&mut reopened, 122, "DROP TRIGGER agent20_fail_auth")?;
    let next = commitment("agent20-f8-operation", b"fresh-after-restart");
    let next_approved = fixture.approved(next, F8_MESSAGE)?;
    reopened.start_deadline(&fixture.binding.proposal_action, &next, 10_000)?;
    let _new_commitment = restarted.prepare(&mut reopened, &next_approved, F8_MESSAGE, 102)?;
    assert_eq!(fixture.nonce_state(&mut reopened, 123, next)?,
               Some("published".into()));
    Ok(())
}

#[test]
fn subsequent_new_operation_has_defined_recovery() -> PResult<()> {
    let mut case = failed_authorization()?;
    case.fixture.sql(&mut case.store, 130, "DROP TRIGGER agent20_fail_auth")?;
    let next = commitment("agent20-f8-operation", b"independently-approved-recovery");
    let approved = case.fixture.approved(next, F8_MESSAGE)?;
    case.store.start_deadline(&case.fixture.binding.proposal_action, &next, 10_000)?;
    let first = case.signer.prepare(&mut case.store, &approved, F8_MESSAGE, 101)?;
    let mut peer = case.fixture.signer(1)?;
    let mut peer_db = RuntimeStore::open(
        &case._dir.path().join("peer.sqlite"), MasterKey::from_bytes([32;32]))?;
    peer_db.start_deadline(&case.fixture.binding.proposal_action, &next, 10_000)?;
    let second = peer.prepare(&mut peer_db, &approved, F8_MESSAGE, 101)?;
    let mut commitments = BTreeMap::new();
    commitments.insert(case.fixture.binding.id_of(&case.fixture.members[0])?, first);
    commitments.insert(case.fixture.binding.id_of(&case.fixture.members[1])?, second);
    let package = signing_package(&case.fixture.binding, next, F8_MESSAGE, commitments)?;
    let mut shares = BTreeMap::new();
    shares.insert(case.fixture.binding.id_of(&case.fixture.members[0])?,
        case.signer.sign(&mut case.store, &approved, F8_MESSAGE, &package, 102)?);
    shares.insert(case.fixture.binding.id_of(&case.fixture.members[1])?,
        peer.sign(&mut peer_db, &approved, F8_MESSAGE, &package, 102)?);
    let artifact = aggregate(&case.fixture.binding, next, F8_MESSAGE,
                             &package, &shares, &case.fixture.public)?;
    provider::verify_activated_artifact(
        &case.fixture.binding, F8_MESSAGE, &artifact, &case.fixture.active)?;
    assert!(case.signer.prepare(&mut case.store, &case.approved, F8_MESSAGE, 103).is_err());
    Ok(())
}

#[test]
fn commitment_failure_preserves_activation_requirements() -> PResult<()> {
    let case = failed_authorization()?;
    // No storage-recovery code may replace the all-N activation requirement.
    let descriptor = case.fixture.active.descriptor().clone();
    let mut incomplete = GroupActivation::new(descriptor.clone())?;
    for member in &case.fixture.members[..2] {
        incomplete.attest(member, descriptor.digest()?)?;
    }
    assert!(incomplete.finalize().is_err());
    let mut inconsistent = GroupActivation::new(descriptor.clone())?;
    assert!(inconsistent.attest(&case.fixture.members[0], [9;32]).is_err());
    Ok(())
}

#[test]
fn commitment_failure_preserves_approved_intent() -> PResult<()> {
    let mut case = failed_authorization()?;
    case.fixture.sql(&mut case.store, 140, "DROP TRIGGER agent20_fail_auth")?;
    let new_op = commitment("agent20-f8-operation", b"intent-protection");
    let good = case.fixture.approved(new_op, F8_MESSAGE)?;
    let mut partial = IntentApprovals::new(good.intent().clone());
    partial.approve(&case.fixture.members[0], good.digest())?;
    assert!(partial.finalize().is_err(), "both selected signers must approve");
    case.store.start_deadline(&case.fixture.binding.proposal_action, &new_op, 10_000)?;
    assert!(case.signer.prepare(&mut case.store, &good, b"modified message", 100).is_err());
    assert_eq!(case.fixture.nonce_state(&mut case.store, 141, new_op)?, None,
               "changed content must be rejected before reserving a nonce");
    let _valid = case.signer.prepare(&mut case.store, &good, F8_MESSAGE, 101)?;
    assert_eq!(case.fixture.nonce_state(&mut case.store, 142, new_op)?,
               Some("published".into()));
    Ok(())
}
