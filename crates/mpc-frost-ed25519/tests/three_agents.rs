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
