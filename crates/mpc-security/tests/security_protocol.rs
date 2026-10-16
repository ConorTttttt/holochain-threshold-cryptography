use holochain_mpc_core::{commitment, SessionSpec};
use holochain_mpc_security::{BroadcastMessage as Msg, Ceremony, EchoBroadcast, SecurityError};
use holochain_mpc_security::sealed::{ChannelHeader, ChannelReplay, NativeChannelKey};

fn setup() -> (Ceremony, Vec<Vec<u8>>) {
    let members = vec![vec![1;39], vec![2;39], vec![3;39]];
    let spec = SessionSpec {
        session_id: commitment("session", b"security-protocol-demo"),
        application_id: "org.example.any-application".into(),
        protocol_id: "frost-ed25519".into(), protocol_version: 1,
        context_hash: commitment("purpose", b"application-defined intent"),
        participants: members.clone(), threshold: 2, max_round: 6,
    };
    (Ceremony { spec, proposal_action: vec![44;39] }, members)
}

fn all_announcements(ceremony: &Ceremony, members: &[Vec<u8>]) -> Vec<EchoBroadcast> {
    let mut states: Vec<_> = members.iter().map(|m| EchoBroadcast::new(ceremony.clone(), m.clone()).unwrap()).collect();
    let announcements: Vec<_> = states.iter_mut().enumerate()
        .map(|(i,s)| s.begin(format!("authentic R1 package {i}").into_bytes()).unwrap()).collect();
    let mut echoes = Vec::new();
    for (origin, announce) in announcements.into_iter().enumerate() {
        for receiver in 0..members.len() {
            if receiver == origin { continue; }
            let response = states[receiver].receive(&members[origin], announce.clone()).unwrap().unwrap();
            echoes.push((receiver, response));
        }
    }
    // Arbitrary order is safe: every echo is authenticated by the *forwarder*.
    echoes.reverse();
    for (forwarder, echo) in echoes {
        for receiver in 0..members.len() {
            if receiver != forwarder {
                states[receiver].receive(&members[forwarder], echo.clone()).unwrap();
            }
        }
    }
    states
}

#[test]
fn unanimous_echo_and_attestation_unlocks_transcript() {
    let (ceremony, members) = setup();
    let mut states = all_announcements(&ceremony, &members);
    assert!(states.iter().all(EchoBroadcast::echoes_complete));
    assert!(states[0].finalize().is_err());
    let attestations: Vec<_> = states.iter_mut().map(|s| s.attest().unwrap()).collect();
    for (sender, attest) in attestations.into_iter().enumerate() {
        for receiver in 0..members.len() {
            if sender != receiver { states[receiver].receive(&members[sender], attest.clone()).unwrap(); }
        }
    }
    let completed: Vec<_> = states.iter().map(|s| s.finalize().unwrap()).collect();
    assert!(completed.windows(2).all(|p| p[0].hash() == p[1].hash()));
    assert_eq!(completed[0].packages().len(), 3);
}

#[test]
fn origin_equivocation_aborts_and_blocks_round2() {
    let (ceremony, members) = setup();
    let mut alice = EchoBroadcast::new(ceremony, members[0].clone()).unwrap();
    alice.begin(b"alice-value".to_vec()).unwrap();
    let first = Msg::Announce { package: b"bob-original".to_vec() };
    alice.receive(&members[1], first).unwrap();
    let forged_variant = Msg::Echo { origin: members[1].clone(), package: b"bob-equivocated".to_vec() };
    assert_eq!(alice.receive(&members[2], forged_variant), Err(SecurityError::Equivocation));
    assert!(alice.is_aborted());
    assert!(matches!(alice.attest(), Err(SecurityError::Aborted)));
}

#[test]
fn withholding_or_missing_echo_fails_closed() {
    let (ceremony, members) = setup();
    let mut alice = EchoBroadcast::new(ceremony, members[0].clone()).unwrap();
    alice.begin(b"a".to_vec()).unwrap();
    alice.receive(&members[1], Msg::Announce { package: b"b".to_vec() }).unwrap();
    alice.receive(&members[2], Msg::Announce { package: b"c".to_vec() }).unwrap();
    assert!(!alice.echoes_complete());
    assert!(matches!(alice.attest(), Err(SecurityError::NotReady)));
}

#[test]
fn inconsistent_attestation_aborts_without_token() {
    let (ceremony, members) = setup();
    let mut states = all_announcements(&ceremony, &members);
    states[0].receive(&members[1], Msg::Attest { transcript_hash: [7;32] }).unwrap();
    assert_eq!(states[0].attest(), Err(SecurityError::AttestationMismatch));
    assert!(states[0].is_aborted());
    assert!(states[0].finalize().is_err());
}

#[test]
fn only_member_can_announce_and_echo() {
    let (ceremony, members) = setup();
    let mut a = EchoBroadcast::new(ceremony, members[0].clone()).unwrap();
    assert_eq!(a.receive(&[99;39], Msg::Announce { package: vec![1] }), Err(SecurityError::Unauthorized));
    assert_eq!(a.receive(&members[1], Msg::Echo { origin: vec![99;39], package: vec![1] }), Err(SecurityError::Unauthorized));
}

#[test]
fn restart_replays_only_authenticated_events_and_does_not_fabricate_gate() {
    let (ceremony, members) = setup();
    // A durable controller replays independently authenticated events. It MUST
    // NOT deserialize an untrusted EchoBroadcast snapshot into a proof token.
    let mut original = EchoBroadcast::new(ceremony.clone(), members[0].clone()).unwrap();
    let mut replay = EchoBroadcast::new(ceremony, members[0].clone()).unwrap();
    let own = b"own DKG R1".to_vec();
    original.begin(own.clone()).unwrap();
    replay.begin(own).unwrap();
    for (sender, payload) in [(1usize, b"member B".as_slice()),
                              (2usize, b"member C".as_slice())] {
        let message = Msg::Announce { package: payload.to_vec() };
        original.receive(&members[sender], message.clone()).unwrap();
        replay.receive(&members[sender], message).unwrap();
    }
    assert!(!original.echoes_complete());
    assert_eq!(replay.echoes_complete(), original.echoes_complete());
    assert!(matches!(replay.attest(), Err(SecurityError::NotReady)));
    assert!(matches!(replay.finalize(), Err(SecurityError::NotReady)));
}

#[test]
fn x25519_salsa_box_encrypt_decrypt_and_context_binding() {
    let (ceremony, members) = setup();
    let alice = NativeChannelKey::generate();
    let bob = NativeChannelKey::generate();
    let charlie = NativeChannelKey::generate();
    let hdr = ChannelHeader { sender: members[0].clone(), recipient: members[1].clone(), round: 3, sequence: 1 };
    let plaintext = b"PRIVATE FROST round-2 share (test bytes only)";
    let packet = alice.seal(&ceremony, hdr.clone(), bob.public_key(), plaintext).unwrap();
    assert!(packet.structurally_valid());
    assert!(!serde_json::to_vec(&packet).unwrap().windows(plaintext.len()).any(|w| w == plaintext));
    assert_eq!(bob.open(&ceremony, &hdr, alice.public_key(), &packet).unwrap(), plaintext);
    let mut tampered = packet.clone();
    tampered.ciphertext[0] ^= 1;
    assert!(bob.open(&ceremony, &hdr, alice.public_key(), &tampered).is_err());
    assert!(bob.open(&ceremony, &hdr, charlie.public_key(), &packet).is_err());
    assert!(charlie.open(&ceremony, &hdr, alice.public_key(), &packet).is_err());
    let mut swapped = hdr.clone();
    swapped.sequence += 1;
    assert!(bob.open(&ceremony, &swapped, alice.public_key(), &packet).is_err());
    let mut other = ceremony.clone();
    other.proposal_action[0] ^= 1;
    assert!(bob.open(&other, &hdr, alice.public_key(), &packet).is_err());
    let mut replay = ChannelReplay::default();
    replay.check_and_mark(&hdr).unwrap();
    assert!(replay.check_and_mark(&hdr).is_err());
}


#[test]
fn holochain_envelope_round_and_transport_identity_are_enforced() {
    let (ceremony, members) = setup();
    let mut alice = EchoBroadcast::new(ceremony.clone(), members[0].clone()).unwrap();
    let mut bob = EchoBroadcast::new(ceremony, members[1].clone()).unwrap();
    let announce = alice.begin(b"frost public commitment".to_vec()).unwrap();
    let envelope = alice.outgoing(&members[1], 1, &announce).unwrap();
    let response = bob.receive_envelope(&members[1], &members[0], &envelope).unwrap();
    assert!(matches!(response, Some(Msg::EchoDigest { .. })));
    assert_eq!(bob.receive_envelope(&members[1], &members[2], &envelope), Err(SecurityError::Unauthorized));
    let mut swapped = envelope.clone();
    swapped.round = 2;
    assert!(bob.receive_envelope(&members[1], &members[0], &swapped).is_err());
}

#[test]
fn compact_echo_is_ceremony_bound_and_much_smaller_than_full_package() {
    use holochain_mpc_security::dkg_package_digest;
    let (ceremony, members) = setup();
    let mut alice = EchoBroadcast::new(ceremony.clone(), members[0].clone()).unwrap();
    let mut bob = EchoBroadcast::new(ceremony.clone(), members[1].clone()).unwrap();
    let large = vec![27u8; 6 * 1024];
    let announcement = alice.begin(large.clone()).unwrap();
    let response = bob.receive(&members[0], announcement).unwrap().unwrap();
    if let Msg::EchoDigest { origin, package_digest } = &response {
        assert_eq!(origin, &members[0]);
        assert_eq!(*package_digest, dkg_package_digest(&ceremony, origin, &large).unwrap());
    } else { panic!("expected a compact echo"); }
    let compact = serde_json::to_vec(&response).unwrap();
    let full = serde_json::to_vec(&Msg::Echo { origin: members[0].clone(), package: large }).unwrap();
    assert!(compact.len() * 10 < full.len(), "compact echo should save significant bytes");
    let mut other = ceremony;
    other.proposal_action = vec![77;39];
    assert_ne!(dkg_package_digest(&other, &members[0], b"same").unwrap(),
               dkg_package_digest(bob.ceremony(), &members[0], b"same").unwrap());
}

#[test]
fn reject_cross_proposal_replay_even_when_sessions_match() {
    let (ceremony, members) = setup();
    let mut alice = EchoBroadcast::new(ceremony.clone(), members[0].clone()).unwrap();
    let mut other = ceremony;
    other.proposal_action = vec![66;39];
    let mut bob = EchoBroadcast::new(other, members[1].clone()).unwrap();
    let announce = alice.begin(b"origin public commitment".to_vec()).unwrap();
    let env = alice.outgoing(&members[1], 1, &announce).unwrap();
    assert!(matches!(bob.receive_envelope(&members[1], &members[0], &env),
                     Err(SecurityError::Invalid("DKG ceremony binding mismatch"))));
    let mut legacy = env.clone();
    legacy.payload = serde_json::to_vec(&announce).unwrap();
    legacy.payload_hash = commitment("envelope-payload", &legacy.payload);
    assert!(bob.receive_envelope(&members[1], &members[0], &legacy).is_err());
}

#[test]
fn out_of_order_hash_echo_conflicts_with_later_direct_package() {
    use holochain_mpc_security::dkg_package_digest;
    let (ceremony, members) = setup();
    let mut alice = EchoBroadcast::new(ceremony.clone(), members[0].clone()).unwrap();
    alice.begin(b"alice".to_vec()).unwrap();
    let digest = dkg_package_digest(&ceremony, &members[1], b"bob-sends-to-charlie").unwrap();
    alice.receive(&members[2], Msg::EchoDigest { origin: members[1].clone(), package_digest: digest }).unwrap();
    assert_eq!(alice.receive(&members[1], Msg::Announce { package: b"bob-sends-to-alice".to_vec() }),
               Err(SecurityError::Equivocation));
    assert!(alice.is_aborted());
}

#[test]
fn byzantine_reliable_broadcast_is_not_silently_emulated() {
    use holochain_mpc_security::BroadcastGuarantee;
    let (ceremony, members) = setup();
    assert!(matches!(EchoBroadcast::new_with_guarantee(ceremony, members[0].clone(),
        BroadcastGuarantee::AsynchronousByzantineReliable), Err(SecurityError::Invalid(_))));
}

#[test]
fn digest_echo_reduces_bytes_but_not_total_message_count() {
    use holochain_mpc_security::estimate_echo_traffic;
    let e = estimate_echo_traffic(3, 4096).unwrap();
    assert_eq!(e.echo_deliveries, 12);
    assert_eq!(e.full_package_payload_bytes, 12 * 4096);
    assert_eq!(e.digest_payload_bytes, 12 * 32);
    assert!(estimate_echo_traffic(0, 4096).is_none());
}

#[test]
fn authenticated_event_replay_requires_an_external_integrity_verifier() {
    use holochain_mpc_security::DkgReplayEvent;
    let (ceremony, members) = setup();
    let mut alice = EchoBroadcast::new(ceremony.clone(), members[0].clone()).unwrap();
    let _ = alice.begin(b"A package".to_vec()).unwrap();
    let announce = alice.outgoing(&members[1], 1, &Msg::Announce { package: b"A package".to_vec() }).unwrap();
    let event = DkgReplayEvent::Inbound { envelope: announce, authenticated_sender: members[0].clone() };
    let events = vec![event];
    assert!(matches!(EchoBroadcast::replay_authenticated_events(ceremony.clone(), members[1].clone(),
        &events, |_| Err(SecurityError::Unauthorized)), Err(SecurityError::Unauthorized)));
    // This closure models a journal whose receipt signatures were already
    // independently checked. A live service must NOT simply return Ok.
    let rebuilt = EchoBroadcast::replay_authenticated_events(ceremony, members[1].clone(),
        &events, |_| Ok(())).unwrap();
    assert!(!rebuilt.echoes_complete());
    assert!(rebuilt.finalize().is_err());
}
