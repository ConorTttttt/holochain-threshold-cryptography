//! Release-hardening audit (27 October 2026): version, size and unknown-field
//! behaviour of the shared wire types. Offline, synthetic data only.
//!
//! Tests named `known_gap_*` pin TODAY's behaviour of a documented gap
//! (`docs/V040_RELEASE_HARDENING.md`); flip them when the gap is closed.
use holochain_mpc_core::{commitment, Envelope, PrimitiveError, SealedPacket, SessionSpec};
use holochain_mpc_security::{BoundBroadcastV2, BroadcastMessage as Msg, Ceremony, EchoBroadcast, SecurityError};

fn ceremony() -> (Ceremony, Vec<Vec<u8>>) {
    let members = vec![vec![1; 39], vec![2; 39], vec![3; 39]];
    let spec = SessionSpec {
        session_id: commitment("session", b"wire-validation"),
        application_id: "org.example.any-application".into(),
        protocol_id: "frost-ed25519".into(), protocol_version: 1,
        context_hash: commitment("purpose", b"wire-validation"),
        participants: members.clone(), threshold: 2, max_round: 6,
    };
    (Ceremony { spec, proposal_action: vec![44; 39] }, members)
}

fn reseal(env: &Envelope, payload: Vec<u8>) -> Envelope {
    let mut out = env.clone();
    out.payload_hash = commitment("envelope-payload", &payload);
    out.payload = payload;
    out
}

#[test]
fn envelope_wire_version_protocol_and_session_binding_are_enforced() {
    let (c, members) = ceremony();
    let env = Envelope::new(&c.spec, members[0].clone(), Some(members[1].clone()), 1, 1, b"x".to_vec()).unwrap();
    env.validate_against(&c.spec).unwrap();

    let mut bad = env.clone();
    bad.wire_version += 1;
    assert_eq!(bad.validate_against(&c.spec), Err(PrimitiveError::InvalidEnvelope("unsupported wire version")));
    let mut bad = env.clone();
    bad.protocol_version += 1;
    assert_eq!(bad.validate_against(&c.spec), Err(PrimitiveError::WrongProtocol));
    let mut bad = env.clone();
    bad.protocol_id = "other-protocol".into();
    assert_eq!(bad.validate_against(&c.spec), Err(PrimitiveError::WrongProtocol));
    let mut bad = env.clone();
    bad.session_id = [8; 32];
    assert_eq!(bad.validate_against(&c.spec), Err(PrimitiveError::WrongSession));
    // The payload limit is 64 KiB, checked on the byte length, not on JSON.
    let at_limit = reseal(&env, vec![0; 64 * 1024]);
    at_limit.validate_against(&c.spec).unwrap();
    let over = reseal(&env, vec![0; 64 * 1024 + 1]);
    assert!(over.validate_against(&c.spec).is_err());
}

#[test]
fn sealed_packet_version_key_and_size_bounds() {
    let ok = SealedPacket { version: 1, sender_key: [1; 32], recipient_key: [2; 32], nonce: [3; 24],
        ciphertext: vec![0; 16] };
    assert!(ok.structurally_valid());
    let mutate = |f: &dyn Fn(&mut SealedPacket)| { let mut p = ok.clone(); f(&mut p); p.structurally_valid() };
    assert!(!mutate(&|p| p.version = 0));
    assert!(!mutate(&|p| p.version = 2));
    assert!(!mutate(&|p| p.sender_key = [0; 32]));
    assert!(!mutate(&|p| p.recipient_key = [0; 32]));
    assert!(!mutate(&|p| p.ciphertext = vec![0; 15]));
    assert!(mutate(&|p| p.ciphertext = vec![0; 48 * 1024]));
    assert!(!mutate(&|p| p.ciphertext = vec![0; 48 * 1024 + 1]));
}

#[test]
fn broadcast_wire_version_binding_and_malformed_payloads_are_refused() {
    let (c, members) = ceremony();
    let mut alice = EchoBroadcast::new(c.clone(), members[0].clone()).unwrap();
    let mut bob = EchoBroadcast::new(c.clone(), members[1].clone()).unwrap();
    let announce = alice.begin(b"origin public commitment".to_vec()).unwrap();
    let env = alice.outgoing(&members[1], 1, &announce).unwrap();
    let bound: BoundBroadcastV2 = serde_json::from_slice(&env.payload).unwrap();
    assert_eq!(bound.version, 2);

    for version in [0_u16, 1, 3, u16::MAX] {
        let mut wrong = bound.clone();
        wrong.version = version;
        let bad = reseal(&env, serde_json::to_vec(&wrong).unwrap());
        assert!(matches!(bob.receive_envelope(&members[1], &members[0], &bad),
            Err(SecurityError::Invalid("DKG ceremony binding mismatch"))), "version {version}");
    }
    let mut wrong = bound.clone();
    wrong.ceremony_hash = [9; 32];
    let bad = reseal(&env, serde_json::to_vec(&wrong).unwrap());
    assert!(bob.receive_envelope(&members[1], &members[0], &bad).is_err());

    for garbage in [&b""[..], b"{", b"null", b"[]", b"{\"version\":2}", &[0xff; 64][..]] {
        let bad = reseal(&env, garbage.to_vec());
        assert!(matches!(bob.receive_envelope(&members[1], &members[0], &bad),
            Err(SecurityError::Invalid("missing or malformed DKG ceremony binding"))), "{garbage:?}");
    }
    // A round that does not match the message kind is refused.
    let mut wrong_round = env.clone();
    wrong_round.round = 2;
    assert!(bob.receive_envelope(&members[1], &members[0], &wrong_round).is_err());
    // The untouched message still works afterwards (no state was poisoned).
    bob.receive_envelope(&members[1], &members[0], &env).unwrap();
    let _ = Msg::Abort;
}

#[test]
fn announcement_size_is_bounded() {
    let (c, members) = ceremony();
    let mut alice = EchoBroadcast::new(c, members[0].clone()).unwrap();
    assert!(alice.begin(Vec::new()).is_err());
    assert!(alice.begin(vec![1; 8 * 1024 + 1]).is_err());
    alice.begin(vec![1; 8 * 1024]).unwrap();
}

// Documented gap: these types do not set `deny_unknown_fields`. For the signed
// and attested hashes this is harmless where the digest is taken over a
// re-serialisation, but the wire still accepts non-canonical JSON.
#[test]
fn known_gap_unknown_fields_are_ignored_by_wire_types() {
    let (c, members) = ceremony();
    let mut alice = EchoBroadcast::new(c.clone(), members[0].clone()).unwrap();
    let mut bob = EchoBroadcast::new(c.clone(), members[1].clone()).unwrap();
    let announce = alice.begin(b"origin public commitment".to_vec()).unwrap();
    let env = alice.outgoing(&members[1], 1, &announce).unwrap();

    let mut value: serde_json::Value = serde_json::from_slice(&env.payload).unwrap();
    value["smuggled"] = serde_json::json!("extra");
    let padded = reseal(&env, serde_json::to_vec(&value).unwrap());
    assert!(bob.receive_envelope(&members[1], &members[0], &padded).is_ok());

    let mut envelope_json = serde_json::to_value(&env).unwrap();
    envelope_json["smuggled"] = serde_json::json!(1);
    assert!(serde_json::from_value::<Envelope>(envelope_json).is_ok());
    let packet = SealedPacket { version: 1, sender_key: [1; 32], recipient_key: [2; 32], nonce: [3; 24],
        ciphertext: vec![0; 16] };
    let mut packet_json = serde_json::to_value(&packet).unwrap();
    packet_json["smuggled"] = serde_json::json!(1);
    assert!(serde_json::from_value::<SealedPacket>(packet_json).is_ok());
}
