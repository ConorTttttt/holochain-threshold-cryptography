//! Bounded, explicitly seeded adversarial tests for the authenticated echo gate.
//! These test protocol-state safety, not mathematical security or conductor provenance.
use holochain_mpc_core::{commitment, Envelope, SessionSpec};
use holochain_mpc_security::{BroadcastMessage as Msg, Ceremony, EchoBroadcast};
use std::panic::{catch_unwind, AssertUnwindSafe};

const SEEDS: [u64; 4] = [
    0x0000_0000_0000_0001,
    0x3141_5926_5358_9793,
    0x9e37_79b9_7f4a_7c15,
    0xffff_ffff_ffff_fffe,
];

fn ceremony() -> (Ceremony, Vec<Vec<u8>>) {
    let members = vec![vec![1; 39], vec![2; 39], vec![3; 39]];
    let spec = SessionSpec {
        session_id: commitment("s17-property-session", b"no valuables"),
        application_id: "org.example.security-tests".into(),
        protocol_id: "frost-ed25519".into(),
        protocol_version: 1,
        context_hash: commitment("s17-property-context", b"adversarial"),
        participants: members.clone(),
        threshold: 2,
        max_round: 6,
    };
    (Ceremony { spec, proposal_action: vec![42; 39] }, members)
}

// No generated private keys, nonce material or external entropy. A failing
// seed/case pair reproduces exactly the same sequence of public payload bytes.
fn next(state: &mut u64) -> u64 {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    state.wrapping_mul(0x2545_f491_4f6c_dd1d)
}
fn blob(state: &mut u64) -> Vec<u8> {
    let size = 1 + (next(state) as usize % 96);
    (0..size).map(|_| next(state) as u8).collect()
}

// Drive three distinct state machines exclusively via authenticated envelopes,
// including every digest echo and (on the honest path) every attestation.
fn run_three(seed: u64, case: usize, equivocate: bool) {
    let (ceremony, members) = ceremony();
    let mut state = seed ^ ((case as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let mut nodes: Vec<_> = members.iter()
        .map(|member| EchoBroadcast::new(ceremony.clone(), member.clone()).unwrap())
        .collect();
    let announces: Vec<_> = (0..3)
        .map(|index| nodes[index].begin(blob(&mut state)).unwrap())
        .collect();
    // Agent B is Byzantine: A and C receive different public R1 packages.
    let mut replacement = match &announces[1] {
        Msg::Announce { package } => package.clone(),
        _ => unreachable!(),
    };
    replacement[0] ^= 0x80;

    let mut echoes = Vec::new();
    for origin in 0..3 {
        for target in 0..3 {
            if origin == target { continue; }
            let msg = if equivocate && origin == 1 && target == 2 {
                Msg::Announce { package: replacement.clone() }
            } else { announces[origin].clone() };
            let env = nodes[origin].outgoing(&members[target], origin as u64 + 1, &msg).unwrap();
            let response = nodes[target].receive_envelope(&members[target], &members[origin], &env)
                .unwrap_or_else(|err| panic!("seed={seed:#x} case={case} announce: {err}"));
            if let Some(echo) = response { echoes.push((target, origin, echo)); }
        }
    }
    // Reverse delivery order; all echoes still have transport-authenticated
    // provenance. A malicious origin cannot choose the echoer's identity.
    echoes.reverse();
    for (forwarder, origin, echo) in echoes {
        for target in 0..3 {
            if target == forwarder { continue; }
            let env = nodes[forwarder].outgoing(&members[target], 10 + origin as u64, &echo).unwrap();
            let outcome = nodes[target].receive_envelope(&members[target], &members[forwarder], &env);
            if !equivocate {
                assert!(outcome.is_ok(), "seed={seed:#x} case={case}: {outcome:?}");
            }
        }
    }
    if equivocate {
        // Neither honest A nor honest C can obtain a token from a disagreement,
        // even if the Byzantine participant lies about what it announced.
        assert!(!nodes[0].echoes_complete(), "seed={seed:#x} case={case}");
        assert!(!nodes[2].echoes_complete(), "seed={seed:#x} case={case}");
        assert!(nodes[0].finalize().is_err(), "seed={seed:#x} case={case}");
        assert!(nodes[2].finalize().is_err(), "seed={seed:#x} case={case}");
        return;
    }
    assert!(nodes.iter().all(EchoBroadcast::echoes_complete), "seed={seed:#x} case={case}");
    let attestations: Vec<_> = nodes.iter_mut().map(|node| node.attest().unwrap()).collect();
    for sender in 0..3 {
        for target in 0..3 {
            if sender == target { continue; }
            let env = nodes[sender].outgoing(&members[target], 100, &attestations[sender]).unwrap();
            nodes[target].receive_envelope(&members[target], &members[sender], &env).unwrap();
        }
    }
    let gates: Vec<_> = nodes.iter().map(|node| node.finalize().unwrap()).collect();
    for gate in &gates[1..] {
        assert_eq!(gates[0].hash(), gate.hash(), "seed={seed:#x} case={case}");
        assert_eq!(gates[0].packages(), gate.packages(), "seed={seed:#x} case={case}");
    }
}

#[test]
fn bounded_three_party_round_one_agreement_and_equivocation() {
    for seed in SEEDS {
        for case in 0..16 {
            run_three(seed, case, false);
            run_three(seed, case, true);
        }
    }
}

#[test]
fn malformed_broadcast_wire_never_panics_or_mints_a_transcript() {
    let (ceremony, members) = ceremony();
    for seed in SEEDS {
        let mut rng = seed;
        for case in 0..128 {
            let raw: Vec<u8> = if case % 3 == 0 {
                vec![b'['; 1 + (next(&mut rng) as usize % 1024)]
            } else if case % 3 == 1 {
                vec![0xff; 1 + (next(&mut rng) as usize % 1024)]
            } else {
                (0..(1 + next(&mut rng) as usize % 1024))
                    .map(|_| next(&mut rng) as u8).collect()
            };
            let env = Envelope::new(&ceremony.spec, members[0].clone(),
                Some(members[1].clone()), 1, 1, raw).unwrap();
            let mut receiver = EchoBroadcast::new(ceremony.clone(), members[1].clone()).unwrap();
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                receiver.receive_envelope(&members[1], &members[0], &env)
            }));
            assert!(outcome.is_ok(), "panic seed={seed:#x} case={case}");
            assert!(outcome.unwrap().is_err(), "accepted garbage seed={seed:#x} case={case}");
            assert!(receiver.finalize().is_err(), "minted token seed={seed:#x} case={case}");
        }
    }
}

#[test]
fn forged_provenance_and_cross_proposal_attestation_are_rejected() {
    let (ceremony, members) = ceremony();
    let mut a = EchoBroadcast::new(ceremony.clone(), members[0].clone()).unwrap();
    let announce = a.begin(b"public-only".to_vec()).unwrap();
    let env = a.outgoing(&members[1], 1, &announce).unwrap();
    let mut b = EchoBroadcast::new(ceremony.clone(), members[1].clone()).unwrap();
    assert!(b.receive_envelope(&members[1], &members[2], &env).is_err());
    assert!(b.finalize().is_err());
    let mut other = ceremony;
    other.proposal_action[0] ^= 1;
    let mut other_b = EchoBroadcast::new(other, members[1].clone()).unwrap();
    assert!(other_b.receive_envelope(&members[1], &members[0], &env).is_err());
    assert!(other_b.finalize().is_err());
}

#[test]
fn duplicate_announcements_are_idempotent_but_conflicts_fail_closed() {
    let (ceremony, members) = ceremony();
    let mut b = EchoBroadcast::new(ceremony.clone(), members[1].clone()).unwrap();
    let mut a = EchoBroadcast::new(ceremony, members[0].clone()).unwrap();
    let honest = b.begin(b"public round-one B".to_vec()).unwrap();
    let env = b.outgoing(&members[0], 11, &honest).unwrap();
    assert!(matches!(a.receive_envelope(&members[0], &members[1], &env), Ok(Some(Msg::EchoDigest { .. }))));
    assert!(matches!(a.receive_envelope(&members[0], &members[1], &env), Ok(None)));
    // Same slot, DIFFERENT valid envelope bytes: even if a transport layer
    // incorrectly forwarded both, the transcript gate must halt.
    let altered = b.outgoing(&members[0], 11,
        &Msg::Announce { package: b"conflicting B package".to_vec() }).unwrap();
    assert!(a.receive_envelope(&members[0], &members[1], &altered).is_err());
    assert!(a.is_aborted());
    assert!(a.finalize().is_err());
}

#[test]
fn conflicting_attestations_from_one_authenticated_origin_abort() {
    let (ceremony, members) = ceremony();
    let b = EchoBroadcast::new(ceremony.clone(), members[1].clone()).unwrap();
    let mut a = EchoBroadcast::new(ceremony, members[0].clone()).unwrap();
    a.begin(b"A public R1".to_vec()).unwrap();
    let first = b.outgoing(&members[0], 77,
        &Msg::Attest { transcript_hash: [7; 32] }).unwrap();
    a.receive_envelope(&members[0], &members[1], &first).unwrap();
    let conflicting = b.outgoing(&members[0], 78,
        &Msg::Attest { transcript_hash: [8; 32] }).unwrap();
    assert!(a.receive_envelope(&members[0], &members[1], &conflicting).is_err());
    assert!(a.is_aborted());
    assert!(a.finalize().is_err());
}
