//! Agent 19 / Sprint 1.7: Fable A11/F-9, INV-12 and INV-13.
 //! Native-only adversarial fixtures. No conductor, persistent cell, real identity,
 //! production key, or activation attestation is used here.
 //!
 //! The attacker knows its own ephemeral X25519 key and creates TWO separately
 //! sealed, authenticated envelopes containing a legitimate FROST DKG part2
 //! share. The plaintext share is generated from the very same unanimous
 //! Round-1 transcript the recipient controller verified.
use holochain_mpc_core::{commitment, Envelope, SessionSpec};
use holochain_mpc_dkg_worker::{Command, Controller, PeerKeyBinding, Reply};
use holochain_mpc_dkg_worker::conductor_bridge::KeyEvidence;
use holochain_mpc_dkg_worker::key_pinning::verify_explicit_key_roster;
use holochain_mpc_dkg_worker::transport_channel::DurableTransportChannel;
use holochain_mpc_frost_ed25519 as frost;
use holochain_mpc_runtime::{MasterKey, RuntimeStore};
use holochain_mpc_runtime::transport_key::TransportKeyBinding;
use holochain_mpc_security::{BroadcastMessage, Ceremony, EchoBroadcast, BoundBroadcastV2};
use holochain_mpc_security::sealed::{NativeChannelKey, SealedPacket};
use std::collections::BTreeMap;
use std::path::Path;

fn binding() -> frost::Binding {
    frost::Binding::new(vec![0x71;39], SessionSpec {
        session_id: commitment("agent19-round2-session", b"disposable-fixture"),
        application_id: "org.example.round2.security".into(),
        protocol_id: frost::PROTOCOL_ID.into(),
        protocol_version: frost::PROTOCOL_VERSION,
        context_hash: commitment("agent19-round2-context", b"disposable-fixture"),
        participants: (1u8..=3).map(|i| vec![i;39]).collect(),
        threshold: 2,
        max_round: 6,
    }).unwrap()
}

fn to_worker(worker: &mut Controller, env: Envelope) -> Vec<Envelope> {
    let sender = env.sender.clone();
    let reply = worker.handle(Command::Deliver {
        authenticated_sender: sender, envelope: env,
    }).unwrap();
    match reply {
        Reply::Delivered { outbound } => outbound,
        _ => panic!("worker did not acknowledge delivery"),
    }
}

// Route complete, signed-by-transport-test-harness broadcast envelopes.
// Native EchoBroadcast also verifies both external parties' entire transcript.
fn route(
    worker: &mut Controller,
    b: &mut EchoBroadcast,
    c: &mut EchoBroadcast,
    seq_b: &mut u64,
    seq_c: &mut u64,
    members: &[Vec<u8>],
    env: Envelope,
) -> Vec<Envelope> {
    let recipient = env.recipient.as_ref().expect("directed broadcast");
    if recipient == &members[0] {
        return to_worker(worker, env);
    }
    let (state, sequence) = if recipient == &members[1] {
        (b, seq_b)
    } else {
        assert_eq!(recipient, &members[2]);
        (c, seq_c)
    };
    let local = recipient.clone();
    let echo = state.receive_envelope(&local, &env.sender, &env).unwrap();
    let Some(message) = echo else { return Vec::new(); };
    let this_seq = *sequence;
    *sequence += 1;
    members.iter().filter(|member| *member != &local)
        .map(|member| state.outgoing(member, this_seq, &message).unwrap())
        .collect()
}

struct Fixture {
    binding: frost::Binding,
    worker: Controller,
    sender_key: NativeChannelKey,
    other_key: NativeChannelKey,
    recipient_public: [u8;32],
    share_b: frost::RoundTwo,
    share_c: frost::RoundTwo,
}

impl Fixture {
    fn new() -> Self {
        let binding = binding();
        let members = binding.spec.participants.clone();
        let a = &members[0];
        let b = &members[1];
        let c = &members[2];
        let ceremony = Ceremony {
            spec: binding.spec.clone(),
            proposal_action: binding.proposal_action.clone(),
        };
        let mut worker = Controller::default();
        let Reply::Initialized { local_public_key, outbound: a_announce } =
            worker.handle(Command::Init {
                binding: binding.clone(), local: a.clone(),
            }).unwrap()
        else { panic!("unexpected Init result") };
        assert_eq!(a_announce.len(), 2);

        let a_wire: BoundBroadcastV2 = serde_json::from_slice(&a_announce[0].payload).unwrap();
        let BroadcastMessage::Announce { package: a_bytes } = a_wire.message
        else { panic!("controller did not announce DKG Round-1 package") };
        let package_a: frost::RoundOne = serde_json::from_slice(&a_bytes).unwrap();

        let (mut party_b, package_b) = frost::DkgParty::begin(binding.clone(), b).unwrap();
        let (mut party_c, package_c) = frost::DkgParty::begin(binding.clone(), c).unwrap();
        let mut echo_b = EchoBroadcast::new(ceremony.clone(), b.clone()).unwrap();
        let mut echo_c = EchoBroadcast::new(ceremony, c.clone()).unwrap();
        let msg_b = echo_b.begin(serde_json::to_vec(&package_b).unwrap()).unwrap();
        let msg_c = echo_c.begin(serde_json::to_vec(&package_c).unwrap()).unwrap();

        // All 3 actual Round-1 packages, 12 authenticated digest echoes and
        // 6 unanimity attestations are delivered, never fabricated as a gate.
        let announcements = vec![
            a_announce[0].clone(), a_announce[1].clone(),
            echo_b.outgoing(a,1,&msg_b).unwrap(),
            echo_b.outgoing(c,1,&msg_b).unwrap(),
            echo_c.outgoing(a,1,&msg_c).unwrap(),
            echo_c.outgoing(b,1,&msg_c).unwrap(),
        ];
        let mut seq_b = 2;
        let mut seq_c = 2;
        let mut echoes = Vec::new();
        for message in announcements {
            echoes.extend(route(&mut worker,&mut echo_b,&mut echo_c,
                &mut seq_b,&mut seq_c,&members,message));
        }
        assert_eq!(echoes.len(), 12, "every announcement must be echoed to both peers");
        for message in echoes {
            assert!(route(&mut worker,&mut echo_b,&mut echo_c,
                &mut seq_b,&mut seq_c,&members,message).is_empty());
        }

        let Reply::Attesting { outbound: a_attest } = worker.handle(Command::Attest).unwrap()
        else { panic!("recipient did not attest") };
        let b_attest = echo_b.attest().unwrap();
        let c_attest = echo_c.attest().unwrap();
        let mut attestations = a_attest;
        for target in [a,c] { attestations.push(echo_b.outgoing(target,1,&b_attest).unwrap()); }
        for target in [a,b] { attestations.push(echo_c.outgoing(target,1,&c_attest).unwrap()); }
        assert_eq!(attestations.len(), 6);
        for message in attestations {
            assert!(route(&mut worker,&mut echo_b,&mut echo_c,
                &mut seq_b,&mut seq_c,&members,message).is_empty());
        }
        let gate_b = echo_b.finalize().unwrap();
        let gate_c = echo_c.finalize().unwrap();
        assert_eq!(gate_b.hash(), gate_c.hash());

        let packages = BTreeMap::from([
            (binding.id_of(a).unwrap(),package_a),
            (binding.id_of(b).unwrap(),package_b),
            (binding.id_of(c).unwrap(),package_c),
        ]);
        let outgoing_b = party_b.part2(&packages,&gate_b).unwrap();
        let outgoing_c = party_c.part2(&packages,&gate_c).unwrap();
        let share_b = outgoing_b[&binding.id_of(a).unwrap()].clone();
        let share_c = outgoing_c[&binding.id_of(a).unwrap()].clone();

        let sender_key = NativeChannelKey::generate();
        let other_key = NativeChannelKey::generate();
        let pins = vec![
            PeerKeyBinding {member:a.clone(),public_key:local_public_key,action:vec![11;39]},
            PeerKeyBinding {member:b.clone(),public_key:sender_key.public_key(),action:vec![12;39]},
            PeerKeyBinding {member:c.clone(),public_key:other_key.public_key(),action:vec![13;39]},
        ];
        let Reply::RoundTwo { transcript_hash, outbound } =
            worker.handle(Command::BeginRoundTwo { pinned_keys:pins }).unwrap()
        else { panic!("worker refused verified Round-2 gate") };
        assert_eq!(transcript_hash,gate_b.hash());
        assert_eq!(outbound.len(),2);
        Self { binding,worker,sender_key,other_key,recipient_public:local_public_key,
            share_b,share_c }
    }

    fn seal(&self, sender_index: usize, recipient_index: usize, sequence: u64) -> Envelope {
        let members = &self.binding.spec.participants;
        let (key, share) = if sender_index == 1 {
            (&self.sender_key, &self.share_b)
        } else {
            assert_eq!(sender_index,2);
            (&self.other_key, &self.share_c)
        };
        let target_key = if recipient_index == 0 {
            self.recipient_public
        } else {
            assert_eq!(recipient_index,2);
            self.other_key.public_key()
        };
        let frame = frost::Frame {
            proposal_action: self.binding.proposal_action.clone(),
            operation_id: self.binding.spec.session_id,
            message: frost::Message::DkgRound2(share.clone()),
        };
        let sealed = frost::seal_dkg_round_two(
            &self.binding,&frame,&members[sender_index],&members[recipient_index],
            sequence,key,target_key).unwrap();
        let packet: SealedPacket = serde_json::from_slice(&sealed.payload).unwrap();
        assert!(packet.structurally_valid());
        sealed
    }

    fn deliver(&mut self, env: Envelope) -> Result<Reply,String> {
        self.worker.handle(Command::Deliver {
            authenticated_sender: env.sender.clone(), envelope:env,
        })
    }

    fn assert_terminal(&mut self) {
        assert!(self.worker.handle(Command::Finalize).is_err());
        assert!(self.worker.handle(Command::Attest).is_err());
        assert!(self.worker.handle(Command::Init {
            binding:self.binding.clone(),local:self.binding.spec.participants[0].clone()
        }).is_err(), "poisoned DKG cannot restart with old ephemeral secrets");
    }
}

#[test]
fn valid_unique_round_two_packages_complete_native_dkg() {
    let mut f = Fixture::new();
    let b = f.seal(1,0,1);
    let c = f.seal(2,0,1);
    assert!(matches!(f.deliver(b),Ok(Reply::Delivered { .. })));
    assert!(matches!(f.deliver(c),Ok(Reply::Delivered { .. })));
    let result = f.worker.handle(Command::Finalize).unwrap();
    assert!(matches!(result,Reply::Completed { .. }),
        "test fixture must be able to perform actual FROST part3");
}

#[test]
fn duplicate_round_two_different_sequence_aborts() {
    let mut f = Fixture::new();
    let first = f.seal(1,0,1);
    let second = f.seal(1,0,2);
    assert_ne!(first.payload,second.payload,"fresh ciphertext is independently sealed");
    assert!(matches!(f.deliver(first),Ok(Reply::Delivered { .. })));
    let error = f.deliver(second).unwrap_err();
    assert!(error.contains("duplicate share"),"error must reach uniqueness check: {error}");
    f.assert_terminal();
}

#[test]
fn duplicate_round_two_reverse_order_aborts() {
    let mut f = Fixture::new();
    let first = f.seal(1,0,1);
    let second = f.seal(1,0,2);
    assert!(matches!(f.deliver(second),Ok(Reply::Delivered { .. })));
    let error = f.deliver(first).unwrap_err();
    assert!(error.contains("duplicate share"),"{error}");
    f.assert_terminal();
}

#[test]
fn duplicate_round_two_across_deliveries_aborts() {
    // Two separate controller calls model successive inbox observations.
    // This is NOT an actual RelayEngine::poll_once or conductor execution.
    let mut f = Fixture::new();
    let first = f.seal(1,0,1);
    assert!(matches!(f.deliver(first),Ok(Reply::Delivered { .. })));
    let second = f.seal(1,0,37);
    assert!(f.deliver(second).unwrap_err().contains("duplicate share"));
    f.assert_terminal();
}

#[test]
fn round_two_wrong_sender_rejected() {
    let mut f = Fixture::new();
    let b = f.seal(1,0,1);
    let error = f.worker.handle(Command::Deliver {
        authenticated_sender: f.binding.spec.participants[2].clone(), envelope:b,
    }).unwrap_err();
    assert!(error.contains("sender not authenticated"),"{error}");
    f.assert_terminal();
}

#[test]
fn round_two_wrong_recipient_rejected() {
    let mut f = Fixture::new();
    // Genuine sealed packet addressed and encrypted to C, delivered to A.
    let b_to_c = f.seal(1,2,1);
    assert!(f.deliver(b_to_c).is_err());
    f.assert_terminal();
}

#[test]
fn round_two_cross_proposal_rejected() {
    let mut f = Fixture::new();
    let mut other_binding = f.binding.clone();
    other_binding.proposal_action[0] ^= 1;
    let frame = frost::Frame {
        proposal_action:other_binding.proposal_action.clone(),
        operation_id:other_binding.spec.session_id,
        message:frost::Message::DkgRound2(f.share_b.clone()),
    };
    let packet = frost::seal_dkg_round_two(&other_binding,&frame,
        &f.binding.spec.participants[1],&f.binding.spec.participants[0],
        1,&f.sender_key,f.recipient_public).unwrap();
    assert!(f.deliver(packet).is_err(),"cross-proposal ciphertext must be rejected");
    f.assert_terminal();
}

#[test]
fn round_two_duplicate_cannot_activate_group() {
    let mut f = Fixture::new();
    // Even if the other honest sender's valid share is already available,
    // a second authenticated B package is terminal before FROST part3.
    let first = f.seal(1,0,1);
    let honest = f.seal(2,0,1);
    assert!(f.deliver(first).is_ok());
    assert!(f.deliver(honest).is_ok());
    // The attacker schedules the duplicate BEFORE any Finalize command.
    let conflicting = f.seal(1,0,2);
    assert!(f.deliver(conflicting).unwrap_err().contains("duplicate share"));
    f.assert_terminal();
    // No Completed descriptor can be exported after poison, hence no native
    // share can be used as evidence for unanimous activation.
}

fn approved_key_fixture() -> (Ceremony,TransportKeyBinding,DurableTransportChannel,Vec<KeyEvidence>) {
    let binding = binding();
    let local = TransportKeyBinding {
        dna:[0x45;39],agent:[1;39],proposal:[0x71;39],
        session:binding.spec.session_id,
    };
    let mut store = RuntimeStore::open(Path::new(":memory:"),
        MasterKey::from_bytes([0x29;32])).unwrap();
    let channel = DurableTransportChannel::provision_new(&mut store,&local).unwrap();
    let approved = vec![
        KeyEvidence {author:vec![1;39],action:vec![11;39],public_key:channel.public_key()},
        KeyEvidence {author:vec![2;39],action:vec![12;39],public_key:NativeChannelKey::generate().public_key()},
        KeyEvidence {author:vec![3;39],action:vec![13;39],public_key:NativeChannelKey::generate().public_key()},
    ];
    (Ceremony {spec:binding.spec,proposal_action:binding.proposal_action},local,channel,approved)
}

#[test]
fn forked_encryption_key_registration_rejected() {
    let (ceremony,local,channel,approved) = approved_key_fixture();
    let mut observed = approved.clone();
    let mut fork = observed[1].clone();
    fork.action = vec![22;39];
    fork.public_key = NativeChannelKey::generate().public_key();
    observed.push(fork);
    assert!(verify_explicit_key_roster(&ceremony,&local,&channel,&approved,&observed).is_err());
    observed = approved.clone();
    observed.push(approved[1].clone());
    assert!(verify_explicit_key_roster(&ceremony,&local,&channel,&approved,&observed).is_err());
}

#[test]
fn unapproved_key_rotation_rejected() {
    let (ceremony,local,channel,approved) = approved_key_fixture();
    let mut observed = approved.clone();
    observed[1].action = vec![42;39];
    observed[1].public_key = NativeChannelKey::generate().public_key();
    assert!(verify_explicit_key_roster(&ceremony,&local,&channel,&approved,&observed).is_err());
    // Even reusing an approved public key cannot legitimate a new action.
    observed[1].public_key = approved[1].public_key;
    assert!(verify_explicit_key_roster(&ceremony,&local,&channel,&approved,&observed).is_err());
}

#[test]
fn local_approved_registration_must_match_secret() {
    let (ceremony,local,channel,mut approved) = approved_key_fixture();
    approved[0].public_key = NativeChannelKey::generate().public_key();
    assert!(verify_explicit_key_roster(&ceremony,&local,&channel,&approved,&approved).is_err());
}
