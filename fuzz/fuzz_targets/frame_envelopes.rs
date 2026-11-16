#![no_main]
use libfuzzer_sys::fuzz_target;
use holochain_mpc_core::{commitment, Envelope, SealedPacket, SessionSpec, MAX_PAYLOAD_BYTES};
use holochain_mpc_frost_ed25519::{Binding, Frame};
use holochain_mpc_security::{Ceremony, EchoBroadcast};

fuzz_target!(|data: &[u8]| {
    // Cap the *raw* untrusted input before constructing any envelope. Keep
    // memory bounded independently of serde JSON expansion.
    if data.len() > MAX_PAYLOAD_BYTES { return; }
    let participants = vec![vec![1; 39], vec![2; 39], vec![3; 39]];
    let spec = SessionSpec {
        session_id: commitment("fuzz-s17-session", b"static"),
        application_id: "org.example.fuzz".into(),
        protocol_id: "frost-ed25519".into(),
        protocol_version: 1,
        context_hash: commitment("fuzz-s17-context", b"static"),
        participants: participants.clone(),
        threshold: 2,
        max_round: 6,
    };
    let binding = Binding::new(vec![7; 39], spec).expect("fixture");
    let sender = &participants[0];
    let recipient = &participants[1];

    // The fuzz runner treats panics as failures. Errors are expected and
    // neither a valid transcript nor a signature is accepted from bytes alone.
    if let Ok(env) = Envelope::new(&binding.spec, sender.clone(),
        Some(recipient.clone()), 1, 1, data.to_vec()) {
        let _ = Frame::decode(&binding, &env, recipient, sender);
        let ceremony = Ceremony {
            spec: binding.spec.clone(),
            proposal_action: binding.proposal_action.clone(),
        };
        if let Ok(mut broadcast) = EchoBroadcast::new(ceremony, recipient.clone()) {
            let _ = broadcast.receive_envelope(recipient, sender, &env);
            assert!(broadcast.finalize().is_err());
        }
    }
    let _: Result<SealedPacket, _> = serde_json::from_slice(data);
});
