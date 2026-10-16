//! A session/envelope demonstration. No MPC cryptography is performed.
use holochain_mpc_core::{Envelope, Inbox, SessionSpec};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = vec![1u8; 39];
    let bob = vec![2u8; 39];
    let session = SessionSpec {
        session_id: [42; 32],
        application_id: "org.example.shared".into(),
        protocol_id: "demo-opaque".into(),
        protocol_version: 1,
        context_hash: [23; 32],
        participants: vec![alice.clone(), bob.clone()],
        threshold: 2,
        max_round: 2,
    };
    session.validate()?;
    let envelope = Envelope::new(
        &session, alice.clone(), Some(bob.clone()), 1, 1,
        b"Example message -- not a secret or cryptographic share".to_vec(),
    )?;
    let mut bob_inbox = Inbox::new();
    // Transport MUST independently verify Alice's identity and supply it here.
    bob_inbox.accept(&session, &bob, &alice, &envelope)?;
    println!("accepted {} opaque protocol message", bob_inbox.len());
    Ok(())
}
