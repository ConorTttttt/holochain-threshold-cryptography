//! v0.3.6: reject legacy unauthenticated CLI access and forged MAC frames.
use std::io::Write;
use std::process::{Command as ProcessCommand, Stdio};
use holochain_mpc_core::{commitment, SessionSpec};
use holochain_mpc_frost_ed25519 as frost;
use holochain_mpc_dkg_worker::Command;
use holochain_mpc_dkg_worker::ipc::{AuthChannel, ChannelContext, Role, TestBootstrap};

#[test]
fn unauthenticated_cli_mode_is_unavailable() {
    let status = ProcessCommand::new(env!("CARGO_BIN_EXE_mpc-dkg-worker"))
        .arg("--unsafe-test-stdio").status().expect("launch test worker");
    assert!(!status.success());
}

#[test]
fn forged_authenticated_command_terminates_worker_without_reply() {
    let local = vec![1; 39];
    let proposal = vec![9; 39];
    let spec = SessionSpec {
        session_id: commitment("v036-test-ipc", b"forged-frame"),
        application_id: "org.example.ipc-adversary".into(),
        protocol_id: frost::PROTOCOL_ID.into(),
        protocol_version: frost::PROTOCOL_VERSION,
        context_hash: commitment("v036-ipc-context", b"test"),
        participants: vec![local.clone(), vec![2;39], vec![3;39]],
        threshold: 2, max_round: 6,
    };
    let binding = frost::Binding::new(proposal.clone(), spec.clone()).unwrap();
    let context = ChannelContext { worker_agent: local.clone(), proposal_action: proposal,
        session_id: spec.session_id, channel_id: [6;32] };
    let mut impostor = AuthChannel::new([2;32], context.clone(), Role::Host).unwrap();
    let frame = impostor.seal(Command::Init { binding, local }).unwrap();
    let mut child = ProcessCommand::new(env!("CARGO_BIN_EXE_mpc-dkg-worker"))
        .arg("--test-authenticated-stdio")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().expect("launch test worker");
    let mut stdin = child.stdin.take().expect("worker stdin");
    serde_json::to_writer(&mut stdin, &TestBootstrap { context, secret: [1;32], persistence: None }).unwrap();
    stdin.write_all(b"\n").unwrap();
    serde_json::to_writer(&mut stdin, &frame).unwrap();
    stdin.write_all(b"\n").unwrap();
    drop(stdin);
    let output = child.wait_with_output().expect("worker response");
    assert!(!output.status.success(), "a forged frame must not be accepted");
    assert!(output.stdout.is_empty(), "worker must not emit an unauthenticated reply");
}
