//! Process-boundary crash checks. This is test-only bootstrap/key provisioning.
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command as ProcessCommand, Stdio};
use holochain_mpc_core::{commitment, SessionSpec};
use holochain_mpc_dkg_worker::{Command, Reply};
use holochain_mpc_dkg_worker::ipc::{AuthChannel, AuthFrame, ChannelContext, Role, TestBootstrap, TestPersistence};
use holochain_mpc_frost_ed25519 as frost;
use holochain_mpc_runtime::{MasterKey, RuntimeStore};
use holochain_mpc_runtime::dkg::DkgState;

fn setup() -> (frost::Binding, ChannelContext) {
    let local = vec![1;39];
    let spec = SessionSpec {
        session_id: commitment("v037-dkg-crash", b"worker process"),
        application_id: "org.example.dkg-restart".into(),
        protocol_id: frost::PROTOCOL_ID.into(), protocol_version: frost::PROTOCOL_VERSION,
        context_hash: commitment("v037-context", b"test"),
        participants: vec![local.clone(),vec![2;39],vec![3;39]],
        threshold: 2, max_round: 6,
    };
    let proposal = vec![9;39];
    let binding = frost::Binding::new(proposal.clone(), spec.clone()).unwrap();
    let context = ChannelContext { worker_agent: local, proposal_action: proposal,
        session_id: spec.session_id, channel_id: [6;32] };
    (binding, context)
}
fn spawn(context: ChannelContext, db: &std::path::Path) -> Child {
    let mut child = ProcessCommand::new(env!("CARGO_BIN_EXE_mpc-dkg-worker"))
        .arg("--test-authenticated-stdio")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().unwrap();
    let stdin = child.stdin.as_mut().unwrap();
    serde_json::to_writer(&mut *stdin, &TestBootstrap {
        context, secret: [12;32],
        persistence: Some(TestPersistence { database_path: db.to_path_buf(), master_key: [13;32] }),
    }).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    child
}

#[test]
fn abrupt_process_kill_leaves_encrypted_marker_and_denies_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secret-journal.sqlite");
    let (binding, context) = setup();
    let mut host = AuthChannel::new([12;32], context.clone(), Role::Host).unwrap();
    let mut child = spawn(context.clone(), &db);
    {
        let stdin = child.stdin.as_mut().unwrap();
        let frame = host.seal(Command::Init {
            binding, local: context.worker_agent.clone(),
        }).unwrap();
        serde_json::to_writer(&mut *stdin, &frame).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }
    let mut reply_line = String::new();
    assert_ne!(BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut reply_line).unwrap(), 0);
    let reply: AuthFrame<Reply> = serde_json::from_str(&reply_line).unwrap();
    assert!(matches!(host.open(reply).unwrap(), Reply::Initialized { .. }));
    child.kill().unwrap();
    child.wait().unwrap();
    let store = RuntimeStore::open(&db, MasterKey::from_bytes([13;32])).unwrap();
    let record = store.dkg_checkpoint(&context.proposal_action, &context.worker_agent, &context.session_id)
        .unwrap().unwrap();
    assert_eq!(record.state, DkgState::Running);
    assert_eq!(record.revision, 1);
    drop(store);
    let resumed = spawn(context, &db).wait_with_output().unwrap();
    assert!(!resumed.status.success(), "crashed ceremony cannot resume");
    assert!(resumed.stdout.is_empty(), "no replayed public announcement on restart");
}

#[test]
fn unauthenticated_init_creates_durable_abort_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secret-journal.sqlite");
    let (binding, context) = setup();
    let mut impostor = AuthChannel::new([99;32], context.clone(), Role::Host).unwrap();
    let mut child = spawn(context.clone(), &db);
    let frame = impostor.seal(Command::Init { binding, local: context.worker_agent.clone() }).unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *stdin, &frame).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }
    assert!(!child.wait_with_output().unwrap().status.success());
    let store = RuntimeStore::open(&db, MasterKey::from_bytes([13;32])).unwrap();
    assert_eq!(store.dkg_checkpoint(&context.proposal_action, &context.worker_agent, &context.session_id)
        .unwrap().unwrap().state, DkgState::Aborted);
}
