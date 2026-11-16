#![cfg(unix)]
//! Real OS process boundaries and protected local socket/files, NOT a conductor integration.
use holochain_mpc_core::{commitment, SessionSpec};
use holochain_mpc_dkg_worker::{Command, Reply};
use holochain_mpc_dkg_worker::ipc::{AuthChannel, AuthFrame, ChannelContext, Role};
use holochain_mpc_dkg_worker::node_service::{config_path, provision, socket_path, NodeConfig};
use holochain_mpc_frost_ed25519 as frost;
use holochain_mpc_runtime::{MasterKey, RuntimeStore};
use holochain_mpc_runtime::dkg::DkgState;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command as Process, Stdio};
use std::time::{Duration, Instant};

fn context(owner: u8, proposal: u8, channel: u8) -> ChannelContext {
    ChannelContext { worker_agent: vec![owner; 39], proposal_action: vec![proposal;39],
        session_id: commitment("node-test-session-v1", b"three node ceremony"),
        channel_id: [channel;32] }
}
fn binding(ctx: &ChannelContext) -> frost::Binding {
    let spec = SessionSpec {
        session_id: ctx.session_id, application_id: "org.example.mpc.node.test".into(),
        protocol_id: frost::PROTOCOL_ID.into(), protocol_version: frost::PROTOCOL_VERSION,
        context_hash: commitment("node-test-context-v1", b"node boot"),
        participants: vec![vec![1;39],vec![2;39],vec![3;39]], threshold: 2, max_round: 6,
    };
    frost::Binding::new(ctx.proposal_action.clone(), spec).unwrap()
}
fn key(dir: &std::path::Path, name: &str) -> [u8;32] {
    let content = fs::read(dir.join(name)).unwrap();
    content.try_into().unwrap()
}
fn child(dir: &std::path::Path) -> Child {
    Process::new(env!("CARGO_BIN_EXE_mpc-node"))
        .arg("serve").arg(dir)
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap()
}
fn connect(dir: &std::path::Path) -> UnixStream {
    let start = Instant::now();
    loop {
        match UnixStream::connect(socket_path(dir)) {
            Ok(sock) => { sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap(); return sock; },
            Err(_) if start.elapsed() < Duration::from_secs(5) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => panic!("node did not bind local socket: {e}"),
        }
    }
}
#[test]
fn two_independent_node_processes_accept_only_their_own_authenticated_controller() {
    let temp = tempfile::tempdir().unwrap();
    let alice_dir = temp.path().join("alice");
    let bob_dir = temp.path().join("bob");
    let alice = context(1, 9, 4);
    let bob = context(2, 9, 5);
    provision(&alice_dir, alice.clone()).unwrap();
    provision(&bob_dir, bob.clone()).unwrap();
    assert_ne!(key(&alice_dir, "ipc.key"), key(&bob_dir, "ipc.key"));
    assert_ne!(key(&alice_dir, "storage.key"), key(&bob_dir, "storage.key"));
    let config: NodeConfig = serde_json::from_slice(&fs::read(config_path(&alice_dir)).unwrap()).unwrap();
    assert_eq!(config.context, alice);

    let mut a_child = child(&alice_dir);
    let mut b_child = child(&bob_dir);
    let mut a_sock = connect(&alice_dir);
    let mut b_sock = connect(&bob_dir);

    let mut a_host = AuthChannel::new(key(&alice_dir, "ipc.key"), alice.clone(), Role::Host).unwrap();
    let frame = a_host.seal(Command::Init { binding: binding(&alice), local: alice.worker_agent.clone() }).unwrap();
    serde_json::to_writer(&mut a_sock, &frame).unwrap();
    a_sock.write_all(b"\n").unwrap();
    let mut line = String::new();
    assert!(BufReader::new(a_sock.try_clone().unwrap()).read_line(&mut line).unwrap() > 0);
    let reply: AuthFrame<Reply> = serde_json::from_str(&line).unwrap();
    assert!(matches!(a_host.open(reply).unwrap(), Reply::Initialized { .. }));

    // Bob has a different socket, pinned agent identity and authentication key.
    // A forged Init using Alice's key but Bob's context fails authentication.
    let mut impostor = AuthChannel::new(key(&alice_dir, "ipc.key"), bob.clone(), Role::Host).unwrap();
    let forged = impostor.seal(Command::Init { binding: binding(&bob), local: bob.worker_agent.clone() }).unwrap();
    serde_json::to_writer(&mut b_sock, &forged).unwrap();
    b_sock.write_all(b"\n").unwrap();
    drop(a_sock);
    drop(b_sock);
    assert!(a_child.wait().unwrap().success());
    assert!(!b_child.wait().unwrap().success());
    let a_store = RuntimeStore::open(&alice_dir.join("journal.sqlite"),
        MasterKey::from_bytes(key(&alice_dir,"storage.key"))).unwrap();
    assert_eq!(a_store.dkg_checkpoint(&alice.proposal_action,&alice.worker_agent,&alice.session_id)
        .unwrap().unwrap().state, DkgState::Aborted);
    let b_store = RuntimeStore::open(&bob_dir.join("journal.sqlite"),
        MasterKey::from_bytes(key(&bob_dir,"storage.key"))).unwrap();
    assert_eq!(b_store.dkg_checkpoint(&bob.proposal_action,&bob.worker_agent,&bob.session_id)
        .unwrap().unwrap().state, DkgState::Aborted);
    drop(a_store);
    drop(b_store);

    // Both journals are terminal for restarts of their pinned proposal.
    assert!(!child(&alice_dir).wait().unwrap().success());
    assert!(!child(&bob_dir).wait().unwrap().success());
}

#[test]
fn disconnect_before_init_does_not_poison_an_unstarted_ceremony() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("node");
    let ctx = context(1, 9, 4);
    provision(&dir, ctx.clone()).unwrap();
    let mut first = child(&dir);
    let sock = connect(&dir);
    drop(sock); // EOF without any protocol command or FROST randomness
    assert!(first.wait().unwrap().success());
    let journal = RuntimeStore::open(&dir.join("journal.sqlite"),
        MasterKey::from_bytes(key(&dir, "storage.key"))).unwrap();
    assert!(journal.dkg_checkpoint(&ctx.proposal_action, &ctx.worker_agent, &ctx.session_id)
        .unwrap().is_none());
    drop(journal);
    // There was no admission: a new native process may still accept Init.
    let mut second = child(&dir);
    drop(connect(&dir));
    assert!(second.wait().unwrap().success());
}

#[test]
fn truncated_ipc_frame_after_init_durably_aborts_and_denies_restart() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("node");
    let ctx = context(1, 9, 4);
    provision(&dir, ctx.clone()).unwrap();
    let mut process = child(&dir);
    let mut socket = connect(&dir);
    let mut host = AuthChannel::new(key(&dir, "ipc.key"), ctx.clone(), Role::Host).unwrap();
    let init = host.seal(Command::Init {
        binding: binding(&ctx), local: ctx.worker_agent.clone() }).unwrap();
    serde_json::to_writer(&mut socket, &init).unwrap();
    socket.write_all(b"\n").unwrap();
    let mut reply_line = String::new();
    assert_ne!(BufReader::new(socket.try_clone().unwrap()).read_line(&mut reply_line).unwrap(), 0);
    let reply: AuthFrame<Reply> = serde_json::from_str(&reply_line).unwrap();
    assert!(matches!(host.open(reply).unwrap(), Reply::Initialized { .. }));
    socket.write_all(b"{truncated").unwrap();
    drop(socket); // read_until reaches EOF with an unterminated frame
    assert!(!process.wait().unwrap().success());
    let journal = RuntimeStore::open(&dir.join("journal.sqlite"),
        MasterKey::from_bytes(key(&dir, "storage.key"))).unwrap();
    let checkpoint = journal.dkg_checkpoint(&ctx.proposal_action, &ctx.worker_agent,
        &ctx.session_id).unwrap().unwrap();
    assert_eq!(checkpoint.state, DkgState::Aborted);
    assert_eq!(checkpoint.revision, 2, "Init was acknowledged before terminal abort");
    drop(journal);
    assert!(!child(&dir).wait().unwrap().success());
}
