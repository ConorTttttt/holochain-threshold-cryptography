//! No FROST Round-1/2 secret is persisted or resurrected. A durable admission
//! marker makes worker crash recovery fail closed for a reused proposal/agent.
use holochain_mpc_runtime::{MasterKey, RuntimeStore, RuntimeError};
use holochain_mpc_runtime::dkg::DkgState;
use rusqlite::Connection;

fn binding() -> (Vec<u8>, Vec<u8>, [u8;32]) {
    (vec![9;39], vec![1;39], [7;32])
}
fn open(path: &std::path::Path, key: [u8;32]) -> RuntimeStore {
    RuntimeStore::open(path, MasterKey::from_bytes(key)).unwrap()
}

#[test]
fn write_ahead_admission_and_restart_rejects_old_proposal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("worker.db");
    let (proposal, owner, session) = binding();
    let mut store = open(&path, [8;32]);
    assert!(store.dkg_checkpoint(&proposal, &owner, &session).unwrap().is_none());
    store.dkg_begin(&proposal, &owner, &session).unwrap();
    store.dkg_record_reply(&proposal, &owner, &session, [42;32], false).unwrap();
    drop(store);
    let mut restarted = open(&path, [8;32]);
    let checkpoint = restarted.dkg_checkpoint(&proposal, &owner, &session).unwrap().unwrap();
    assert_eq!(checkpoint.state, DkgState::Running);
    assert_eq!(checkpoint.revision, 1);
    assert_eq!(checkpoint.reply_digest, [42;32]);
    assert!(matches!(restarted.dkg_begin(&proposal, &owner, &session), Err(RuntimeError::Conflict(_))));
    // New ceremony / new on-chain action is accepted.
    let next_proposal = vec![10;39];
    restarted.dkg_begin(&next_proposal, &owner, &session).unwrap();
}

#[test]
fn abort_and_completion_are_permanent_tombstones() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("worker.db");
    let (proposal, owner, session) = binding();
    let mut store = open(&path, [8;32]);
    store.dkg_begin(&proposal, &owner, &session).unwrap();
    store.dkg_abort(&proposal, &owner, &session).unwrap();
    store.dkg_abort(&proposal, &owner, &session).unwrap();
    assert_eq!(store.dkg_checkpoint(&proposal, &owner, &session).unwrap().unwrap().state, DkgState::Aborted);
    assert!(store.dkg_record_reply(&proposal, &owner, &session, [1;32], false).is_err());
    assert!(store.dkg_begin(&proposal, &owner, &session).is_err());

    let next = vec![11;39];
    store.dkg_begin(&next, &owner, &session).unwrap();
    store.dkg_record_reply(&next, &owner, &session, [44;32], true).unwrap();
    assert_eq!(store.dkg_checkpoint(&next, &owner, &session).unwrap().unwrap().state, DkgState::Completed);
    assert!(store.dkg_record_reply(&next, &owner, &session, [45;32], false).is_err());
    drop(store);
    let mut restarted = open(&path, [8;32]);
    assert!(restarted.dkg_begin(&next, &owner, &session).is_err());
    assert!(restarted.dkg_begin(&proposal, &owner, &session).is_err());
}

#[test]
fn tampering_wrong_master_key_and_rebinding_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("worker.db");
    let (proposal, owner, session) = binding();
    let mut store = open(&path, [8;32]);
    store.dkg_begin(&proposal, &owner, &session).unwrap();
    assert!(store.dkg_checkpoint(&proposal, &owner, &[5;32]).is_err());
    assert!(store.dkg_checkpoint(&proposal, &vec![2;39], &session).unwrap().is_none());
    drop(store);
    let wrong = open(&path, [10;32]);
    assert!(matches!(wrong.dkg_checkpoint(&proposal, &owner, &session), Err(RuntimeError::Crypto)));
    drop(wrong);
    let conn = Connection::open(&path).unwrap();
    conn.execute("UPDATE dkg_checkpoints SET revision=revision+1 WHERE proposal=?1 AND owner=?2",
        rusqlite::params![proposal, owner]).unwrap();
    drop(conn);
    let good = open(&path, [8;32]);
    assert!(good.dkg_checkpoint(&proposal, &owner, &session).is_err());
}

#[test]
fn concurrent_same_ceremony_start_only_one_wins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("worker.db");
    let (proposal, owner, session) = binding();
    let mut first = open(&path, [8;32]);
    let mut second = open(&path, [8;32]);
    first.dkg_begin(&proposal, &owner, &session).unwrap();
    assert!(second.dkg_begin(&proposal, &owner, &session).is_err());
}

#[test]
fn disconnect_at_each_dkg_round_boundary_aborts_and_prevents_restart() {
    // Journal-level fault-injection: encrypted reply commitments represent the
    // last write-ahead IPC response at Round 1, attestation/Round 2, or share
    // distribution/Round 3. No private FROST package is ever recovered.
    for released_replies in 1_u8..=3 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dkg-journal.sqlite");
        let (proposal, owner, session) = binding();
        let mut store = open(&path, [8;32]);
        assert!(!store.dkg_abort_running(&proposal, &owner, &session).unwrap(),
            "an unused connection must not consume the proposal");
        store.dkg_begin(&proposal, &owner, &session).unwrap();
        for revision in 1..=released_replies {
            store.dkg_record_reply(&proposal, &owner, &session, [revision;32], false).unwrap();
        }
        drop(store); // simulate worker connection loss after N outward replies
        let mut recovered = open(&path, [8;32]);
        assert!(recovered.dkg_abort_running(&proposal, &owner, &session).unwrap());
        let aborted = recovered.dkg_checkpoint(&proposal, &owner, &session).unwrap().unwrap();
        assert_eq!(aborted.state, DkgState::Aborted);
        assert_eq!(aborted.revision, u64::from(released_replies) + 1);
        assert_eq!(aborted.reply_digest, [0;32], "terminal abort clears reply commitment");
        assert!(!recovered.dkg_abort_running(&proposal, &owner, &session).unwrap());
        assert!(recovered.dkg_begin(&proposal, &owner, &session).is_err());
        drop(recovered);
        let restarted = open(&path, [8;32]);
        assert_eq!(restarted.dkg_checkpoint(&proposal, &owner, &session).unwrap()
            .unwrap().state, DkgState::Aborted);
    }
}

#[test]
fn completed_share_checkpoint_is_not_aborted_by_connection_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dkg-journal.sqlite");
    let (proposal, owner, session) = binding();
    let mut store = open(&path, [8;32]);
    store.dkg_begin(&proposal, &owner, &session).unwrap();
    store.dkg_record_reply(&proposal, &owner, &session, [0x33;32], true).unwrap();
    assert!(!store.dkg_abort_running(&proposal, &owner, &session).unwrap());
    let terminal = store.dkg_checkpoint(&proposal, &owner, &session).unwrap().unwrap();
    assert_eq!(terminal.state, DkgState::Completed);
    assert_eq!(terminal.revision, 1);
    assert_eq!(terminal.reply_digest, [0x33;32]);
    assert!(store.dkg_begin(&proposal, &owner, &session).is_err());
}
