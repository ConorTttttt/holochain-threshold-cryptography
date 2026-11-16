use holochain_mpc_runtime::{MasterKey, RuntimeError, RuntimeStore, Received};
use holochain_mpc_core::{commitment, Envelope, SessionSpec};
use tempfile::tempdir;
use rusqlite::params;

type T = Result<(),Box<dyn std::error::Error>>;
fn fixture() -> (SessionSpec,Vec<u8>,Vec<u8>) {
    let a=vec![1;39]; let b=vec![2;39];
    (SessionSpec{session_id:commitment("session",b"test"),application_id:"test".into(),
        protocol_id:"frost-ed25519".into(),protocol_version:1,
        context_hash:commitment("context",b"test"),participants:vec![a.clone(),b.clone()],
        threshold:2,max_round:6},a,b)
}
fn store(path:&std::path::Path)->Result<RuntimeStore,Box<dyn std::error::Error>>{
    Ok(RuntimeStore::open(path,MasterKey::from_bytes([8;32]))?)
}
#[test]
fn authenticated_atomic_inbox_recovers_from_restarts_and_concurrent_logical_replays()->T{
    let dir=tempdir()?; let path=dir.path().join("mpc.sqlite");
    let (spec,a,b)=fixture();let proposal=vec![3;39];
    let env=Envelope::new(&spec,a.clone(),Some(b.clone()),1,1,b"hello".to_vec())?;
    {
        let mut db=store(&path)?;
        assert_eq!(db.apply_received(&proposal,&spec,&b,&a,&env,|tx| {
            tx.execute("CREATE TABLE IF NOT EXISTS side_effects (n INTEGER)",[])?;
            tx.execute("INSERT INTO side_effects(n) VALUES (1)",[])?;
            Ok(())
        })?,Received::Inserted);
    }
    let mut db1=store(&path)?;
    let mut db2=store(&path)?;
    assert_eq!(db1.apply_received(&proposal,&spec,&b,&a,&env,|_| {
        panic!("a replay must not cause effects");
    })?,Received::Duplicate);
    assert_eq!(db2.apply_received(&proposal,&spec,&b,&a,&env,|_| Ok(()))?,Received::Duplicate);
    let mut altered=env.clone();altered.payload=b"evil".to_vec();
    altered.payload_hash=commitment("envelope-payload",&altered.payload);
    assert!(matches!(db1.apply_received(&proposal,&spec,&b,&a,&altered,|_|Ok(())),
                     Err(RuntimeError::Conflict(_))));
    assert!(db1.apply_received(&proposal,&spec,&b,&b,&env,|_|Ok(())).is_err());
    // Rollback of a transaction must roll back both the message and its effect.
    let second=Envelope::new(&spec,a.clone(),Some(b.clone()),1,2,b"second".to_vec())?;
    assert!(db1.apply_received(&proposal,&spec,&b,&a,&second,|tx| {
       tx.execute("INSERT INTO side_effects(n) VALUES (2)",params![])?;
       Err(RuntimeError::Wire("injected crash before commit"))
    }).is_err());
    assert_eq!(db1.apply_received(&proposal,&spec,&b,&a,&second,|tx| {
        tx.execute("INSERT INTO side_effects(n) VALUES (2)",params![])?;
        Ok(())
    })?,Received::Inserted);
    Ok(())
}
#[test]
fn nonce_burn_survives_restart_and_abort_cannot_revive()->T {
    let dir=tempdir()?; let path=dir.path().join("m.sqlite");
    let proposal=[7;39];let signer=[1;39];let op=[3;32];
    {
        let mut db=store(&path)?;
        db.start_deadline(&proposal,&op,1500)?;
        db.reserve_nonce(&proposal,0,&op,&signer,1000)?;
        db.authorize_commitment(&proposal,0,&op,&signer,b"public commitment")?;
    }
    {
        let mut db=store(&path)?;
        assert!(matches!(db.reserve_nonce(&proposal,0,&op,&signer,1000),Err(RuntimeError::Conflict(_))));
        assert!(!db.expire_at(&proposal,&op,1499)?);
        assert!(db.expire_at(&proposal,&op,1500)?);
        assert!(matches!(db.reserve_nonce(&proposal,0,&op,&signer,1000),Err(RuntimeError::Aborted)));
        assert!(db.start_deadline(&proposal,&op,100000).is_err());
        db.record_abort(&proposal,&op,"partition")?;
    }
    Ok(())
}
#[test]
fn ciphertext_is_write_once_epoch_bound_and_detects_tampering()->T {
    let dir=tempdir()?;let path=dir.path().join("secrets.sqlite");
    let prop=[4;39];let owner=[1;39];let group=[5;32];
    {
        let mut db=store(&path)?;
        db.seal_share(&prop,0,&owner,group,b"test secret key share")?;
        assert!(db.seal_share(&prop,0,&owner,group,b"different").is_err());
    }
    let db=store(&path)?;
    assert_eq!(&**db.open_share(&prop,0,&owner,group)?,b"test secret key share");
    assert!(db.open_share(&prop,0,&owner,[6;32]).is_err());
    drop(db);
    assert!(RuntimeStore::open(&path,MasterKey::from_bytes([9;32]))?
        .open_share(&prop,0,&owner,group).is_err());
    Ok(())
}
#[test]
fn abort_on_missing_or_expired_operation_and_activation_forks()->T {
    let dir=tempdir()?; let path=dir.path().join("state.sqlite");
    let mut db=store(&path)?;
    let prop=[4;39];let op=[9;32];
    assert!(db.expire_at(&prop,&op,100).is_err());
    db.start_deadline(&prop,&op,200)?;
    db.reserve_nonce(&prop,1,&op,&[2;39],100)?;
    db.record_abort(&prop,&op,"peer timed out")?;
    assert!(db.reserve_nonce(&prop,1,&op,&[2;39],100).is_err());
    db.store_activation(&prop,1,[4;32])?;
    assert!(db.store_activation(&prop,1,[5;32]).is_err());
    Ok(())
}

// ---- v0.4.0 Phase 7 custody hardening ----------------------------------

use holochain_mpc_runtime::chain::Anchor;
use holochain_mpc_runtime::lifecycle::EpochState;
use std::fs;
use std::path::{Path, PathBuf};

fn key() -> MasterKey { MasterKey::from_bytes([8;32]) }
fn anchored(path: &Path, anchor: &Path) -> Result<RuntimeStore, RuntimeError> {
    RuntimeStore::open_anchored(path, key(), anchor)
}
fn side(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}
/// An operator's file-level copy of a stopped node's journal.
fn snapshot(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    ["", "-wal", "-shm"].iter().map(|s| side(path, s))
        .filter_map(|p| fs::read(&p).ok().map(|bytes| (p, bytes))).collect()
}
/// Put the copy back with the private mode the custody checks require.
fn restore_files(path: &Path, files: &[(PathBuf, Vec<u8>)]) {
    for s in ["", "-wal", "-shm"] { let _ = fs::remove_file(side(path, s)); }
    for (p, bytes) in files {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        std::io::Write::write_all(&mut options.open(p).unwrap(), bytes).unwrap();
    }
}
fn rollback(result: Result<RuntimeStore, RuntimeError>) -> String {
    match result {
        Err(e @ RuntimeError::Rollback(_)) => e.to_string(),
        Err(e) => panic!("expected an anti-rollback refusal, got: {e}"),
        Ok(_) => panic!("expected an anti-rollback refusal, the journal was accepted"),
    }
}

/// R3: a restored older journal file is refused before the nonce slot it
/// forgot about can be reserved again.
#[test]
fn restored_journal_snapshot_is_refused_by_its_anchor()->T {
    let dir=tempdir()?; let path=dir.path().join("journal.sqlite"); let anchor=dir.path().join("journal.anchor");
    Anchor::create(&anchor,&key())?;
    let (proposal,signer,op)=([7;39],[1;39],[3;32]);
    anchored(&path,&anchor)?.start_deadline(&proposal,&[1;32],5000)?;
    let before=snapshot(&path);
    {
        let mut db=anchored(&path,&anchor)?;
        db.start_deadline(&proposal,&op,1500)?;
        db.reserve_nonce(&proposal,0,&op,&signer,1000)?;
        db.authorize_commitment(&proposal,0,&op,&signer,b"public commitment")?;
        db.record_abort(&proposal,&op,"published then aborted")?;
    }
    restore_files(&path,&before);
    let refused=rollback(anchored(&path,&anchor));
    assert!(refused.contains("older than"),"{refused}");
    // What the anchor prevents: the restored journal hands out the slot again.
    {
        let mut plain=store(&path)?;
        plain.start_deadline(&proposal,&op,1500)?;
        plain.reserve_nonce(&proposal,0,&op,&signer,1000)?;
        plain.authorize_commitment(&proposal,0,&op,&signer,b"a second commitment")?;
        plain.record_abort(&proposal,&op,"published twice")?;
        plain.start_deadline(&proposal,&[2;32],5000)?;
    }
    // Writing past the anchor's position does not launder the restore.
    let refused=rollback(anchored(&path,&anchor));
    assert!(refused.contains("does not extend"),"{refused}");
    Ok(())
}

#[test]
fn a_journal_ahead_of_its_anchor_catches_up_but_a_fork_is_refused()->T {
    let dir=tempdir()?; let path=dir.path().join("journal.sqlite"); let anchor=dir.path().join("journal.anchor");
    Anchor::create(&anchor,&key())?;
    let p=[4;39];
    anchored(&path,&anchor)?.start_deadline(&p,&[1;32],10)?;
    // An unanchored write stands in for a crash between commit and append.
    store(&path)?.start_deadline(&p,&[2;32],10)?;
    let db=anchored(&path,&anchor)?;
    let (head,last)=(db.custody_head()?,Anchor::open(&anchor)?.scan(&key())?.last);
    assert_eq!((head.seq,head.chain),(last.seq,last.chain),"the anchor caught up with the journal");
    drop(db);
    let before=snapshot(&path);
    anchored(&path,&anchor)?.start_deadline(&p,&[3;32],10)?;
    restore_files(&path,&before);
    // A different history that is longer than the anchored one.
    let mut plain=store(&path)?;
    for op in 4..8u8 { plain.start_deadline(&p,&[op;32],10)?; }
    drop(plain);
    let refused=rollback(anchored(&path,&anchor));
    assert!(refused.contains("does not extend"),"{refused}");
    Ok(())
}

#[test]
fn missing_foreign_or_tampered_anchors_fail_closed()->T {
    let dir=tempdir()?; let path=dir.path().join("journal.sqlite"); let anchor=dir.path().join("a.anchor");
    Anchor::create(&anchor,&key())?;
    anchored(&path,&anchor)?.start_deadline(&[4;39],&[1;32],10)?;
    let original=fs::read_to_string(&anchor)?;
    // A wrong master key cannot authenticate the anchor or the journal head.
    assert!(RuntimeStore::open_anchored(&path,MasterKey::from_bytes([9;32]),&anchor).is_err());
    // A deleted anchor.
    fs::rename(&anchor,dir.path().join("moved"))?;
    assert!(rollback(anchored(&path,&anchor)).contains("missing"));
    fs::rename(dir.path().join("moved"),&anchor)?;
    // A fresh anchor substituted for this journal's own.
    let other=dir.path().join("b.anchor");
    Anchor::create(&other,&key())?;
    assert!(rollback(anchored(&path,&other)).contains("different"));
    // A flipped tag byte in the latest record.
    let lines: Vec<&str>=original.lines().collect();
    let last=lines.last().unwrap();
    let flipped=format!("{}{}",&last[..last.len()-1],if last.ends_with('0'){'1'}else{'0'});
    fs::write(&anchor,original.replace(last,&flipped))?;
    assert!(rollback(anchored(&path,&anchor)).contains("not authentic"));
    // An old, authentic record appended again so it reads as the latest.
    fs::write(&anchor,format!("{original}{}\n",lines[1]))?;
    assert!(rollback(anchored(&path,&anchor)).contains("backwards"));
    // A torn final write is skipped, and the next record still parses.
    fs::write(&anchor,format!("{original}17 0badc0de"))?;
    let mut db=anchored(&path,&anchor)?;
    db.start_deadline(&[4;39],&[2;32],10)?;
    drop(db);
    let scan=Anchor::open(&anchor)?.scan(&key())?;
    assert_eq!((scan.skipped_lines,scan.last.seq),(1,anchored(&path,&anchor)?.custody_head()?.seq));
    Ok(())
}

#[test]
fn retired_epochs_refuse_signing_and_erasure_is_one_way()->T {
    let dir=tempdir()?; let path=dir.path().join("journal.sqlite"); let anchor=dir.path().join("j.anchor");
    Anchor::create(&anchor,&key())?;
    let (prop,owner,signer,group)=([4;39],[1;39],[1;39],[5;32]);
    let mut db=anchored(&path,&anchor)?;
    db.seal_share(&prop,0,&owner,group,b"epoch zero share")?;
    db.start_deadline(&prop,&[1;32],5000)?;
    db.reserve_nonce(&prop,0,&[1;32],&signer,100)?;
    db.retire_epoch(&prop,0,1000,"rotated to a new group")?;
    // The in-flight operation is aborted, and nothing new starts in the epoch.
    assert!(matches!(db.ensure_live(&prop,&[1;32],200),Err(RuntimeError::Aborted)));
    db.start_deadline(&prop,&[2;32],5000)?;
    assert!(matches!(db.reserve_nonce(&prop,0,&[2;32],&signer,100),Err(RuntimeError::Conflict(_))));
    assert!(db.open_share(&prop,0,&owner,group).is_err());
    assert_eq!(db.epoch_state(&prop,0)?,EpochState::Retired);
    assert!(db.retire_epoch(&prop,0,1000,"again").is_err());
    // Other epochs are untouched; only retired ones can be erased.
    db.seal_share(&prop,1,&owner,[6;32],b"epoch one share")?;
    assert_eq!(&**db.open_share(&prop,1,&owner,[6;32])?,b"epoch one share");
    assert!(db.erase_share(&prop,1,2000).is_err());
    drop(db);
    let ciphertext: Vec<u8>=rusqlite::Connection::open(&path)?.query_row(
        "SELECT ciphertext FROM secrets WHERE epoch=0",[],|r| r.get(0))?;
    let before_erase=snapshot(&path);
    let mut db=anchored(&path,&anchor)?;
    assert_eq!(db.erase_share(&prop,0,2000)?,1);
    assert!(db.erase_share(&prop,0,2000).is_err());
    assert!(db.seal_share(&prop,0,&owner,group,b"resurrected").is_err());
    assert_eq!(db.epoch_state(&prop,0)?,EpochState::Erased);
    drop(db);
    // Best effort: the old ciphertext is gone from the main file and the WAL.
    for (_,bytes) in snapshot(&path) {
        assert!(!bytes.windows(ciphertext.len()).any(|w| w==ciphertext.as_slice()));
    }
    // Restoring the pre-erasure journal to recover the share is a rollback.
    restore_files(&path,&before_erase);
    rollback(anchored(&path,&anchor));
    Ok(())
}

#[cfg(unix)]
mod custody_layout {
    use super::*;
    use holochain_mpc_runtime::custody::{self, Custody, CustodyConfig, KeySource, Layout};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    fn private(path: &Path, bytes: &[u8]) {
        let _ = fs::remove_file(path);
        let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
        std::io::Write::write_all(&mut file, bytes).unwrap();
    }
    fn chmod(path: &Path, mode: u32) { fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap(); }
    /// A state directory as `mpc-node provision` leaves it, plus a journal.
    fn node(root: &Path, name: &str) -> PathBuf {
        let dir = root.join(name);
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        private(&dir.join("storage.key"), &[8; 32]);
        private(&dir.join("node.json"), b"{\"pinned-node-identity\":1}");
        custody::provision(&dir, &[8; 32]).unwrap();
        private(&dir.join("journal.sqlite"), b"");
        let custody = Custody::load(&dir).unwrap();
        custody.open_journal().unwrap().seal_share(&[4; 39], 0, &[1; 39], [5; 32], b"sealed share").unwrap();
        dir
    }
    fn unsafe_layout(dir: &Path) -> String {
        match Custody::load(dir) {
            Err(e @ RuntimeError::Unsafe(_)) => e.to_string(),
            Err(e) => panic!("expected an unsafe-layout refusal, got: {e}"),
            Ok(_) => panic!("expected an unsafe-layout refusal, the layout was accepted"),
        }
    }
    fn rewrite(dir: &Path, config: &CustodyConfig) {
        private(&dir.join("custody.json"), &serde_json::to_vec(config).unwrap());
    }

    #[test]
    fn custody_layout_refuses_unsafe_modes_and_misplaced_keys() -> T {
        let root = tempdir()?;
        let dir = node(root.path(), "node");
        let key = dir.join("storage.key");
        let good = Custody::load(&dir)?.config().clone();
        assert_eq!(good.anchor, root.path().join("node.custody-anchor"));

        chmod(&key, 0o640);
        assert!(unsafe_layout(&dir).contains("storage.key"));
        chmod(&key, 0o600);
        chmod(&dir, 0o750);
        assert!(unsafe_layout(&dir).contains("0700"));
        chmod(&dir, 0o700);
        fs::rename(&key, dir.join("real.key"))?;
        std::os::unix::fs::symlink(dir.join("real.key"), &key)?;
        unsafe_layout(&dir);
        fs::remove_file(&key)?;
        fs::rename(dir.join("real.key"), &key)?;
        fs::hard_link(&key, root.path().join("copy.key"))?;
        unsafe_layout(&dir);
        fs::remove_file(root.path().join("copy.key"))?;
        let journal = dir.join("journal.sqlite");
        chmod(&journal, 0o644);
        assert!(Custody::load(&dir)?.open_journal().is_err(), "a readable journal is refused");
        chmod(&journal, 0o600);

        // custody.json cannot place the key or the anchor unsafely.
        rewrite(&dir, &CustodyConfig { layout: Layout::Separated, separate_from: vec![PathBuf::from("/")], ..good.clone() });
        assert!(unsafe_layout(&dir).contains("separated layout forbids"));
        rewrite(&dir, &CustodyConfig { master_key: KeySource::File { path: dir.join("other.key") }, ..good.clone() });
        assert!(unsafe_layout(&dir).contains("outside the state directory"));
        rewrite(&dir, &CustodyConfig { anchor: dir.join("inside.anchor"), ..good.clone() });
        assert!(unsafe_layout(&dir).contains("outside the state directory"));
        let keys = root.path().join("keys");
        fs::DirBuilder::new().mode(0o700).create(&keys)?;
        private(&keys.join("master.key"), &[8; 32]);
        let external = CustodyConfig { master_key: KeySource::File { path: keys.join("master.key") }, ..good.clone() };
        rewrite(&dir, &external);
        assert!(unsafe_layout(&dir).contains("still beside the journal"));
        fs::remove_file(&key)?;
        let custody = Custody::load(&dir)?;
        assert_eq!(&**custody.open_journal()?.open_share(&[4; 39], 0, &[1; 39], [5; 32])?, b"sealed share");
        chmod(&keys.join("master.key"), 0o644);
        unsafe_layout(&dir);
        chmod(&keys.join("master.key"), 0o600);
        // The separated layout: the anchor's directory belongs to this user here,
        // and separate_from names a path this user owns.
        rewrite(&dir, &CustodyConfig { layout: Layout::Separated, separate_from: vec![PathBuf::from("/")], ..external.clone() });
        assert!(unsafe_layout(&dir).contains("must belong to another"));
        rewrite(&dir, &CustodyConfig { layout: Layout::Separated, separate_from: vec![keys.clone()], ..external.clone() });
        assert!(unsafe_layout(&dir).contains("different users"));
        if std::env::var_os(custody::CREDENTIALS_ENV).is_none() {
            rewrite(&dir, &CustodyConfig { master_key: KeySource::SystemdCredential { name: "mpc-storage-key".into() }, ..good.clone() });
            assert!(unsafe_layout(&dir).contains("CREDENTIALS_DIRECTORY"));
        }
        rewrite(&dir, &external);
        Custody::load(&dir)?;

        // A parent directory another user could rename is refused up front.
        let shared = root.path().join("shared");
        fs::DirBuilder::new().mode(0o700).create(&shared)?;
        chmod(&shared, 0o777);
        assert!(matches!(custody::check_location(&shared.join("node")), Err(RuntimeError::Unsafe(_))));
        Ok(())
    }

    #[test]
    fn backup_restores_only_when_not_older_than_the_anchor() -> T {
        let root = tempdir()?;
        let dir = node(root.path(), "node");
        let bundle = root.path().join("node.backup");
        let summary = Custody::load(&dir)?.backup(&bundle)?;
        assert!(summary.head_seq > 0);
        let bytes = fs::read(&bundle)?;
        assert!(!bytes.windows(20).any(|w| w == b"pinned-node-identity"), "the bundle is encrypted");
        assert!(Custody::load(&dir)?.backup(&bundle).is_err(), "never overwrite a backup");

        // The directory is lost; the operator restores it with their key copy.
        fs::rename(&dir, root.path().join("lost"))?;
        assert!(matches!(custody::restore(&bundle, &dir, &[9; 32]), Err(RuntimeError::Crypto)));
        let mut tampered = bytes.clone();
        let at = tampered.len() - 5;
        tampered[at] ^= 1;
        fs::write(root.path().join("tampered.backup"), &tampered)?;
        assert!(custody::restore(&root.path().join("tampered.backup"), &dir, &[8; 32]).is_err());
        assert!(!dir.exists());
        custody::restore(&bundle, &dir, &[8; 32])?;
        assert!(custody::restore(&bundle, &dir, &[8; 32]).is_err(), "never restore over a directory");
        let custody = Custody::load(&dir)?;
        let mut db = custody.open_journal()?;
        assert_eq!(&**db.open_share(&[4; 39], 0, &[1; 39], [5; 32])?, b"sealed share");
        // Any later write makes the bundle stale.
        db.start_deadline(&[4; 39], &[1; 32], 10)?;
        drop(db);
        fs::remove_dir_all(&dir)?;
        let refused = custody::restore(&bundle, &dir, &[8; 32]).err().unwrap();
        assert!(matches!(refused, RuntimeError::Rollback(_)), "{refused}");
        assert!(!dir.exists());
        assert!(fs::read_dir(root.path())?.all(|e| !e.unwrap().file_name().to_string_lossy().contains(".restore-")),
            "a refused restore leaves no staging directory");
        Ok(())
    }

    #[test]
    fn retention_erases_only_shares_retired_long_enough() -> T {
        let root = tempdir()?;
        let dir = node(root.path(), "node");
        let mut config = Custody::load(&dir)?.config().clone();
        assert!(Custody::load(&dir)?.apply_retention(1).is_err(), "no policy, no erasure");
        config.retired_share_retention_days = Some(30);
        rewrite(&dir, &config);
        let custody = Custody::load(&dir)?;
        let retired_at = 1_000_000;
        custody.open_journal()?.retire_epoch(&[4; 39], 0, retired_at, "rotated")?;
        assert!(custody.apply_retention(retired_at + 29 * 86_400_000)?.is_empty());
        assert_eq!(custody.apply_retention(retired_at + 30 * 86_400_000)?, vec![([4; 39].to_vec(), 0)]);
        assert_eq!(custody.open_journal()?.epoch_state(&[4; 39], 0)?, EpochState::Erased);
        Ok(())
    }

    #[test]
    fn mpc_custody_cli_verifies_and_refuses_a_rolled_back_journal() -> T {
        use std::process::Command;
        let root = tempdir()?;
        let dir = node(root.path(), "node");
        let cli = |args: &[&str]| Command::new(env!("CARGO_BIN_EXE_mpc-custody")).args(args).output().unwrap();
        let state = dir.to_str().unwrap();
        let ok = cli(&["verify", state]);
        assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));
        assert!(String::from_utf8_lossy(&ok.stdout).contains("PASS"));
        let refused = cli(&["retire-epoch", state, "--proposal-hex", &"04".repeat(39), "--epoch", "0", "--reason", "x"]);
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("--confirm-retire"));

        let journal = dir.join("journal.sqlite");
        let before = snapshot(&journal);
        Custody::load(&dir)?.open_journal()?.start_deadline(&[4; 39], &[1; 32], 10)?;
        restore_files(&journal, &before);
        let rolled_back = cli(&["verify", state]);
        assert!(!rolled_back.status.success());
        assert!(String::from_utf8_lossy(&rolled_back.stderr).contains("anti-rollback"), "{}", String::from_utf8_lossy(&rolled_back.stderr));
        Ok(())
    }
}


// Sprint 1.7 / Agent 20: deterministic SQLite fault injection for the
// reservation and post-commit/pre-acknowledgement storage boundaries.
#[test]
fn reserve_nonce_storage_error_is_fail_closed_after_explicit_abort() -> T {
    let dir = tempdir()?;
    let path = dir.path().join("reserve-fault.sqlite");
    let proposal = [7;39];
    let operation = [41;32];
    let signer = [1;39];
    let mut db = store(&path)?;
    db.start_deadline(&proposal, &operation, 5000)?;
    // A true SQLite write error (no mock RuntimeStore implementation).
    let injection = rusqlite::Connection::open(&path)?;
    injection.execute_batch(
        "CREATE TRIGGER agent20_fail_reserve BEFORE INSERT ON nonces
         BEGIN SELECT RAISE(ABORT, 'agent20 injected reserve failure'); END;")?;
    assert!(matches!(
        db.reserve_nonce(&proposal, 0, &operation, &signer, 100),
        Err(RuntimeError::Sql(_))
    ));
    let row_count: i64 = injection.query_row(
        "SELECT COUNT(*) FROM nonces", [], |r| r.get(0))?;
    assert_eq!(row_count, 0, "no FROST nonce may be generated before reservation");
    // S15-L01 owns automatic SigningSession::begin abort accounting. Until that
    // work lands, caller policy must explicitly record a terminal abort here.
    db.record_abort(&proposal, &operation, "reserve storage failure")?;
    injection.execute_batch("DROP TRIGGER agent20_fail_reserve;")?;
    assert!(matches!(
        db.reserve_nonce(&proposal, 0, &operation, &signer, 101),
        Err(RuntimeError::Aborted)
    ));
    assert!(db.start_deadline(&proposal, &operation, 6000).is_err());
    Ok(())
}

#[test]
fn authorize_commitment_after_commit_before_ack_is_ambiguous_and_burned() -> T {
    let dir = tempdir()?;
    let path = dir.path().join("ambiguous.sqlite");
    let anchor = dir.path().join("anchor");
    let temporarily_moved = dir.path().join("anchor-held");
    Anchor::create(&anchor, &key())?;
    let (proposal, signer, operation) = ([7;39], [1;39], [42;32]);
    let mut db = anchored(&path, &anchor)?;
    db.start_deadline(&proposal, &operation, 5000)?;
    db.reserve_nonce(&proposal, 0, &operation, &signer, 100)?;
    // The anchor is normally present for both writes. Replace the anchor path
    // with a directory only *after* reservation and before authorization.
    // SQLite commits the published state, but post-commit check_anchor fails.
    // This is a deterministic missing-ack fault even when running as root.
    fs::rename(&anchor, &temporarily_moved)?;
    fs::create_dir(&anchor)?;
    assert!(db.authorize_commitment(
        &proposal, 0, &operation, &signer, b"disposable public commitment").is_err());
    let connection = rusqlite::Connection::open(&path)?;
    let state: String = connection.query_row(
        "SELECT state FROM nonces WHERE proposal=?1 AND operation=?2 AND signer=?3",
        params![proposal.as_slice(), operation.as_slice(), signer.as_slice()],
        |row| row.get(0))?;
    assert_eq!(state, "published", "write committed despite missing ack");
    drop(connection);
    fs::remove_dir(&anchor)?;
    fs::rename(&temporarily_moved, &anchor)?;
    db.check_anchor()?; // reconcile the committed-but-unacknowledged write
    drop(db);
    let mut restarted = anchored(&path, &anchor)?;
    assert!(matches!(
        restarted.reserve_nonce(&proposal, 0, &operation, &signer, 101),
        Err(RuntimeError::Conflict(_))
    ));
    // An ambiguous acknowledgement must never cause a second authorization.
    assert!(restarted.authorize_commitment(
        &proposal, 0, &operation, &signer, b"a different commitment").is_err());
    Ok(())
}


#[test]
fn custody_log_failure_rolls_back_nonce_reserve_and_publication() -> T {
    let dir = tempdir()?;
    let path = dir.path().join("custody-log-fault.sqlite");
    let (proposal, signer, operation) = ([7;39], [1;39], [43;32]);
    let mut db = store(&path)?;
    db.start_deadline(&proposal, &operation, 5000)?;
    let injection = rusqlite::Connection::open(&path)?;
    injection.execute_batch(
        "CREATE TRIGGER agent20_log_fault BEFORE INSERT ON custody_log
         WHEN NEW.label = 'reserve-nonce'
         BEGIN SELECT RAISE(ABORT, 'agent20 reserve chain failure'); END;")?;
    assert!(matches!(
        db.reserve_nonce(&proposal, 0, &operation, &signer, 100),
        Err(RuntimeError::Sql(_))
    ));
    let count: i64 = injection.query_row("SELECT COUNT(*) FROM nonces", [], |r| r.get(0))?;
    assert_eq!(count, 0, "reservation and custody-chain event must be atomic");
    injection.execute_batch("DROP TRIGGER agent20_log_fault;")?;
    db.reserve_nonce(&proposal, 0, &operation, &signer, 101)?;
    injection.execute_batch(
        "CREATE TRIGGER agent20_log_fault BEFORE INSERT ON custody_log
         WHEN NEW.label = 'publish-commitment'
         BEGIN SELECT RAISE(ABORT, 'agent20 publish chain failure'); END;")?;
    assert!(matches!(
        db.authorize_commitment(&proposal, 0, &operation, &signer, b"test commitment"),
        Err(RuntimeError::Sql(_))
    ));
    let state: String = injection.query_row(
        "SELECT state FROM nonces WHERE proposal=?1 AND operation=?2 AND signer=?3",
        params![proposal.as_slice(), operation.as_slice(), signer.as_slice()],
        |r| r.get(0))?;
    assert_eq!(state, "reserved", "publish UPDATE must roll back with its custody event");
    injection.execute_batch("DROP TRIGGER agent20_log_fault;")?;
    db.authorize_commitment(&proposal, 0, &operation, &signer, b"test commitment")?;
    assert!(matches!(
        db.reserve_nonce(&proposal, 0, &operation, &signer, 102),
        Err(RuntimeError::Conflict(_))
    ));
    Ok(())
}
