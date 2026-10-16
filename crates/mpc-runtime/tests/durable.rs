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
