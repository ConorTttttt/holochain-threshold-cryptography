//! S1-H01 offline regressions. No test in this file certifies production
//! custody: an independently operated rollback witness is NOT implemented.
#![cfg(unix)]

use holochain_mpc_runtime::chain::Anchor;
use holochain_mpc_runtime::custody::{self, Custody, CustodyConfig, KeySource, Layout};
use holochain_mpc_runtime::{MasterKey, RuntimeStore};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tempfile::tempdir;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const KEY: [u8; 32] = [8; 32];

fn private_file(path: &Path, contents: &[u8]) -> TestResult {
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(contents)?;
    f.sync_all()?;
    Ok(())
}
fn config(state: &Path, layout: Layout, key: KeySource) -> CustodyConfig {
    let mut c = CustodyConfig::development(state).unwrap();
    c.layout = layout;
    c.master_key = key;
    c
}
fn side(path: &Path, suffix: &str) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(suffix);
    PathBuf::from(p)
}
fn snapshot(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    ["", "-wal", "-shm"].iter().filter_map(|suffix| {
        let p = side(path, suffix);
        fs::read(&p).ok().map(|bytes| (p, bytes))
    }).collect()
}
fn restore_snapshot(path: &Path, previous: &[(PathBuf, Vec<u8>)]) -> TestResult {
    for suffix in ["", "-wal", "-shm"] {
        let p = side(path, suffix);
        if p.exists() { fs::remove_file(p)?; }
    }
    for (p, bytes) in previous { private_file(p, bytes)?; }
    Ok(())
}

#[test]
fn test_production_layout_rejects_state_directory_key() {
    let state = Path::new("/var/lib/mpc-custody/test-node");
    let c = config(state, Layout::Production, KeySource::StateDirectory);
    let error = c.validate(state).unwrap_err().to_string();
    assert!(error.contains("state-directory"), "{error}");
    for source in [
        KeySource::File { path: PathBuf::from("/etc/mpc/secret.key") },
        KeySource::SystemdCredential { name: "mpc-storage-key".into() },
    ] {
        let error = config(state, Layout::Production, source)
            .validate(state).unwrap_err().to_string();
        assert!(error.contains("NOT VERIFIED"), "{error}");
    }
}

#[test]
fn test_hardened_profile_rejects_unprotected_or_ambiguous_layouts() {
    let state = Path::new("/var/lib/mpc-custody/test-node");
    let role_paths = vec![
        PathBuf::from("/var/lib/mpc-relay/one"),
        PathBuf::from("/var/lib/mpc-lair/one"),
        PathBuf::from("/var/lib/mpc-conductor/one"),
    ];
    let mut c = config(state, Layout::Hardened, KeySource::StateDirectory);
    c.separate_from = role_paths.clone();
    assert!(c.validate(state).is_err(), "state-dir key must be rejected");
    c.master_key = KeySource::File { path: PathBuf::from("/var/keys/key") };
    assert!(c.validate(state).is_err(), "local file is not credential injection");
    c.master_key = KeySource::SystemdCredential { name: "mpc-storage-key".into() };
    c.separate_from.pop();
    assert!(c.validate(state).is_err(), "missing conductor root");
    c.separate_from = role_paths;
    assert!(c.validate(state).is_ok(), "shape only; not a production approval");
    c.anchor = state.join("anchor");
    assert!(c.validate(state).is_err(), "anchor in state snapshot domain");
}

#[test]
fn test_development_backup_restore_restart_with_disposable_share() -> TestResult {
    if unsafe { geteuid() } == 0 {
        eprintln!("NOT VERIFIED: custody must run as a dedicated non-root user");
        return Ok(());
    }
    let tmp = tempdir()?;
    let state = tmp.path().join("node");
    fs::create_dir(&state)?;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    private_file(&state.join(custody::STATE_KEY), &KEY)?;
    private_file(&state.join(custody::NODE_CONFIG), b"synthetic node configuration")?;
    custody::provision(&state, &KEY)?;
    let journal = state.join(custody::JOURNAL);
    private_file(&journal, b"")?;
    let proposal = [5u8; 39];
    let owner = [7u8; 39];
    let group = [9u8; 32];
    {
        let custody = Custody::load(&state)?;
        let mut db = custody.open_journal()?;
        db.seal_share(&proposal, 0, &owner, group, b"disposable secret share")?;
        db.start_deadline(&proposal, &[1u8; 32], 5_000)?;
        assert_eq!(&**db.open_share(&proposal, 0, &owner, group)?, b"disposable secret share");
        db.reserve_nonce(&proposal, 0, &[1u8; 32], &owner, 1_000)?;
    }
    let bundle = tmp.path().join("backup.enc");
    let summary = Custody::load(&state)?.backup(&bundle)?;
    assert!(summary.bytes > 0);
    let restored = tmp.path().join("restored-node");
    custody::restore(&bundle, &restored, &KEY)?;
    let reopened = Custody::load(&restored)?.open_journal()?;
    assert_eq!(&**reopened.open_share(&proposal, 0, &owner, group)?, b"disposable secret share");
    drop(reopened);
    // Updating the original journal makes the old encrypted bundle stale.
    Custody::load(&state)?.open_journal()?.record_abort(&proposal, &[1u8; 32], "ended")?;
    let stale = tmp.path().join("stale-restore");
    assert!(custody::restore(&bundle, &stale, &KEY).is_err());
    assert!(!stale.exists(), "refused restore must not leave state behind");
    Ok(())
}

/// This test intentionally documents the known *software-anchor* failure:
/// restoring the local journal AND the local anchor is accepted. The only
/// current way to refuse it is that production startup itself is disabled.
/// A positive independent-witness rewind test is NOT VERIFIED / not present.
#[test]
fn test_whole_state_snapshot_rewind_refused() -> TestResult {
    let tmp = tempdir()?;
    let journal = tmp.path().join("journal.sqlite");
    let anchor = tmp.path().join("local.anchor");
    Anchor::create(&anchor, &MasterKey::from_bytes(KEY))?;
    {
        let mut db = RuntimeStore::open_anchored(&journal, MasterKey::from_bytes(KEY), &anchor)?;
        db.start_deadline(&[1; 39], &[2; 32], 5_000)?;
    }
    let earlier = snapshot(&journal);
    let anchor_earlier = fs::read(&anchor)?;
    {
        let mut db = RuntimeStore::open_anchored(&journal, MasterKey::from_bytes(KEY), &anchor)?;
        db.start_deadline(&[1; 39], &[3; 32], 5_000)?;
        db.reserve_nonce(&[1; 39], 0, &[3; 32], &[4; 39], 1_000)?;
    }
    // Rewind the complete *local* snapshot, including its software anchor.
    restore_snapshot(&journal, &earlier)?;
    fs::write(&anchor, &anchor_earlier)?;
    let reopened = RuntimeStore::open_anchored(&journal, MasterKey::from_bytes(KEY), &anchor)?;
    assert!(reopened.is_anchored(), "software anchor accepts coordinated rewind");
    drop(reopened);
    // Production mode rejects startup before any signing or nonce step,
    // because a truly independent witness is not implemented.
    let state = tmp.path().join("node");
    let error = config(&state, Layout::Production,
        KeySource::SystemdCredential { name: "mpc-storage-key".into() })
        .validate(&state).unwrap_err().to_string();
    assert!(error.contains("independent rollback witness"), "{error}");
    Ok(())
}

/// Privileged, disposable-UID proof. Run explicitly on a Linux test host as
/// root with: cargo test -p holochain-mpc-runtime --test custody_security_profile
/// test_separated_uids_cannot_read_custody -- --ignored --exact
/// It tests kernel DAC isolation, NOT conductor/signer IPC interoperability.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "NOT VERIFIED until executed on an isolated privileged Linux host"]
fn test_separated_uids_cannot_read_custody() -> TestResult {
    use std::os::unix::fs::chown;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    if unsafe { geteuid() } != 0 {
        return Err("requires root for disposable UID ownership fixture; NOT VERIFIED".into());
    }
    let tmp = tempdir()?;
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755))?;
    let state = tmp.path().join("custody");
    fs::create_dir(&state)?;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    let secret = state.join("master.key");
    private_file(&secret, &KEY)?;
    let journal = state.join("journal.sqlite");
    private_file(&journal, b"")?;
    {
        let mut store = RuntimeStore::open(&journal, MasterKey::from_bytes(KEY))?;
        store.seal_share(&[1; 39], 0, &[2; 39], [3; 32], b"disposable UID-isolation share")?;
    }
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600))?;
    let owner = 61001_u32;
    for path in [&state, &secret, &journal] {
        chown(path, Some(owner), Some(owner))?;
    }
    // No process needs to run under the custody UID for this negative test.
    for other_uid in [61002_u32, 61003, 61004] {
        let result = Command::new("sh")
            .uid(other_uid).gid(other_uid)
            .arg("-c")
            .arg("test ! -r \"$1\" && test ! -r \"$2\" && test ! -r \"$3\"")
            .arg("sh").arg(&state).arg(&secret).arg(&journal)
            .status()?;
        assert!(result.success(), "other UID {other_uid} could read protected custody files");
    }
    Ok(())
}

extern "C" { fn geteuid() -> u32; }
