//! v0.4.0 Phase 7 hardening: custody layout of one node state directory.
//!
//! `custody.json` in the state directory names the anti-rollback anchor (a
//! file OUTSIDE the directory) and where the journal master key comes from:
//! `storage.key` in the directory (development layout only), a protected file
//! elsewhere, or a systemd credential. `Custody::load` refuses to proceed on
//! unsafe ownership or modes, writable ancestors, symlinks, hard links, a key
//! beside the journal in the separated layout, or the root user. Every
//! journal it opens is anchored (`RuntimeStore::open_anchored`).
//!
//! Development-grade custody, NOT production key custody: whoever runs as the
//! custody user, or as root, can read the master key and rewrite the journal
//! and the anchor. See docs/V040_PHASE7_CUSTODY_HARDENING.md.
use super::chain::{self, hex, unhex, Anchor, AnchorScan, CustodyHead};
use super::lifecycle::{self, EpochRecord, EpochState};
use super::{MasterKey, RResult, RuntimeError, RuntimeStore};
use chacha20poly1305::{aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

pub const CONFIG: &str = "custody.json";
pub const JOURNAL: &str = "journal.sqlite";
pub const STATE_KEY: &str = "storage.key";
pub const NODE_CONFIG: &str = "node.json";
pub const DESCRIPTOR: &str = "group-descriptor.json";
/// Set by systemd for a unit with `LoadCredential=`/`LoadCredentialEncrypted=`.
pub const CREDENTIALS_ENV: &str = "CREDENTIALS_DIRECTORY";
/// The default anchor is `<state-dir>.custody-anchor`, beside the directory.
pub const ANCHOR_SUFFIX: &str = ".custody-anchor";
const CONFIG_SCHEMA: u16 = 1;
const MAX_CONFIG: u64 = 16 * 1024;
const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_BUNDLE: u64 = 256 * 1024 * 1024;
const BUNDLE_MAGIC: &[u8] = b"holochain-mpc custody-backup v1\n";
const MS_PER_DAY: i64 = 86_400_000;

extern "C" {
    fn geteuid() -> u32;
    fn getegid() -> u32;
}
// SAFETY: both calls take no arguments and always succeed.
fn euid() -> u32 { unsafe { geteuid() } }
fn egid() -> u32 { unsafe { getegid() } }

fn unsafe_layout(message: String) -> RuntimeError { RuntimeError::Unsafe(message) }

/// Where the journal master key comes from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeySource {
    /// `storage.key` inside the state directory, beside the journal it
    /// protects. What `mpc-node provision` creates; development layout only.
    StateDirectory,
    /// A 32-byte file outside the state directory: owned by the custody user
    /// with mode 0400/0600, or owned by root and readable only by the custody
    /// user's group (0440).
    File { path: PathBuf },
    /// `$CREDENTIALS_DIRECTORY/<name>`, placed by systemd from
    /// `LoadCredentialEncrypted=` (TPM2- or host-key-sealed) or
    /// `LoadCredential=`. The key never sits in the state directory.
    SystemdCredential { name: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// One user may run everything; the master key may sit in the state
    /// directory. Rollback of the journal alone is still detected.
    Development,
    /// The target layout: the key comes from outside the state directory, the
    /// anchor's directory belongs to another user, and the node (conductor,
    /// relay) and Lair run as other users (`separate_from`).
    Separated,
    /// Strict, software-checked candidate profile. Still NOT production:
    /// neither sealed credentials nor an independent rollback witness can
    /// be attested by this process. Requires three distinct role UIDs.
    Hardened,
    /// Reserved for independently witnessed, hardware-protected custody.
    /// This build ALWAYS rejects it.
    Production,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyConfig {
    pub schema: u16,
    /// Absolute path of the anti-rollback anchor, outside the state directory.
    pub anchor: PathBuf,
    pub master_key: KeySource,
    pub layout: Layout,
    /// Paths owned by the other roles' users, such as the Lair keystore root
    /// and the conductor data root. Each must belong to a different user.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub separate_from: Vec<PathBuf>,
    /// Days a retired epoch's share is kept before `apply_retention` erases it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_share_retention_days: Option<u32>,
}

fn normal_absolute(path: &Path) -> bool {
    path.is_absolute() && path.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}
/// Lexically and, where the paths exist, after resolving symlinks.
fn inside(path: &Path, dir: &Path) -> bool {
    if path.starts_with(dir) { return true; }
    let resolved = |p: &Path| -> Option<PathBuf> {
        match fs::canonicalize(p) {
            Ok(real) => Some(real),
            Err(_) => Some(fs::canonicalize(p.parent()?).ok()?.join(p.file_name()?)),
        }
    };
    matches!((resolved(path), resolved(dir)), (Some(p), Some(d)) if p.starts_with(&d))
}

impl CustodyConfig {
    /// The configuration `mpc-node provision` writes: development layout, the
    /// key in the state directory, the anchor beside the directory.
    pub fn development(state_dir: &Path) -> RResult<Self> {
        Ok(Self { schema: CONFIG_SCHEMA, anchor: default_anchor(state_dir)?, master_key: KeySource::StateDirectory,
            layout: Layout::Development, separate_from: Vec::new(), retired_share_retention_days: None })
    }
    pub fn validate(&self, state_dir: &Path) -> RResult<()> {
        if self.schema != CONFIG_SCHEMA { return Err(RuntimeError::Wire("unsupported custody.json schema")); }
        if self.layout == Layout::Production {
            if matches!(&self.master_key, KeySource::StateDirectory) {
                return Err(unsafe_layout("production forbids a state-directory master key".into()));
            }
            // A separate path or local append-only anchor cannot attest a
            // hardware-protected key or storage outside a VM snapshot domain.
            return Err(unsafe_layout("production custody is NOT VERIFIED: independent rollback witness and hardware-backed key source are required; startup refused".into()));
        }
        if self.layout == Layout::Hardened {
            if !matches!(&self.master_key, KeySource::SystemdCredential { .. }) {
                return Err(unsafe_layout("hardened layout requires an injected systemd credential, not a local key file".into()));
            }
            if self.separate_from.len() != 3 {
                return Err(unsafe_layout("hardened layout requires exactly three ordered role roots: relay, Lair signer, conductor".into()));
            }
        }
        if !normal_absolute(&self.anchor) || self.anchor.parent().is_none() {
            return Err(unsafe_layout("the anchor must be a normalised absolute path".into()));
        }
        if inside(&self.anchor, state_dir) {
            return Err(unsafe_layout("the anchor must be outside the state directory, or restoring the directory rewinds it".into()));
        }
        match &self.master_key {
            KeySource::StateDirectory if self.layout != Layout::Development => {
                return Err(unsafe_layout("the separated layout forbids a master key inside the state directory".into()));
            }
            KeySource::StateDirectory => {}
            KeySource::File { path } => {
                if !normal_absolute(path) { return Err(unsafe_layout("the key file must be a normalised absolute path".into())); }
                if inside(path, state_dir) {
                    return Err(unsafe_layout("an external key file must be outside the state directory".into()));
                }
            }
            KeySource::SystemdCredential { name } => {
                if name.is_empty() || name.len() > 64 || name.starts_with('.') ||
                   !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
                    return Err(RuntimeError::Wire("invalid systemd credential name"));
                }
            }
        }
        if self.separate_from.iter().any(|p| !normal_absolute(p)) {
            return Err(unsafe_layout("separate_from paths must be normalised absolute paths".into()));
        }
        if self.layout != Layout::Development && self.separate_from.is_empty() {
            return Err(unsafe_layout("the separated layout must name the Lair and node paths in separate_from".into()));
        }
        if self.retired_share_retention_days.is_some_and(|d| d > 36_500) {
            return Err(RuntimeError::Wire("retention longer than 100 years"));
        }
        Ok(())
    }
}

/// `<parent>/<name>.custody-anchor` for state directory `<parent>/<name>`.
pub fn default_anchor(state_dir: &Path) -> RResult<PathBuf> {
    let (Some(parent), Some(name)) = (state_dir.parent(), state_dir.file_name()) else {
        return Err(unsafe_layout("the state directory needs a parent directory".into()));
    };
    let mut file = name.to_os_string();
    file.push(ANCHOR_SUFFIX);
    Ok(parent.join(file))
}

/// Refuse root, and a path below a directory another user could rename.
/// Ancestors must be owned by root or this user. Write access for others is
/// refused unless the directory is root-owned and sticky (like /tmp); group
/// write only for this user's own primary group (a umask-0002, user-private
/// group setup), which `custody_check.sh` still reports as a warning.
pub fn check_location(path: &Path) -> RResult<()> {
    if euid() == 0 {
        return Err(unsafe_layout("custody must not run as root; use the dedicated custody user".into()));
    }
    if !path.is_absolute() { return Err(unsafe_layout(format!("{} is not absolute", path.display()))); }
    let mut chains = vec![path.parent().map(Path::to_path_buf)];
    if let Some(parent) = path.parent() { chains.push(fs::canonicalize(parent).ok()); }
    for start in chains.into_iter().flatten() {
        let mut next = Some(start.as_path());
        while let Some(dir) = next {
            let meta = fs::metadata(dir)?;
            let mode = meta.mode();
            let trusted_owner = meta.uid() == 0 || meta.uid() == euid();
            let shared_sticky = mode & 0o1000 != 0 && meta.uid() == 0;
            let group_ok = mode & 0o020 == 0 || meta.gid() == egid() || shared_sticky;
            let others_ok = mode & 0o002 == 0 || shared_sticky;
            if !meta.is_dir() || !trusted_owner || !group_ok || !others_ok {
                return Err(unsafe_layout(format!("{} is owned by another user, or writable by others or by \
                    a group other than this user's own", dir.display())));
            }
            next = dir.parent();
        }
    }
    Ok(())
}

fn state_directory(dir: &Path) -> RResult<()> {
    check_location(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != euid() || meta.mode() & 0o777 != 0o700 {
        return Err(unsafe_layout(format!("{} must be a directory owned by this user with mode 0700", dir.display())));
    }
    Ok(())
}

/// lstat rules for a file the custody user owns alone.
fn owned_private(path: &Path) -> RResult<fs::Metadata> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.nlink() != 1 ||
       meta.uid() != euid() || meta.mode() & 0o077 != 0 {
        return Err(unsafe_layout(format!(
            "{} must be a regular file owned by this user, mode 0600 or 0400, with one link", path.display())));
    }
    Ok(meta)
}

/// Read a file checked by lstat, refusing one swapped between check and open.
fn read_checked(path: &Path, checked: &fs::Metadata, max: u64) -> RResult<Zeroizing<Vec<u8>>> {
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != checked.dev() || opened.ino() != checked.ino() || opened.len() > max {
        return Err(unsafe_layout(format!("{} changed while being read or is too large", path.display())));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(opened.len() as usize));
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn write_new_private(path: &Path, bytes: &[u8]) -> RResult<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_config(dir: &Path) -> RResult<CustodyConfig> {
    let path = dir.join(CONFIG);
    let meta = owned_private(&path).map_err(|e| match e {
        RuntimeError::Io(io) if io.kind() == ErrorKind::NotFound => unsafe_layout(format!(
            "{} is missing; provision with mpc-node or adopt the directory with `mpc-custody init`", path.display())),
        other => other,
    })?;
    let bytes = read_checked(&path, &meta, MAX_CONFIG)?;
    let config: CustodyConfig = serde_json::from_slice(&bytes).map_err(|_| RuntimeError::Wire("invalid custody.json"))?;
    config.validate(dir)?;
    Ok(config)
}

fn key_metadata(path: &Path, source: &KeySource) -> RResult<fs::Metadata> {
    match source {
        KeySource::StateDirectory => owned_private(path),
        KeySource::File { .. } => {
            check_location(path)?;
            let meta = fs::symlink_metadata(path)?;
            let mode = meta.mode();
            let owner_only = meta.uid() == euid() && mode & 0o077 == 0;
            let root_group = meta.uid() == 0 && mode & 0o037 == 0 && (mode & 0o040 == 0 || meta.gid() == egid());
            if !meta.is_file() || meta.file_type().is_symlink() || meta.nlink() != 1 || !(owner_only || root_group) {
                return Err(unsafe_layout(format!("{} must be a regular file with one link, owned by this user \
                    with mode 0400/0600, or by root with mode 0440 and this user's group", path.display())));
            }
            Ok(meta)
        }
        KeySource::SystemdCredential { .. } => {
            let meta = fs::symlink_metadata(path)?;
            if !meta.is_file() || meta.file_type().is_symlink() || !(meta.uid() == euid() || meta.uid() == 0) ||
               meta.mode() & 0o077 != 0 {
                return Err(unsafe_layout(format!("{} is not a private systemd credential", path.display())));
            }
            Ok(meta)
        }
    }
}

fn load_key(dir: &Path, config: &CustodyConfig) -> RResult<Zeroizing<[u8; 32]>> {
    let beside = dir.join(STATE_KEY);
    let path = match &config.master_key {
        KeySource::StateDirectory => beside,
        source => {
            if fs::symlink_metadata(&beside).is_ok() {
                return Err(unsafe_layout(format!("{} is still beside the journal; remove it once the \
                    external key source holds the key", beside.display())));
            }
            match source {
                KeySource::File { path } => path.clone(),
                KeySource::SystemdCredential { name } => {
                    let base = std::env::var_os(CREDENTIALS_ENV).map(PathBuf::from)
                        .filter(|p| p.is_absolute())
                        .ok_or_else(|| unsafe_layout(format!("{CREDENTIALS_ENV} is not set; run under systemd \
                            with LoadCredentialEncrypted={name}:...")))?;
                    let credential = base.join(name);
                    if config.layout != Layout::Development && inside(&credential, dir) {
                        return Err(unsafe_layout("separated credential must not resolve inside the state directory".into()));
                    }
                    credential
                }
                KeySource::StateDirectory => unreachable!(),
            }
        }
    };
    let meta = key_metadata(&path, &config.master_key)?;
    let bytes = read_checked(&path, &meta, 32)?;
    let key: [u8; 32] = bytes.as_slice().try_into()
        .map_err(|_| unsafe_layout(format!("{} must hold exactly 32 bytes", path.display())))?;
    let key = Zeroizing::new(key);
    if key.iter().all(|b| *b == 0) { return Err(RuntimeError::Wire("unprovisioned zero master key")); }
    Ok(key)
}

fn anchor_location(config: &CustodyConfig) -> RResult<()> {
    let anchor = &config.anchor;
    check_location(anchor)?;
    let meta = fs::symlink_metadata(anchor).map_err(|e| match e.kind() {
        ErrorKind::NotFound => RuntimeError::Rollback("anti-rollback anchor is missing"),
        _ => e.into(),
    })?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.nlink() != 1 ||
       meta.uid() != euid() || meta.mode() & 0o022 != 0 {
        return Err(unsafe_layout(format!("{} must be a regular file owned by this user, not writable \
            by group or others, with one link", anchor.display())));
    }
    if config.layout != Layout::Development {
        let parent_path = anchor.parent().unwrap_or(Path::new("/"));
        let parent = fs::symlink_metadata(parent_path)?;
        if !parent.is_dir() || parent.file_type().is_symlink() ||
           parent.uid() == euid() || parent.mode() & 0o022 != 0 ||
           (config.layout == Layout::Hardened && parent.uid() != 0) {
            return Err(unsafe_layout(format!("separated layout: the directory of {} must belong to another \
                user (root) and not be writable by the custody user", anchor.display())));
        }
    }
    Ok(())
}

fn journal_files(journal: &Path) -> RResult<()> {
    owned_private(journal)?;
    for suffix in ["-wal", "-shm"] {
        let mut side = journal.as_os_str().to_os_string();
        side.push(suffix);
        let side = PathBuf::from(side);
        match fs::symlink_metadata(&side) {
            Ok(meta) => if !meta.is_file() || meta.file_type().is_symlink() || meta.nlink() != 1 ||
                           meta.uid() != euid() || meta.mode() & 0o022 != 0 {
                return Err(unsafe_layout(format!("{} must be a private regular file", side.display())));
            },
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// A checked state directory, its configuration and its master key.
pub struct Custody { dir: PathBuf, config: CustodyConfig, key: Zeroizing<[u8; 32]> }

/// What `Custody::inspect` found, without changing anything.
pub struct Inspection {
    pub head: CustodyHead,
    pub anchor: AnchorScan,
    pub epochs: Vec<EpochRecord>,
}

pub struct BackupSummary { pub head_seq: u64, pub bytes: u64 }
pub struct RestoreSummary { pub head_seq: u64 }

impl Custody {
    /// Every check that must pass before a custody process touches state.
    pub fn load(dir: &Path) -> RResult<Self> {
        state_directory(dir)?;
        let config = read_config(dir)?;
        for path in &config.separate_from {
            if fs::metadata(path)?.uid() == euid() {
                return Err(unsafe_layout(format!("{} belongs to the custody user; the node, the signer and \
                    Lair must run as different users", path.display())));
            }
        }
        if config.layout == Layout::Hardened {
            // The ordered roots represent relay, Lair signer and conductor.
            // This checks filesystem ownership, not running process identity.
            let mut owners = Vec::new();
            for (role, path) in ["relay", "Lair signer", "conductor"].iter()
                .zip(&config.separate_from) {
                let meta = fs::symlink_metadata(path)?;
                if !meta.is_dir() || meta.file_type().is_symlink() ||
                   meta.uid() == 0 || meta.uid() == euid() ||
                   meta.mode() & 0o777 != 0o700 || owners.contains(&meta.uid()) {
                    return Err(unsafe_layout(format!(
                        "hardened {role} root {} must be 0700, non-symlinked and owned by a distinct non-root UID",
                        path.display())));
                }
                owners.push(meta.uid());
            }
        }
        anchor_location(&config)?;
        let key = load_key(dir, &config)?;
        Ok(Self { dir: dir.to_path_buf(), config, key })
    }
    pub fn dir(&self) -> &Path { &self.dir }
    pub fn config(&self) -> &CustodyConfig { &self.config }
    pub fn master_key(&self) -> MasterKey { MasterKey::from_bytes(*self.key) }
    pub fn journal_path(&self) -> PathBuf { self.dir.join(JOURNAL) }

    /// The existing journal, anchored. Refused if it is older than the anchor.
    pub fn open_journal(&self) -> RResult<RuntimeStore> {
        let journal = self.journal_path();
        journal_files(&journal)?;
        RuntimeStore::open_anchored(&journal, self.master_key(), &self.config.anchor)
    }

    /// Before a DKG starts: an existing journal must pass the anchor check,
    /// and a missing one is only acceptable while the anchor holds no history.
    pub fn preflight(&self) -> RResult<()> {
        if fs::symlink_metadata(self.journal_path()).is_ok() {
            drop(self.open_journal()?);
            return Ok(());
        }
        let scan = Anchor::open(&self.config.anchor)?.scan(&self.master_key())?;
        if scan.last.seq != 0 {
            return Err(RuntimeError::Rollback("journal is missing but its anchor records history"));
        }
        Ok(())
    }

    /// Read-only audit: the same anchor comparison as `open_journal`, but
    /// nothing is bound, appended or created.
    pub fn inspect(&self) -> RResult<Inspection> {
        let journal = self.journal_path();
        journal_files(&journal)?;
        let conn = Connection::open_with_flags(&journal, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let anchor = Anchor::open(&self.config.anchor)?;
        let (head, scan) = chain::inspect(&conn, &self.master_key(), &anchor)?;
        Ok(Inspection { head, anchor: scan, epochs: lifecycle::list(&conn)? })
    }

    /// Write an encrypted backup of this node's custody state to `out`: the
    /// journal (sealed shares, nonce and operation journal, custody chain),
    /// custody.json, node.json and the group descriptor. Not included: the
    /// master key (back it up separately), ipc.key and transport.sqlite.
    pub fn backup(&self, out: &Path) -> RResult<BackupSummary> {
        if !normal_absolute(out) || inside(out, &self.dir) {
            return Err(RuntimeError::Wire("the backup must be an absolute path outside the state directory"));
        }
        // Anchors any lagging commits and refuses an already rolled-back journal.
        let store = self.open_journal()?;
        let mut tag = [0_u8; 8];
        OsRng.fill_bytes(&mut tag);
        let snapshot = self.dir.join(format!(".custody-backup-{}.sqlite", hex(&tag)));
        let taken = (|| -> RResult<(CustodyHead, Zeroizing<Vec<u8>>)> {
            let target = snapshot.to_str().ok_or(RuntimeError::Wire("non UTF-8 state directory"))?;
            store.connection.execute("VACUUM INTO ?1", [target])?;
            let head = chain::read_head(&Connection::open(&snapshot)?, &self.master_key())?;
            let meta = fs::symlink_metadata(&snapshot)?;
            Ok((head, read_checked(&snapshot, &meta, MAX_FILE)?))
        })();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut path = snapshot.as_os_str().to_os_string();
            path.push(suffix);
            let _ = fs::remove_file(PathBuf::from(path));
        }
        let (head, journal) = taken?;
        drop(store);
        let mut files: Vec<(&str, Zeroizing<Vec<u8>>)> = vec![(JOURNAL, journal)];
        for name in [CONFIG, NODE_CONFIG, DESCRIPTOR] {
            let path = self.dir.join(name);
            match owned_private(&path) {
                Ok(meta) => files.push((name, read_checked(&path, &meta, MAX_FILE)?)),
                Err(RuntimeError::Io(e)) if e.kind() == ErrorKind::NotFound && name == DESCRIPTOR => {}
                Err(e) => return Err(e),
            }
        }
        let header = BundleHeader { schema: 1, head_seq: head.seq,
            anchor_id: hex(&head.anchor_id.ok_or(RuntimeError::Rollback("journal is not anchored"))?),
            master_key: self.config.master_key.clone() };
        let bundle = seal_bundle(&self.master_key(), &header, &files)?;
        write_new_private(out, &bundle)?;
        if let Some(parent) = out.parent() { File::open(parent)?.sync_all()?; }
        Ok(BackupSummary { head_seq: head.seq, bytes: bundle.len() as u64 })
    }

    /// Erase the shares of epochs retired longer ago than
    /// `retired_share_retention_days`. Returns the erased (proposal, epoch).
    pub fn apply_retention(&self, now_ms: i64) -> RResult<Vec<(Vec<u8>, u64)>> {
        let days = self.config.retired_share_retention_days
            .ok_or(RuntimeError::Wire("custody.json sets no retired_share_retention_days"))?;
        let mut store = self.open_journal()?;
        let due: Vec<EpochRecord> = store.epochs()?.into_iter().filter(|e| e.state == EpochState::Retired &&
            e.retired_ms.is_some_and(|t| t.saturating_add(i64::from(days) * MS_PER_DAY) <= now_ms)).collect();
        for epoch in &due { store.erase_share(&epoch.proposal, epoch.epoch, now_ms)?; }
        Ok(due.into_iter().map(|e| (e.proposal, e.epoch)).collect())
    }
}

/// Called by `mpc-node provision` right after it writes `storage.key`: write
/// the development `custody.json` and create the anchor beside the directory.
/// An existing anchor is evidence of an earlier directory: it is refused.
pub fn provision(state_dir: &Path, key: &[u8; 32]) -> RResult<CustodyConfig> {
    state_directory(state_dir)?;
    let config = CustodyConfig::development(state_dir)?;
    config.validate(state_dir)?;
    Anchor::create(&config.anchor, &MasterKey::from_bytes(*key))?;
    write_new_private(&state_dir.join(CONFIG), &serde_json::to_vec_pretty(&config)
        .map_err(|_| RuntimeError::Wire("custody.json encoding"))?)?;
    Ok(config)
}

/// Adopt a state directory provisioned before custody hardening (it has no
/// custody.json). Trust on first use: the journal is anchored as it stands,
/// so a rollback that happened BEFORE adoption cannot be detected.
pub fn adopt(state_dir: &Path, config: &CustodyConfig) -> RResult<()> {
    state_directory(state_dir)?;
    config.validate(state_dir)?;
    if fs::symlink_metadata(state_dir.join(CONFIG)).is_ok() {
        return Err(RuntimeError::Conflict("custody.json already exists"));
    }
    let key = load_key(state_dir, config)?;
    Anchor::create(&config.anchor, &MasterKey::from_bytes(*key))?;
    write_new_private(&state_dir.join(CONFIG), &serde_json::to_vec_pretty(config)
        .map_err(|_| RuntimeError::Wire("custody.json encoding"))?)?;
    File::open(state_dir)?.sync_all()?;
    let custody = Custody::load(state_dir)?;
    if fs::symlink_metadata(custody.journal_path()).is_ok() { drop(custody.open_journal()?); }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleHeader { schema: u16, head_seq: u64, anchor_id: String, master_key: KeySource }

fn seal_bundle(key: &MasterKey, header: &BundleHeader, files: &[(&str, Zeroizing<Vec<u8>>)]) -> RResult<Vec<u8>> {
    let mut clear = Zeroizing::new(Vec::new());
    for (name, data) in files {
        clear.extend_from_slice(&(name.len() as u16).to_be_bytes());
        clear.extend_from_slice(name.as_bytes());
        clear.extend_from_slice(&(data.len() as u64).to_be_bytes());
        clear.extend_from_slice(data);
    }
    let mut aad = BUNDLE_MAGIC.to_vec();
    aad.extend_from_slice(&serde_json::to_vec(header).map_err(|_| RuntimeError::Wire("backup header"))?);
    aad.push(b'\n');
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0[..]).map_err(|_| RuntimeError::Crypto)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, Payload { msg: &clear, aad: &aad }).map_err(|_| RuntimeError::Crypto)?;
    let mut out = aad;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

type BundleFiles = Vec<(String, Zeroizing<Vec<u8>>)>;
fn open_bundle(key: &MasterKey, bytes: &[u8]) -> RResult<(BundleHeader, BundleFiles)> {
    let invalid = || RuntimeError::Wire("not a custody backup");
    let rest = bytes.strip_prefix(BUNDLE_MAGIC).ok_or_else(invalid)?;
    let end = rest.iter().take(4096).position(|b| *b == b'\n').ok_or_else(invalid)?;
    let header: BundleHeader = serde_json::from_slice(&rest[..end]).map_err(|_| invalid())?;
    let aad = &bytes[..BUNDLE_MAGIC.len() + end + 1];
    let body = &rest[end + 1..];
    if header.schema != 1 || body.len() < 24 { return Err(invalid()); }
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0[..]).map_err(|_| RuntimeError::Crypto)?;
    let clear = Zeroizing::new(cipher.decrypt(XNonce::from_slice(&body[..24]),
        Payload { msg: &body[24..], aad }).map_err(|_| RuntimeError::Crypto)?);
    fn take<'a>(clear: &'a [u8], at: &mut usize, n: usize) -> RResult<&'a [u8]> {
        let end = at.checked_add(n).ok_or(RuntimeError::Wire("not a custody backup"))?;
        let slice = clear.get(*at..end).ok_or(RuntimeError::Wire("not a custody backup"))?;
        *at = end;
        Ok(slice)
    }
    let mut files: BundleFiles = Vec::new();
    let mut at = 0_usize;
    while at < clear.len() {
        let name_len = u16::from_be_bytes(take(&clear, &mut at, 2)?.try_into().map_err(|_| invalid())?) as usize;
        let name = String::from_utf8(take(&clear, &mut at, name_len)?.to_vec()).map_err(|_| invalid())?;
        let data_len = usize::try_from(u64::from_be_bytes(take(&clear, &mut at, 8)?.try_into().map_err(|_| invalid())?))
            .map_err(|_| invalid())?;
        let data = Zeroizing::new(take(&clear, &mut at, data_len)?.to_vec());
        if ![JOURNAL, CONFIG, NODE_CONFIG, DESCRIPTOR].contains(&name.as_str()) ||
           files.iter().any(|(seen, _)| *seen == name) {
            return Err(RuntimeError::Wire("unexpected file in custody backup"));
        }
        files.push((name, data));
    }
    Ok((header, files))
}

/// Restore an encrypted backup into `state_dir`, which must not exist. The
/// operator supplies the master key from its own, separate backup. Refused
/// unless the backup's anti-rollback anchor still exists and the restored
/// journal is not older than it: a backup taken before this node's latest
/// signing, retirement or erasure is never accepted. Nothing is left behind
/// on refusal; the directory appears only after every check passed.
pub fn restore(bundle: &Path, state_dir: &Path, key: &[u8; 32]) -> RResult<RestoreSummary> {
    check_location(state_dir)?;
    if !normal_absolute(state_dir) || fs::symlink_metadata(state_dir).is_ok() {
        return Err(RuntimeError::Wire("restore into an absolute path that does not exist yet"));
    }
    let (Some(parent), Some(name)) = (state_dir.parent(), state_dir.file_name()) else {
        return Err(RuntimeError::Wire("restore target needs a parent directory"));
    };
    let meta = fs::symlink_metadata(bundle)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(unsafe_layout(format!("{} must be a regular file", bundle.display())));
    }
    let master = MasterKey::from_bytes(*key);
    let (header, files) = open_bundle(&master, &read_checked(bundle, &meta, MAX_BUNDLE)?)?;
    let file = |name: &str| files.iter().find(|(n, _)| n == name).map(|(_, d)| d);
    let (Some(config_bytes), Some(_), Some(_)) = (file(CONFIG), file(NODE_CONFIG), file(JOURNAL)) else {
        return Err(RuntimeError::Wire("custody backup is incomplete"));
    };
    let config: CustodyConfig = serde_json::from_slice(config_bytes)
        .map_err(|_| RuntimeError::Wire("invalid custody.json in backup"))?;
    config.validate(state_dir)?;
    if config.master_key != header.master_key { return Err(RuntimeError::Wire("backup header disagrees with custody.json")); }
    let anchor = Anchor::open(&config.anchor)
        .map_err(|_| RuntimeError::Rollback("the backup's anti-rollback anchor is missing; refusing to restore"))?;
    if unhex::<32>(&header.anchor_id) != Some(anchor.id()) {
        return Err(RuntimeError::Rollback("backup belongs to a different anti-rollback anchor"));
    }
    if header.head_seq < anchor.scan(&master)?.last.seq {
        return Err(RuntimeError::Rollback("backup is older than its anti-rollback anchor"));
    }
    let mut tag = [0_u8; 8];
    OsRng.fill_bytes(&mut tag);
    let staging = parent.join(format!(".{}.restore-{}", name.to_string_lossy(), hex(&tag)));
    DirBuilder::new().mode(0o700).create(&staging)?;
    let staged = (|| -> RResult<CustodyHead> {
        for (name, data) in &files { write_new_private(&staging.join(name), data)?; }
        if config.master_key == KeySource::StateDirectory { write_new_private(&staging.join(STATE_KEY), key)?; }
        // The full check: the restored chain must not be behind the anchor.
        let store = RuntimeStore::open_anchored(&staging.join(JOURNAL), MasterKey::from_bytes(*key), &config.anchor)?;
        let head = store.custody_head()?;
        drop(store);
        File::open(&staging)?.sync_all()?;
        Ok(head)
    })();
    let head = match staged {
        Ok(head) => head,
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
    };
    fs::rename(&staging, state_dir)?;
    File::open(parent)?.sync_all()?;
    Ok(RestoreSummary { head_seq: head.seq })
}

/// Read a 32-byte master key from an operator-held file (for `restore`).
pub fn read_key_file(path: &Path) -> RResult<Zeroizing<[u8; 32]>> {
    let meta = owned_private(path)?;
    let bytes = read_checked(path, &meta, 32)?;
    let key: [u8; 32] = bytes.as_slice().try_into()
        .map_err(|_| unsafe_layout(format!("{} must hold exactly 32 bytes", path.display())))?;
    Ok(Zeroizing::new(key))
}
