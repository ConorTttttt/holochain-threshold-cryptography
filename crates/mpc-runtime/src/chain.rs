//! v0.4.0 Phase 7 hardening: an authenticated custody chain inside the
//! journal, and an external append-only anchor file outside it.
//!
//! Every committed journal write appends one event to `custody_log` and
//! advances `custody_head` in the SAME SQLite transaction. The head carries an
//! XChaCha20-Poly1305 tag under the node master key, so nobody without the key
//! can move it. Each event mixes in a fresh random salt, so replaying the same
//! writes after a restore still produces a different chain.
//!
//! After the commit, and before the write method returns, the head is
//! appended to the anchor file (an `flock`ed, authenticated text log). A
//! journal whose head is behind the last anchor record, differs from it or
//! does not extend it is refused. A journal AHEAD of the anchor is normal
//! after a crash between the commit and the append, or after writes through a
//! store opened without an anchor; its log must still extend the anchor.
//!
//! The anchor is only as strong as its placement. It must live where a
//! restore of the state directory or journal cannot rewind it (other storage,
//! a directory the custody user cannot write, `chattr +a`). NOT detected: a
//! restore that rewinds the journal AND the anchor together (a whole-disk or
//! VM snapshot), or anyone holding the master key with write access to both.
use super::{MasterKey, RResult, RuntimeError};
use chacha20poly1305::{aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce};
use holochain_mpc_core::commitment;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) const TABLES: &str = "CREATE TABLE IF NOT EXISTS custody_head (
      id INTEGER PRIMARY KEY CHECK (id = 1), seq INTEGER NOT NULL, chain BLOB NOT NULL,
      anchor_id BLOB, nonce BLOB NOT NULL, tag BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS custody_log (
      seq INTEGER PRIMARY KEY, label TEXT NOT NULL, event BLOB NOT NULL,
      salt BLOB NOT NULL, chain BLOB NOT NULL);";

const ANCHOR_MAGIC: &str = "holochain-mpc custody-anchor v1";
const MAX_ANCHOR_BYTES: u64 = 64 * 1024 * 1024;

/// The authenticated position of a journal's custody chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustodyHead {
    pub seq: u64,
    pub chain: [u8; 32],
    /// The anchor this journal is bound to, once it has been opened anchored.
    pub anchor_id: Option<[u8; 32]>,
}

/// One authenticated anchor record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorRecord { pub seq: u64, pub chain: [u8; 32] }

/// A verified read of the whole anchor file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorScan {
    pub last: AnchorRecord,
    pub records: usize,
    /// Lines that are not records, such as a write torn by a crash. Without
    /// the key they cannot hold a valid record, so they are skipped.
    pub skipped_lines: usize,
    ends_with_newline: bool,
}

pub(crate) fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
pub(crate) fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 { return None; }
    let mut out = [0_u8; N];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn framed(domain: &[u8], items: &[&[u8]]) -> Vec<u8> {
    let mut out = domain.to_vec();
    for item in items {
        out.extend_from_slice(&(item.len() as u64).to_be_bytes());
        out.extend_from_slice(item);
    }
    out
}
fn genesis() -> [u8; 32] { commitment("custody-chain-genesis-v1", b"") }
fn next_chain(prev: &[u8; 32], seq: u64, label: &str, event: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
    commitment("custody-chain-v1", &framed(b"", &[prev, &seq.to_be_bytes(), label.as_bytes(), event, salt]))
}
fn head_aad(seq: u64, chain: &[u8; 32], anchor_id: &Option<[u8; 32]>) -> Vec<u8> {
    let anchor: &[u8] = match anchor_id { Some(id) => id, None => &[] };
    framed(b"holochain-mpc/custody-head/v1", &[&seq.to_be_bytes(), chain, anchor])
}
fn record_aad(anchor_id: &[u8; 32], seq: u64, chain: &[u8; 32]) -> Vec<u8> {
    framed(b"holochain-mpc/custody-anchor/v1", &[anchor_id, &seq.to_be_bytes(), chain])
}
/// A tag over `aad` alone: AEAD of an empty message under a fresh nonce.
fn tag(key: &MasterKey, aad: &[u8]) -> RResult<([u8; 24], [u8; 16])> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0[..]).map_err(|_| RuntimeError::Crypto)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let tag = cipher.encrypt(&nonce, Payload { msg: b"", aad }).map_err(|_| RuntimeError::Crypto)?;
    let mut fixed = [0_u8; 24];
    fixed.copy_from_slice(&nonce);
    Ok((fixed, tag.try_into().map_err(|_| RuntimeError::Crypto)?))
}
fn check_tag(key: &MasterKey, aad: &[u8], nonce: &[u8], tag: &[u8]) -> RResult<()> {
    if nonce.len() != 24 || tag.len() != 16 { return Err(RuntimeError::Crypto); }
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0[..]).map_err(|_| RuntimeError::Crypto)?;
    cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: tag, aad }).map_err(|_| RuntimeError::Crypto)?;
    Ok(())
}
fn seq_i64(seq: u64) -> RResult<i64> {
    i64::try_from(seq).map_err(|_| RuntimeError::Wire("custody chain overflow"))
}

/// Create the genesis head of a new journal. An existing head is kept.
pub(crate) fn init_head(conn: &Connection, key: &MasterKey) -> RResult<()> {
    if conn.query_row("SELECT 1 FROM custody_head WHERE id=1", [], |_| Ok(())).optional()?.is_some() {
        return Ok(());
    }
    let chain = genesis();
    let (nonce, tag) = tag(key, &head_aad(0, &chain, &None))?;
    conn.execute("INSERT OR IGNORE INTO custody_head (id,seq,chain,anchor_id,nonce,tag) VALUES (1,0,?1,NULL,?2,?3)",
        params![chain.as_slice(), nonce.as_slice(), tag.as_slice()])?;
    Ok(())
}

/// Read and authenticate the head. A wrong master key fails here.
pub(crate) fn read_head(conn: &Connection, key: &MasterKey) -> RResult<CustodyHead> {
    let row: Option<(i64, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Vec<u8>)> = conn.query_row(
        "SELECT seq, chain, anchor_id, nonce, tag FROM custody_head WHERE id=1", [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).optional()?;
    let Some((seq, chain, anchor_id, nonce, tag)) = row else {
        return Err(RuntimeError::Rollback("journal has no custody chain"));
    };
    let seq = u64::try_from(seq).map_err(|_| RuntimeError::Rollback("custody chain position invalid"))?;
    let chain: [u8; 32] = chain.try_into().map_err(|_| RuntimeError::Rollback("custody chain head invalid"))?;
    let anchor_id = match anchor_id {
        Some(id) => Some(<[u8; 32]>::try_from(id).map_err(|_| RuntimeError::Rollback("custody anchor binding invalid"))?),
        None => None,
    };
    check_tag(key, &head_aad(seq, &chain, &anchor_id), &nonce, &tag)?;
    Ok(CustodyHead { seq, chain, anchor_id })
}

/// Append one event to the custody chain inside the caller's transaction.
/// The caller commits, then records the new head in the anchor.
pub(crate) fn log_event(tx: &Connection, key: &MasterKey, label: &str, parts: &[&[u8]]) -> RResult<()> {
    let head = read_head(tx, key)?;
    write_next(tx, key, &head, label, parts, head.anchor_id)
}
fn write_next(tx: &Connection, key: &MasterKey, head: &CustodyHead, label: &str, parts: &[&[u8]],
              anchor_id: Option<[u8; 32]>) -> RResult<()> {
    let seq = head.seq.checked_add(1).ok_or(RuntimeError::Wire("custody chain overflow"))?;
    let event = commitment("custody-event-v1", &framed(b"", parts));
    let mut salt = [0_u8; 16];
    OsRng.fill_bytes(&mut salt);
    let chain = next_chain(&head.chain, seq, label, &event, &salt);
    let (nonce, tag) = tag(key, &head_aad(seq, &chain, &anchor_id))?;
    tx.execute("INSERT INTO custody_log (seq,label,event,salt,chain) VALUES (?1,?2,?3,?4,?5)",
        params![seq_i64(seq)?, label, event.as_slice(), salt.as_slice(), chain.as_slice()])?;
    let written = tx.execute("UPDATE custody_head SET seq=?1, chain=?2, anchor_id=?3, nonce=?4, tag=?5
        WHERE id=1 AND seq=?6", params![seq_i64(seq)?, chain.as_slice(),
        anchor_id.as_ref().map(|id| id.as_slice()), nonce.as_slice(), tag.as_slice(), seq_i64(head.seq)?])?;
    if written != 1 { return Err(RuntimeError::Conflict("concurrent custody chain update")); }
    Ok(())
}

/// True if the logged events after `from` lead exactly to `head`.
fn extends(conn: &Connection, from: &AnchorRecord, head: &CustodyHead) -> RResult<bool> {
    let mut statement = conn.prepare(
        "SELECT seq, label, event, salt FROM custody_log WHERE seq > ?1 AND seq <= ?2 ORDER BY seq")?;
    let rows = statement.query_map(params![seq_i64(from.seq)?, seq_i64(head.seq)?],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?, r.get::<_, Vec<u8>>(3)?)))?;
    let (mut chain, mut seq) = (from.chain, from.seq);
    for row in rows {
        let (at, label, event, salt) = row?;
        seq += 1;
        let (Ok(event), Ok(salt)) = (<[u8; 32]>::try_from(event), <[u8; 16]>::try_from(salt)) else { return Ok(false) };
        if at != seq_i64(seq)? { return Ok(false); }
        chain = next_chain(&chain, seq, &label, &event, &salt);
    }
    Ok(seq == head.seq && chain == head.chain)
}
fn compare(conn: &Connection, head: &CustodyHead, last: &AnchorRecord) -> RResult<()> {
    if head.seq < last.seq {
        Err(RuntimeError::Rollback("journal is older than its anti-rollback anchor"))
    } else if head.seq == last.seq && head.chain != last.chain {
        Err(RuntimeError::Rollback("journal history differs from its anti-rollback anchor"))
    } else if head.seq > last.seq && !extends(conn, last, head)? {
        Err(RuntimeError::Rollback("journal history does not extend its anti-rollback anchor"))
    } else {
        Ok(())
    }
}

/// The startup and post-commit check. Under the anchor's exclusive lock:
/// verify every anchor record, refuse a journal behind or diverged from the
/// last one, bind an unbound journal, and append the head if it is ahead.
pub(crate) fn reconcile(conn: &mut Connection, key: &MasterKey, anchor: &Anchor) -> RResult<CustodyHead> {
    let mut file = anchor.lock(true)?;
    let scan = anchor.scan_file(&mut file, key)?;
    let mut head = read_head(conn, key)?;
    if head.anchor_id.is_some_and(|id| id != anchor.id) {
        return Err(RuntimeError::Rollback("journal is bound to a different anti-rollback anchor"));
    }
    compare(conn, &head, &scan.last)?;
    if head.anchor_id.is_none() {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = read_head(&tx, key)?;
        if current.anchor_id.is_none() {
            write_next(&tx, key, &current, "bind-anchor", &[&anchor.id], Some(anchor.id))?;
        }
        tx.commit()?;
        head = read_head(conn, key)?;
        if head.anchor_id != Some(anchor.id) {
            return Err(RuntimeError::Rollback("journal is bound to a different anti-rollback anchor"));
        }
        compare(conn, &head, &scan.last)?;
    }
    if head.seq > scan.last.seq {
        anchor.append(&mut file, key, &scan, &head)?;
    }
    Ok(head)
}

/// Read-only form of `reconcile` for audits: nothing is bound or appended.
pub(crate) fn inspect(conn: &Connection, key: &MasterKey, anchor: &Anchor) -> RResult<(CustodyHead, AnchorScan)> {
    let mut file = anchor.lock(false)?;
    let scan = anchor.scan_file(&mut file, key)?;
    let head = read_head(conn, key)?;
    if head.anchor_id.is_some_and(|id| id != anchor.id) {
        return Err(RuntimeError::Rollback("journal is bound to a different anti-rollback anchor"));
    }
    compare(conn, &head, &scan.last)?;
    Ok((head, scan))
}

/// The external anti-rollback anchor of one journal: a header naming a random
/// anchor id, then one authenticated `seq chain nonce tag` line per record.
/// Records must strictly increase, so an old record appended again (a replay)
/// is refused rather than read as the latest.
pub struct Anchor { path: PathBuf, id: [u8; 32] }

impl Anchor {
    /// Initialise a new anchor at `path`, or in an EMPTY file prepared there
    /// by an administrator (for example owned by the custody user inside a
    /// root-owned directory, with `chattr +a` already set).
    pub fn create(path: &Path, key: &MasterKey) -> RResult<Self> {
        if !path.is_absolute() { return Err(RuntimeError::Unsafe("anchor path must be absolute".into())); }
        let mut file = match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_file() && meta.len() == 0 => OpenOptions::new().append(true).open(path)?,
            Ok(_) => return Err(RuntimeError::Conflict("anchor already exists; it is evidence and is never replaced")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut options = OpenOptions::new();
                options.append(true).create_new(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
                options.open(path)?
            }
            Err(e) => return Err(e.into()),
        };
        let mut id = [0_u8; 32];
        OsRng.fill_bytes(&mut id);
        let genesis = AnchorRecord { seq: 0, chain: genesis() };
        let mut text = format!("{ANCHOR_MAGIC} {}\n", hex(&id));
        text.push_str(&record_line(key, &id, &genesis)?);
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        if let Some(parent) = path.parent() { File::open(parent)?.sync_all()?; }
        Ok(Self { path: path.to_path_buf(), id })
    }

    /// Open an existing anchor. It must be a regular file, not a symlink.
    pub fn open(path: &Path) -> RResult<Self> {
        let meta = fs::symlink_metadata(path)
            .map_err(|_| RuntimeError::Rollback("anti-rollback anchor is missing"))?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err(RuntimeError::Unsafe(format!("{} must be a regular file, not a symlink", path.display())));
        }
        let mut header = String::new();
        File::open(path)?.take(256).read_to_string(&mut header)
            .map_err(|_| RuntimeError::Rollback("anti-rollback anchor header is invalid"))?;
        let line = header.split('\n').next().unwrap_or_default();
        let id = line.strip_prefix(ANCHOR_MAGIC).and_then(|rest| rest.strip_prefix(' '))
            .and_then(unhex::<32>)
            .ok_or(RuntimeError::Rollback("anti-rollback anchor header is invalid"))?;
        Ok(Self { path: path.to_path_buf(), id })
    }

    pub fn id(&self) -> [u8; 32] { self.id }
    pub fn path(&self) -> &Path { &self.path }

    /// Verify every record and return the latest. Takes a shared lock.
    pub fn scan(&self, key: &MasterKey) -> RResult<AnchorScan> {
        let mut file = self.lock(false)?;
        self.scan_file(&mut file, key)
    }

    /// Open and `flock` the anchor, refusing a file swapped since `open`.
    fn lock(&self, exclusive: bool) -> RResult<File> {
        let file = OpenOptions::new().read(true).append(exclusive).open(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let (opened, named) = (file.metadata()?, fs::symlink_metadata(&self.path)?);
            if named.file_type().is_symlink() || opened.dev() != named.dev() || opened.ino() != named.ino() {
                return Err(RuntimeError::Unsafe(format!("{} changed while being opened", self.path.display())));
            }
        }
        if exclusive { file.lock()? } else { file.lock_shared()? }
        Ok(file)
    }

    fn scan_file(&self, file: &mut File, key: &MasterKey) -> RResult<AnchorScan> {
        if file.metadata()?.len() > MAX_ANCHOR_BYTES {
            return Err(RuntimeError::Rollback("anti-rollback anchor is too large"));
        }
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let text = String::from_utf8_lossy(&bytes);
        let mut lines = text.split('\n');
        let header = lines.next().unwrap_or_default();
        if header != format!("{ANCHOR_MAGIC} {}", hex(&self.id)) {
            return Err(RuntimeError::Rollback("anti-rollback anchor header changed"));
        }
        let ends_with_newline = bytes.last() == Some(&b'\n');
        let mut lines: Vec<&str> = lines.collect();
        if ends_with_newline { lines.pop(); }
        let (mut last, mut records, mut skipped_lines): (Option<AnchorRecord>, usize, usize) = (None, 0, 0);
        for line in lines {
            let Some((record, nonce, tag)) = parse_record(line) else { skipped_lines += 1; continue };
            check_tag(key, &record_aad(&self.id, record.seq, &record.chain), &nonce, &tag)
                .map_err(|_| RuntimeError::Rollback("anti-rollback anchor record is not authentic"))?;
            if last.is_some_and(|previous| record.seq <= previous.seq) {
                return Err(RuntimeError::Rollback("anti-rollback anchor records go backwards"));
            }
            last = Some(record);
            records += 1;
        }
        let last = last.ok_or(RuntimeError::Rollback("anti-rollback anchor has no records"))?;
        Ok(AnchorScan { last, records, skipped_lines, ends_with_newline })
    }

    fn append(&self, file: &mut File, key: &MasterKey, scan: &AnchorScan, head: &CustodyHead) -> RResult<()> {
        let mut line = String::new();
        // Terminate a line torn by a crash, so this record stays parseable.
        if !scan.ends_with_newline { line.push('\n'); }
        line.push_str(&record_line(key, &self.id, &AnchorRecord { seq: head.seq, chain: head.chain })?);
        file.write_all(line.as_bytes())?;
        file.sync_data()?;
        Ok(())
    }
}

fn record_line(key: &MasterKey, anchor_id: &[u8; 32], record: &AnchorRecord) -> RResult<String> {
    let (nonce, tag) = tag(key, &record_aad(anchor_id, record.seq, &record.chain))?;
    Ok(format!("{} {} {} {}\n", record.seq, hex(&record.chain), hex(&nonce), hex(&tag)))
}
fn parse_record(line: &str) -> Option<(AnchorRecord, [u8; 24], [u8; 16])> {
    let mut fields = line.split(' ');
    let seq = fields.next()?;
    if seq.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit()) { return None; }
    let record = AnchorRecord { seq: seq.parse().ok()?, chain: unhex(fields.next()?)? };
    let nonce = unhex(fields.next()?)?;
    let tag = unhex(fields.next()?)?;
    if fields.next().is_some() { return None; }
    Some((record, nonce, tag))
}
