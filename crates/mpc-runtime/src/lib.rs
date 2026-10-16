//! Native security-sensitive state controller, separate from Holochain WASM.
//!
//! SECURITY MODEL:
//! - All message ids and *database-side* effects are committed in one SQLite
//!   `BEGIN IMMEDIATE` transaction. External network calls never run inside it.
//! - `reserve_nonce` is durable BEFORE calling FROST round1::commit; a nonce is
//!   never recovered from storage. An interrupted attempt is irreversibly lost.
//! - `authorize_commitment` fsyncs a burn record BEFORE releasing commitments.
//! - Encrypted share storage uses an externally provisioned 256-bit master key.
//!   The app must protect/rotate/back up that key using an OS/Lair HSM backend.
//! - This is NOT a hardware anti-rollback system. Copying back an old DB and
//!   reusing old key material must be prevented by the deployment environment.
use chacha20poly1305::{aead::{Aead, AeadCore, KeyInit, OsRng, Payload}, XChaCha20Poly1305};
use holochain_mpc_core::{commitment, Envelope, SessionSpec};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::{fmt, path::Path};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug)]
pub enum RuntimeError {
    Sql(rusqlite::Error),
    Wire(&'static str),
    Conflict(&'static str),
    Aborted,
    Crypto,
}
impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sql(e) => write!(f, "database error: {e}"),
            Self::Wire(s) => write!(f, "invalid authenticated input: {s}"),
            Self::Conflict(s) => write!(f, "persistent conflict: {s}"),
            Self::Aborted => write!(f, "operation aborted or expired"),
            Self::Crypto => write!(f, "decryption or encryption failed"),
        }
    }
}
impl std::error::Error for RuntimeError {}
impl From<rusqlite::Error> for RuntimeError { fn from(x: rusqlite::Error) -> Self { Self::Sql(x) } }

pub type RResult<T> = Result<T, RuntimeError>;

pub struct MasterKey(Zeroizing<[u8;32]>);
impl MasterKey {
    /// Caller must provide a high-entropy key from a trusted key manager;
    /// never use a password or the Holochain agent public key as a master key.
    pub fn from_bytes(key: [u8;32]) -> Self { Self(Zeroizing::new(key)) }
}

pub struct RuntimeStore {
    connection: Connection,
    key: MasterKey,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received { Inserted, Duplicate }

/// Caller must authenticate `sender` from remote-call provenance (or preserve
/// that provenance in a signed receipt). A raw inbox payload is NOT an
/// authenticated sender assertion.
impl RuntimeStore {
    pub fn open(path: &Path, key: MasterKey) -> RResult<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS messages (
              proposal BLOB NOT NULL, sender BLOB NOT NULL,
              round INTEGER NOT NULL, seq INTEGER NOT NULL,
              digest BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'received',
              PRIMARY KEY (proposal, sender, round, seq)
            );
            CREATE TABLE IF NOT EXISTS nonces (
              proposal BLOB NOT NULL, epoch INTEGER NOT NULL, operation BLOB NOT NULL,
              signer BLOB NOT NULL, state TEXT NOT NULL,
              commitment_hash BLOB,
              PRIMARY KEY (proposal, epoch, operation, signer)
            );
            CREATE TABLE IF NOT EXISTS secrets (
              proposal BLOB NOT NULL, epoch INTEGER NOT NULL, owner BLOB NOT NULL,
              group_digest BLOB NOT NULL, nonce BLOB NOT NULL,
              ciphertext BLOB NOT NULL,
              PRIMARY KEY (proposal, epoch, owner)
            );
            CREATE TABLE IF NOT EXISTS lifecycles (
              proposal BLOB NOT NULL, operation BLOB NOT NULL,
              deadline_ms INTEGER NOT NULL, state TEXT NOT NULL,
              reason TEXT,
              PRIMARY KEY (proposal, operation)
            );
            CREATE TABLE IF NOT EXISTS activations (
              proposal BLOB NOT NULL, epoch INTEGER NOT NULL,
              certificate_digest BLOB NOT NULL,
              PRIMARY KEY(proposal, epoch)
            );")?;
        Ok(Self { connection: conn, key })
    }
    fn transaction(&mut self) -> RResult<Transaction<'_>> {
        Ok(self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?)
    }
    /// Accept a payload and apply *database-only* effects in ONE transaction.
    /// Duplicate receipt does not rerun side effects. Conflicting payload for
    /// the same logical slot is rejected (not silently treated as a retry).
    pub fn apply_received<F>(&mut self, proposal: &[u8], spec: &SessionSpec,
                             local_recipient: &[u8], authenticated_sender: &[u8],
                             envelope: &Envelope, apply: F) -> RResult<Received>
    where F: FnOnce(&Transaction<'_>) -> RResult<()> {
        envelope.validate_received(spec, local_recipient, authenticated_sender)
            .map_err(|_| RuntimeError::Wire("invalid envelope or authenticated origin"))?;
        if proposal.is_empty() { return Err(RuntimeError::Wire("missing proposal action")); }
        let seq = i64::try_from(envelope.sequence).map_err(|_| RuntimeError::Wire("sequence overflow"))?;
        let digest = commitment("durable-envelope-v1", &serde_json::to_vec(envelope)
            .map_err(|_| RuntimeError::Wire("invalid serialization"))?);
        let tx = self.transaction()?;
        let previous: Option<Vec<u8>> = tx.query_row(
            "SELECT digest FROM messages WHERE proposal=?1 AND sender=?2 AND round=?3 AND seq=?4",
            params![proposal, authenticated_sender, i64::from(envelope.round), seq],
            |r| r.get(0)).optional()?;
        if let Some(previous) = previous {
            return if previous.as_slice() == digest.as_slice() { Ok(Received::Duplicate) }
                   else { Err(RuntimeError::Conflict("same sender/round/sequence, different ciphertext")) };
        }
        tx.execute("INSERT INTO messages (proposal,sender,round,seq,digest) VALUES (?1,?2,?3,?4,?5)",
            params![proposal, authenticated_sender, i64::from(envelope.round), seq, &digest])?;
        apply(&tx)?;
        tx.commit()?;
        Ok(Received::Inserted)
    }
    /// Write-ahead RESERVED nonce use. A successful call marks this operation
    /// irrevocably unavailable for another nonce, even after restart.
    pub fn reserve_nonce(&mut self, proposal: &[u8], epoch: u64,
                         operation: &[u8;32], signer: &[u8], now_ms: i64) -> RResult<()> {
        if proposal.is_empty() || signer.is_empty() || *operation == [0;32] {
            return Err(RuntimeError::Wire("invalid nonce slot"));
        }
        let epoch = i64::try_from(epoch).map_err(|_| RuntimeError::Wire("epoch overflow"))?;
        let tx = self.transaction()?;
        let lifecycle: Option<(i64, String)> = tx.query_row("SELECT deadline_ms,state FROM lifecycles WHERE proposal=?1 AND operation=?2",
            params![proposal, operation.as_slice()], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((deadline_ms,state)) = lifecycle else { return Err(RuntimeError::Wire("operation deadline not registered")); };
        if state != "open" || now_ms >= deadline_ms || now_ms <= 0 {
            return Err(RuntimeError::Aborted);
        }
        let written = tx.execute("INSERT OR IGNORE INTO nonces(proposal,epoch,operation,signer,state) VALUES (?1,?2,?3,?4,'reserved')",
            params![proposal, epoch, operation.as_slice(), signer])?;
        if written != 1 { return Err(RuntimeError::Conflict("nonce slot already used or burned")); }
        tx.commit()?;
        Ok(())
    }
    /// The caller MUST invoke this and wait for its successful commit BEFORE
    /// sending/returning the corresponding FROST public commitments.
    pub fn authorize_commitment(&mut self, proposal: &[u8], epoch: u64,
                                operation: &[u8;32], signer: &[u8],
                                serialized_commitment: &[u8]) -> RResult<[u8;32]> {
        if serialized_commitment.is_empty() { return Err(RuntimeError::Wire("empty signing commitment")); }
        let epoch = i64::try_from(epoch).map_err(|_| RuntimeError::Wire("epoch overflow"))?;
        let hash = commitment("frost-public-nonce-commitment-v1", serialized_commitment);
        let tx = self.transaction()?;
        let written = tx.execute("UPDATE nonces SET state='published', commitment_hash=?5
          WHERE proposal=?1 AND epoch=?2 AND operation=?3 AND signer=?4 AND state='reserved'",
            params![proposal, epoch, operation.as_slice(), signer, &hash])?;
        if written != 1 { return Err(RuntimeError::Conflict("no uniquely reserved, unpublished nonce slot")); }
        tx.commit()?;
        Ok(hash)
    }
    pub fn record_abort(&mut self, proposal: &[u8], operation: &[u8], reason: &str) -> RResult<()> {
        if reason.is_empty() || reason.len()>256 || proposal.is_empty() || operation.is_empty() {
            return Err(RuntimeError::Wire("invalid abort"));
        }
        let tx = self.transaction()?;
        tx.execute("INSERT INTO lifecycles(proposal, operation, deadline_ms, state, reason) VALUES (?1,?2,0,'aborted',?3)
         ON CONFLICT(proposal,operation) DO UPDATE SET state='aborted',reason=excluded.reason",
          params![proposal, operation, reason])?;
        tx.execute("UPDATE nonces SET state='burned' WHERE proposal=?1 AND operation=?2 AND state != 'burned'",
            params![proposal,operation])?;
        tx.commit()?;
        Ok(())
    }
    pub fn start_deadline(&mut self, proposal: &[u8], operation: &[u8], deadline_ms: i64) -> RResult<()> {
        if proposal.is_empty() || operation.is_empty() || deadline_ms <= 0 {
            return Err(RuntimeError::Wire("invalid deadline"));
        }
        let tx = self.transaction()?;
        let inserted = tx.execute("INSERT OR IGNORE INTO lifecycles(proposal,operation,deadline_ms,state) VALUES (?1,?2,?3,'open')",
            params![proposal,operation,deadline_ms])?;
        if inserted == 0 { return Err(RuntimeError::Conflict("deadline already registered; cannot extend or revive")); }
        tx.commit()?;
        Ok(())
    }
    /// Provide a monotonic-enough trusted time source at the controller layer.
    /// Persistent deadline policy must define clock rollback handling.
    pub fn expire_at(&mut self, proposal: &[u8], operation: &[u8], now_ms: i64) -> RResult<bool> {
        let tx = self.transaction()?;
        let state: Option<(i64, String)> = tx.query_row(
            "SELECT deadline_ms,state FROM lifecycles WHERE proposal=?1 AND operation=?2",
            params![proposal,operation], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((deadline, state)) = state else { return Err(RuntimeError::Wire("deadline not registered")); };
        if state == "aborted" { return Ok(true); }
        if now_ms < deadline { return Ok(false); }
        tx.execute("UPDATE lifecycles SET state='aborted',reason='deadline' WHERE proposal=?1 AND operation=?2",
            params![proposal,operation])?;
        tx.execute("UPDATE nonces SET state='burned' WHERE proposal=?1 AND operation=?2",
            params![proposal,operation])?;
        tx.commit()?;
        Ok(true)
    }
    /// Fail closed if a persisted timeout elapsed or an abort occurred.
    /// Call immediately before cryptographic signature-share generation.
    pub fn ensure_live(&mut self, proposal: &[u8], operation: &[u8], now_ms: i64) -> RResult<()> {
        if now_ms <= 0 || self.expire_at(proposal, operation, now_ms)? {
            return Err(RuntimeError::Aborted);
        }
        Ok(())
    }
    pub fn store_activation(&mut self, proposal: &[u8], epoch: u64, cert: [u8;32]) -> RResult<()> {
        if cert == [0;32] { return Err(RuntimeError::Wire("zero activation digest")); }
        let epoch = i64::try_from(epoch).map_err(|_| RuntimeError::Wire("epoch overflow"))?;
        let tx = self.transaction()?;
        let inserted = tx.execute("INSERT OR IGNORE INTO activations(proposal,epoch,certificate_digest) VALUES (?1,?2,?3)",params![proposal,epoch,&cert])?;
        if inserted == 0 { return Err(RuntimeError::Conflict("activation epoch already occupied")); }
        tx.commit()?;
        Ok(())
    }
    /// Encrypt secret share at rest. This is write-once per (proposal,epoch,owner).
    /// Never store signing nonces: only static, epoch-bound key-share material.
    pub fn seal_share(&mut self, proposal: &[u8], epoch: u64, owner: &[u8], group_digest: [u8;32],
                      plaintext: &[u8]) -> RResult<()> {
        if plaintext.is_empty() || plaintext.len() > 256*1024 || proposal.is_empty() || owner.is_empty() || group_digest == [0;32] {
            return Err(RuntimeError::Wire("invalid secret-share envelope"));
        }
        let epoch = i64::try_from(epoch).map_err(|_| RuntimeError::Wire("epoch overflow"))?;
        let aad = share_aad(proposal, epoch, owner, &group_digest);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key.0[..]).map_err(|_|RuntimeError::Crypto)?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce,Payload{msg:plaintext,aad:&aad}).map_err(|_|RuntimeError::Crypto)?;
        let tx = self.transaction()?;
        let written = tx.execute("INSERT OR IGNORE INTO secrets (proposal,epoch,owner,group_digest,nonce,ciphertext) VALUES (?1,?2,?3,?4,?5,?6)",
            params![proposal,epoch,owner,&group_digest,nonce.as_slice(),ciphertext])?;
        if written != 1 { return Err(RuntimeError::Conflict("share epoch already stored")); }
        tx.commit()?;
        Ok(())
    }
    /// Returns a zeroising buffer. Caller must avoid copying into logs, non-
    /// zeroising allocations or WASM inputs.
    pub fn open_share(&self, proposal: &[u8], epoch: u64, owner: &[u8],
                      expected_group_digest: [u8;32]) -> RResult<Zeroizing<Vec<u8>>> {
        let epoch = i64::try_from(epoch).map_err(|_| RuntimeError::Wire("epoch overflow"))?;
        let (group, nonce, ciphertext): (Vec<u8>,Vec<u8>,Vec<u8>) = self.connection.query_row(
            "SELECT group_digest, nonce, ciphertext FROM secrets WHERE proposal=?1 AND epoch=?2 AND owner=?3",
            params![proposal,epoch,owner], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        if group.as_slice() != expected_group_digest.as_slice() || nonce.len() != 24 { return Err(RuntimeError::Conflict("wrong epoch/group or corrupted nonce")); }
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key.0[..]).map_err(|_|RuntimeError::Crypto)?;
        let aad = share_aad(proposal,epoch,owner,&expected_group_digest);
        let mut clear = Zeroizing::new(cipher.decrypt(
            chacha20poly1305::XNonce::from_slice(&nonce),Payload{msg:&ciphertext,aad:&aad})
            .map_err(|_|RuntimeError::Crypto)?);
        // Defensive limit against corrupted/malformed storage.
        if clear.len() > 256*1024 { clear.zeroize(); return Err(RuntimeError::Crypto); }
        Ok(clear)
    }
}
fn share_aad(proposal: &[u8], epoch: i64, owner: &[u8], digest: &[u8;32]) -> Vec<u8> {
    let mut out = b"holochain-mpc/secret-share/v1".to_vec();
    for item in [proposal, &epoch.to_be_bytes(), owner, digest] {
        out.extend_from_slice(&(item.len() as u64).to_be_bytes());
        out.extend_from_slice(item);
    }
    out
}
