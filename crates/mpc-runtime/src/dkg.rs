//! Durable, encrypted DKG *checkpoint metadata* with fail-closed restart rules.
//!
//! This intentionally does NOT serialize any FROST secret packages. When a
//! process exits, its volatile secret packages are lost, and an existing
//! proposal/agent pair may NEVER be opened for another ceremony. Use a fresh
//! Holochain proposal and fresh randomness. An operator who restores an older
//! database snapshot can defeat this protection: OS-backed anti-rollback and
//! trustworthy key provisioning are outside this module's guarantee.
use super::{MasterKey, RResult, RuntimeError, RuntimeStore};
use chacha20poly1305::{aead::{Aead, AeadCore, KeyInit, OsRng, Payload}, XChaCha20Poly1305, XNonce};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkgState { Running, Completed, Aborted }
impl DkgState {
    fn label(self) -> &'static str {
        match self { Self::Running => "running", Self::Completed => "completed", Self::Aborted => "aborted" }
    }
}

/// Authenticated metadata only. `reply_digest` commits to the latest approved
/// outward reply (including encrypted network envelopes, never plaintext shares).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DkgCheckpoint {
    pub state: DkgState,
    pub revision: u64,
    pub reply_digest: [u8; 32],
}

fn dkg_context(proposal: &[u8], owner: &[u8], session: &[u8;32]) -> RResult<()> {
    if proposal.len() != 39 || owner.len() != 39 || *session == [0;32] {
        return Err(RuntimeError::Wire("invalid DKG identity binding"));
    }
    Ok(())
}
fn aad(proposal: &[u8], owner: &[u8], session: &[u8;32], state: &str, revision: i64) -> Vec<u8> {
    let mut out = b"holochain-mpc/dkg-checkpoint/v1".to_vec();
    let revision_bytes = revision.to_be_bytes();
    for item in [proposal, owner, session.as_slice(), state.as_bytes(), revision_bytes.as_slice()] {
        out.extend_from_slice(&(item.len() as u64).to_be_bytes());
        out.extend_from_slice(item);
    }
    out
}
fn encrypt(key: &MasterKey, proposal: &[u8], owner: &[u8], session: &[u8;32],
           value: &DkgCheckpoint) -> RResult<(Vec<u8>, Vec<u8>)> {
    let revision = i64::try_from(value.revision).map_err(|_| RuntimeError::Wire("revision overflow"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0[..]).map_err(|_| RuntimeError::Crypto)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let clear = Zeroizing::new(serde_json::to_vec(value).map_err(|_| RuntimeError::Crypto)?);
    let ciphertext = cipher.encrypt(&nonce, Payload {
        msg: clear.as_slice(),
        aad: &aad(proposal, owner, session, value.state.label(), revision),
    }).map_err(|_| RuntimeError::Crypto)?;
    Ok((nonce.to_vec(), ciphertext))
}
fn read_from(conn: &Connection, key: &MasterKey, proposal: &[u8], owner: &[u8],
             session: &[u8;32]) -> RResult<Option<DkgCheckpoint>> {
    let row: Option<(Vec<u8>, String, i64, Vec<u8>, Vec<u8>)> = conn.query_row(
        "SELECT session, state, revision, nonce, ciphertext FROM dkg_checkpoints WHERE proposal=?1 AND owner=?2",
        params![proposal, owner],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    ).optional()?;
    let Some((stored_session, state, revision, nonce, ciphertext)) = row else { return Ok(None) };
    if stored_session.as_slice() != session || revision < 0 || nonce.len() != 24 || ciphertext.len() > 8192 {
        return Err(RuntimeError::Conflict("DKG checkpoint binding or ciphertext invalid"));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0[..]).map_err(|_| RuntimeError::Crypto)?;
    let clear = Zeroizing::new(cipher.decrypt(XNonce::from_slice(&nonce), Payload {
        msg: &ciphertext, aad: &aad(proposal, owner, session, &state, revision),
    }).map_err(|_| RuntimeError::Crypto)?);
    let record: DkgCheckpoint = serde_json::from_slice(clear.as_slice()).map_err(|_| RuntimeError::Crypto)?;
    if record.state.label() != state || i64::try_from(record.revision).ok() != Some(revision) {
        return Err(RuntimeError::Conflict("DKG checkpoint metadata altered"));
    }
    Ok(Some(record))
}

impl RuntimeStore {
    /// Check an existing ceremony; no returned state may be used to reconstruct
    /// a DKG private package. Calling code must refuse *every* Some result.
    pub fn dkg_checkpoint(&self, proposal: &[u8], owner: &[u8], session: &[u8;32]) -> RResult<Option<DkgCheckpoint>> {
        dkg_context(proposal, owner, session)?;
        read_from(&self.connection, &self.key, proposal, owner, session)
    }

    /// Must commit before beginning FROST DKG or publishing Round-1 data.
    /// Never overwrite an existing record, even one marked aborted/completed.
    pub fn dkg_begin(&mut self, proposal: &[u8], owner: &[u8], session: &[u8;32]) -> RResult<()> {
        dkg_context(proposal, owner, session)?;
        if self.dkg_checkpoint(proposal, owner, session)?.is_some() {
            return Err(RuntimeError::Conflict("DKG proposal/agent already used; fresh proposal required"));
        }
        let record = DkgCheckpoint { state: DkgState::Running, revision: 0, reply_digest: [0;32] };
        let (nonce, ciphertext) = encrypt(&self.key, proposal, owner, session, &record)?;
        let tx = self.transaction()?;
        let written = tx.execute("INSERT OR IGNORE INTO dkg_checkpoints
            (proposal,owner,session,state,revision,nonce,ciphertext) VALUES (?1,?2,?3,'running',0,?4,?5)",
            params![proposal, owner, session.as_slice(), nonce, ciphertext])?;
        if written != 1 { return Err(RuntimeError::Conflict("concurrent DKG start or previous tombstone")); }
        tx.commit()?;
        Ok(())
    }

    /// Atomic, write-ahead acknowledgement of each outward protocol reply.
    /// Must succeed before the IPC channel releases the corresponding reply.
    pub fn dkg_record_reply(&mut self, proposal: &[u8], owner: &[u8], session: &[u8;32],
                            reply_digest: [u8;32], completed: bool) -> RResult<()> {
        dkg_context(proposal, owner, session)?;
        if reply_digest == [0;32] { return Err(RuntimeError::Wire("empty reply commitment")); }
        let current = self.dkg_checkpoint(proposal, owner, session)?
            .ok_or(RuntimeError::Conflict("DKG not started"))?;
        if current.state != DkgState::Running { return Err(RuntimeError::Conflict("DKG not running")); }
        let revision = current.revision.checked_add(1).ok_or(RuntimeError::Wire("revision overflow"))?;
        let next = DkgCheckpoint {
            state: if completed { DkgState::Completed } else { DkgState::Running },
            revision, reply_digest,
        };
        let (nonce, ciphertext) = encrypt(&self.key, proposal, owner, session, &next)?;
        let old_revision = i64::try_from(current.revision).map_err(|_| RuntimeError::Wire("revision overflow"))?;
        let new_revision = i64::try_from(revision).map_err(|_| RuntimeError::Wire("revision overflow"))?;
        let tx = self.transaction()?;
        let written = tx.execute("UPDATE dkg_checkpoints SET state=?4,revision=?5,nonce=?6,ciphertext=?7
            WHERE proposal=?1 AND owner=?2 AND session=?3 AND state='running' AND revision=?8",
            params![proposal,owner,session.as_slice(),next.state.label(),new_revision,nonce,ciphertext,old_revision])?;
        if written != 1 { return Err(RuntimeError::Conflict("concurrent or stale DKG transition")); }
        tx.commit()?;
        Ok(())
    }

    /// Permanently poison a started ceremony after any authenticated-controller
    /// failure. This also creates a durable tombstone for a rejected first
    /// command; such failures can intentionally deny progress on that proposal.
    pub fn dkg_abort(&mut self, proposal: &[u8], owner: &[u8], session: &[u8;32]) -> RResult<()> {
        dkg_context(proposal, owner, session)?;
        let current = self.dkg_checkpoint(proposal, owner, session)?;
        if let Some(current) = &current {
            if current.state != DkgState::Running { return Ok(()); }
        }
        let revision = match &current {
            Some(c) => c.revision.checked_add(1).ok_or(RuntimeError::Wire("revision overflow"))?,
            None => 0,
        };
        let aborted = DkgCheckpoint { state: DkgState::Aborted, revision, reply_digest: [0;32] };
        let (nonce, ciphertext) = encrypt(&self.key, proposal, owner, session, &aborted)?;
        let tx = self.transaction()?;
        if let Some(current) = current {
            let old_revision = i64::try_from(current.revision).map_err(|_| RuntimeError::Wire("revision overflow"))?;
            let new_revision = i64::try_from(revision).map_err(|_| RuntimeError::Wire("revision overflow"))?;
            let written = tx.execute("UPDATE dkg_checkpoints SET state='aborted',revision=?4,nonce=?5,ciphertext=?6
                WHERE proposal=?1 AND owner=?2 AND session=?3 AND state='running' AND revision=?7",
                params![proposal,owner,session.as_slice(),new_revision,nonce,ciphertext,old_revision])?;
            if written != 1 { return Err(RuntimeError::Conflict("concurrent DKG abort")); }
        } else {
            let written = tx.execute("INSERT OR IGNORE INTO dkg_checkpoints
                (proposal,owner,session,state,revision,nonce,ciphertext) VALUES (?1,?2,?3,'aborted',0,?4,?5)",
                params![proposal,owner,session.as_slice(),nonce,ciphertext])?;
            if written != 1 { return Err(RuntimeError::Conflict("concurrent DKG abort tombstone")); }
        }
        tx.commit()?;
        Ok(())
    }
}
