//! v0.4.0 Phase 7 hardening: operator-controlled share lifecycle.
//!
//! A group epoch is active until its operator retires it. Retirement is the
//! rotation hook: it does NOT reshare. It aborts this node's open operations
//! in that epoch, burns their nonce slots, and from then on refuses nonce
//! reservation, share opening and sealing for the epoch. A retired share may
//! later be erased. Both steps are one-way and logged in the custody chain, so
//! restoring an older journal to undo them is refused as a rollback.
//!
//! Erasure is best effort. SQLite `secure_delete` zeroes the row in the main
//! file and a TRUNCATE checkpoint empties the WAL, but copies can survive in
//! backups, snapshots, filesystem journals and flash wear-levelling. The share
//! is still ciphertext under the master key, so once every epoch under a key
//! is erased, destroying that key (crypto-shredding) is the stronger step.
use super::{begin, chain, RResult, RuntimeError, RuntimeStore};
use rusqlite::{params, Connection, OptionalExtension};

pub(crate) const TABLES: &str = "CREATE TABLE IF NOT EXISTS epochs (
      proposal BLOB NOT NULL, epoch INTEGER NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('retired','erased')),
      retired_ms INTEGER NOT NULL, erased_ms INTEGER, reason TEXT NOT NULL,
      PRIMARY KEY (proposal, epoch));";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochState { Active, Retired, Erased }

/// One epoch this node holds or held a share for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRecord {
    pub proposal: Vec<u8>,
    pub epoch: u64,
    pub state: EpochState,
    pub retired_ms: Option<i64>,
    pub erased_ms: Option<i64>,
    pub sealed_share: bool,
}

/// True once the epoch is retired or erased.
pub(crate) fn retired(conn: &Connection, proposal: &[u8], epoch: i64) -> RResult<bool> {
    Ok(conn.query_row("SELECT 1 FROM epochs WHERE proposal=?1 AND epoch=?2",
        params![proposal, epoch], |_| Ok(())).optional()?.is_some())
}

/// Every sealed or retired epoch, for status and retention.
pub(crate) fn list(conn: &Connection) -> RResult<Vec<EpochRecord>> {
    let mut statement = conn.prepare(
        "SELECT proposal, epoch, MAX(state), MAX(retired_ms), MAX(erased_ms), MAX(sealed) FROM (
           SELECT proposal, epoch, '' AS state, NULL AS retired_ms, NULL AS erased_ms, 1 AS sealed FROM secrets
           UNION ALL
           SELECT proposal, epoch, state, retired_ms, erased_ms, 0 FROM epochs)
         GROUP BY proposal, epoch ORDER BY proposal, epoch")?;
    let rows = statement.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?,
        r.get::<_, String>(2)?, r.get::<_, Option<i64>>(3)?, r.get::<_, Option<i64>>(4)?, r.get::<_, i64>(5)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (proposal, epoch, state, retired_ms, erased_ms, sealed) = row?;
        let state = match state.as_str() {
            "" => EpochState::Active,
            "retired" => EpochState::Retired,
            "erased" => EpochState::Erased,
            _ => return Err(RuntimeError::Conflict("unknown epoch state")),
        };
        let epoch = u64::try_from(epoch).map_err(|_| RuntimeError::Conflict("negative epoch"))?;
        out.push(EpochRecord { proposal, epoch, state, retired_ms, erased_ms, sealed_share: sealed == 1 });
    }
    Ok(out)
}

impl RuntimeStore {
    pub fn epoch_state(&self, proposal: &[u8], epoch: u64) -> RResult<EpochState> {
        let epoch = i64::try_from(epoch).map_err(|_| RuntimeError::Wire("epoch overflow"))?;
        let state: Option<String> = self.connection.query_row(
            "SELECT state FROM epochs WHERE proposal=?1 AND epoch=?2", params![proposal, epoch],
            |r| r.get(0)).optional()?;
        Ok(match state.as_deref() {
            None => EpochState::Active,
            Some("retired") => EpochState::Retired,
            Some(_) => EpochState::Erased,
        })
    }

    pub fn epochs(&self) -> RResult<Vec<EpochRecord>> { list(&self.connection) }

    /// Retire one group epoch on this node (rotation hook). One-way.
    pub fn retire_epoch(&mut self, proposal: &[u8], epoch: u64, now_ms: i64, reason: &str) -> RResult<()> {
        if proposal.is_empty() || reason.is_empty() || reason.len() > 256 || now_ms <= 0 {
            return Err(RuntimeError::Wire("invalid epoch retirement"));
        }
        let epoch = i64::try_from(epoch).map_err(|_| RuntimeError::Wire("epoch overflow"))?;
        let tx = begin(&mut self.connection)?;
        let inserted = tx.execute("INSERT OR IGNORE INTO epochs (proposal,epoch,state,retired_ms,reason)
            VALUES (?1,?2,'retired',?3,?4)", params![proposal, epoch, now_ms, reason])?;
        if inserted != 1 { return Err(RuntimeError::Conflict("epoch already retired")); }
        // Stop in-flight signing in this epoch: `ensure_live` then fails.
        tx.execute("UPDATE lifecycles SET state='aborted', reason='epoch retired'
            WHERE proposal=?1 AND state='open'
            AND operation IN (SELECT operation FROM nonces WHERE proposal=?1 AND epoch=?2)",
            params![proposal, epoch])?;
        tx.execute("UPDATE nonces SET state='burned' WHERE proposal=?1 AND epoch=?2 AND state != 'burned'",
            params![proposal, epoch])?;
        chain::log_event(&tx, &self.key, "retire-epoch", &[proposal, &epoch.to_be_bytes(), reason.as_bytes()])?;
        tx.commit()?;
        self.check_anchor()
    }

    /// Erase the sealed share of a RETIRED epoch (best effort; see module
    /// docs). Returns the number of share rows removed. One-way.
    pub fn erase_share(&mut self, proposal: &[u8], epoch: u64, now_ms: i64) -> RResult<usize> {
        if proposal.is_empty() || now_ms <= 0 { return Err(RuntimeError::Wire("invalid share erasure")); }
        let epoch = i64::try_from(epoch).map_err(|_| RuntimeError::Wire("epoch overflow"))?;
        let tx = begin(&mut self.connection)?;
        let state: Option<String> = tx.query_row("SELECT state FROM epochs WHERE proposal=?1 AND epoch=?2",
            params![proposal, epoch], |r| r.get(0)).optional()?;
        match state.as_deref() {
            Some("retired") => {}
            Some(_) => return Err(RuntimeError::Conflict("share already erased")),
            None => return Err(RuntimeError::Conflict("retire the epoch before erasing its share")),
        }
        let erased = tx.execute("DELETE FROM secrets WHERE proposal=?1 AND epoch=?2", params![proposal, epoch])?;
        tx.execute("UPDATE epochs SET state='erased', erased_ms=?3 WHERE proposal=?1 AND epoch=?2",
            params![proposal, epoch, now_ms])?;
        chain::log_event(&tx, &self.key, "erase-share", &[proposal, &epoch.to_be_bytes()])?;
        tx.commit()?;
        self.check_anchor()?;
        // Fold the WAL, which still holds the old pages, into the zeroed main
        // file and truncate it. A concurrent reader can keep frames alive.
        let _: (i64, i64, i64) = self.connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(erased)
    }
}
