//! Dedicated probe ledger. Never opens, resumes or modifies a DKG checkpoint.
//! A pending attempt after a crash is UNCERTAIN and cannot be resubmitted.
use super::{RResult, Received, RuntimeError, RuntimeStore};
use holochain_mpc_core::{commitment, Envelope};
use rusqlite::{params, OptionalExtension};

#[derive(Debug)]
pub struct ProbeAttempt {
    pub state: String,
    pub envelope: Envelope,
    pub receipt: Option<Vec<u8>>,
}

impl RuntimeStore {
    // Lazy tables: existing FROST callers do not run this migration.
    fn probe_tables(&self) -> RResult<()> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS probe_attempts (
          proposal BLOB NOT NULL, sender BLOB NOT NULL, plan BLOB NOT NULL,
          message_id BLOB NOT NULL, envelope BLOB NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('pending','uncertain','acknowledged')),
          receipt BLOB, PRIMARY KEY(proposal,sender));
          CREATE TABLE IF NOT EXISTS probe_receipts (
          proposal BLOB NOT NULL, sender BLOB NOT NULL, plan BLOB NOT NULL,
          message_id BLOB NOT NULL, digest BLOB NOT NULL,
          PRIMARY KEY(proposal,sender));",
        )?;
        Ok(())
    }

    /// One outbound attempt per proposal/sender, even if a later caller changes
    /// its plan, key pins, recipient or payload. Commit BEFORE signing/network IO.
    pub fn probe_admit(
        &mut self,
        proposal: &[u8],
        plan: [u8; 32],
        message_id: [u8; 32],
        envelope: &Envelope,
    ) -> RResult<()> {
        self.probe_tables()?;
        if proposal.len() != 39
            || envelope.sender.len() != 39
            || envelope.protocol_id != "mpc-transport-probe"
            || envelope.protocol_version != 1
            || envelope.round != 1
            || envelope.sequence != 1
        {
            return Err(RuntimeError::Wire("invalid probe admission"));
        }
        let bytes =
            serde_json::to_vec(envelope).map_err(|_| RuntimeError::Wire("probe encoding"))?;
        let tx = self.transaction()?;
        let n = tx.execute(
            "INSERT OR IGNORE INTO probe_attempts
          (proposal,sender,plan,message_id,envelope,state) VALUES (?1,?2,?3,?4,?5,'pending')",
            params![
                proposal,
                &envelope.sender,
                plan.as_slice(),
                message_id.as_slice(),
                bytes
            ],
        )?;
        if n != 1 {
            return Err(RuntimeError::Conflict(
                "probe already admitted: inspect; never retry",
            ));
        }
        tx.commit()?;
        Ok(())
    }

    /// Any error/cancellation after admission is terminal. A crash leaving
    /// 'pending' has the same no-retry meaning as 'uncertain'.
    pub fn probe_uncertain(&mut self, proposal: &[u8], sender: &[u8]) -> RResult<()> {
        self.probe_tables()?;
        let tx = self.transaction()?;
        tx.execute("UPDATE probe_attempts SET state='uncertain' WHERE proposal=?1 AND sender=?2 AND state='pending'",
            params![proposal,sender])?;
        tx.commit()?;
        Ok(())
    }

    pub fn probe_acknowledge(
        &mut self,
        proposal: &[u8],
        sender: &[u8],
        plan: [u8; 32],
        message_id: [u8; 32],
        receipt: &[u8],
    ) -> RResult<()> {
        self.probe_tables()?;
        if receipt.len() != 39 || receipt.iter().all(|b| *b == 0) {
            return Err(RuntimeError::Wire("invalid probe receipt action"));
        }
        let tx = self.transaction()?;
        let n = tx.execute(
            "UPDATE probe_attempts SET state='acknowledged',receipt=?5
          WHERE proposal=?1 AND sender=?2 AND plan=?3 AND message_id=?4 AND state='pending'",
            params![
                proposal,
                sender,
                plan.as_slice(),
                message_id.as_slice(),
                receipt
            ],
        )?;
        if n != 1 {
            return Err(RuntimeError::Conflict(
                "probe receipt without matching pending admission",
            ));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn probe_attempt(
        &self,
        proposal: &[u8],
        sender: &[u8],
        plan: [u8; 32],
        message_id: [u8; 32],
    ) -> RResult<Option<ProbeAttempt>> {
        self.probe_tables()?;
        let row: Option<(Vec<u8>,Vec<u8>,Vec<u8>,String,Option<Vec<u8>>)>=self.connection.query_row(
            "SELECT plan,message_id,envelope,state,receipt FROM probe_attempts WHERE proposal=?1 AND sender=?2",
            params![proposal,sender], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        row.map(|(p, id, bytes, state, receipt)| {
            if p != plan || id != message_id {
                return Err(RuntimeError::Conflict("probe ledger plan changed"));
            }
            let envelope = serde_json::from_slice(&bytes)
                .map_err(|_| RuntimeError::Wire("invalid probe ledger envelope"))?;
            Ok(ProbeAttempt {
                state,
                envelope,
                receipt,
            })
        })
        .transpose()
    }

    /// Caller MUST verify trusted conductor provenance, full envelope, AEAD,
    /// approved pins and inner identity before entering this transaction.
    /// The only application effect is a durable authenticated-receipt marker.
    pub fn probe_accept(
        &mut self,
        proposal: &[u8],
        plan: [u8; 32],
        message_id: [u8; 32],
        envelope: &Envelope,
    ) -> RResult<Received> {
        self.probe_tables()?;
        let bytes =
            serde_json::to_vec(envelope).map_err(|_| RuntimeError::Wire("probe encoding"))?;
        let digest = commitment("mpc-transport-probe/received/v1", &bytes);
        let tx = self.transaction()?;
        let previous: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT plan,message_id,digest FROM probe_receipts WHERE proposal=?1 AND sender=?2",
                params![proposal, &envelope.sender],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((p, id, d)) = previous {
            return if p == plan && id == message_id && d == digest {
                Ok(Received::Duplicate)
            } else {
                Err(RuntimeError::Conflict(
                    "conflicting authenticated probe receipt",
                ))
            };
        }
        tx.execute("INSERT INTO probe_receipts (proposal,sender,plan,message_id,digest) VALUES (?1,?2,?3,?4,?5)",
            params![proposal,&envelope.sender,plan.as_slice(),message_id.as_slice(),digest.as_slice()])?;
        tx.commit()?;
        Ok(Received::Inserted)
    }
}
