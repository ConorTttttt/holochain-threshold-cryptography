//! Coordinator-authenticated structured inbox snapshots. Native DKG and
//! signing consumers must not infer safety from the old get_inbox API.
use crate::connection_policy::ConductorPin;
use holochain_mpc_core::{commitment, Envelope, MAX_PAYLOAD_BYTES};
use holochain_zome_types::prelude::{ActionHash, AgentPubKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_INBOX_SLOTS: usize = 4096;
pub const MAX_INBOX_EVIDENCE_RECORDS: usize = 4096;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct InboxSlots {
    pub envelopes: Vec<Envelope>,
    pub conflicts: Vec<WithheldSlot>,
    pub over_quota: Vec<WithheldSlot>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithheldSlot {
    pub sender: Vec<u8>,
    pub round: u32,
    pub sequence: u64,
    pub variants: Vec<StoredVariant>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredVariant {
    pub envelope: Envelope,
    pub storage_actions: Vec<ActionHash>,
}
impl InboxSlots {
    /// Structural checks before treating coordinator data as authoritative.
    /// Consumer-specific membership and operation relevance are checked later.
    pub fn validate_for_pin(&self, pin: &ConductorPin) -> Result<(), String> {
        let count = self.envelopes.len().checked_add(self.conflicts.len())
            .and_then(|n| n.checked_add(self.over_quota.len()))
            .ok_or("inbox slot count overflow")?;
        if count > MAX_INBOX_SLOTS { return Err("structured inbox exceeds slot bound".into()); }
        let mut ids = BTreeSet::new();
        for env in &self.envelopes {
            validate_envelope(pin, env)?;
            if !ids.insert((env.sender.clone(), env.round, env.sequence)) {
                return Err("duplicate served inbox slot".into());
            }
        }
        let mut records = 0usize;
        for (conflict, list) in [(true, &self.conflicts), (false, &self.over_quota)] {
            for slot in list {
                if AgentPubKey::try_from_raw_39(slot.sender.clone()).is_err()
                    || slot.round == 0 || slot.round > 6 || slot.sequence == u64::MAX
                    || !ids.insert((slot.sender.clone(), slot.round, slot.sequence)) {
                    return Err("malformed or duplicate withheld inbox slot".into());
                }
                if (conflict && slot.variants.len() < 2) || (!conflict && slot.variants.len() != 1) {
                    return Err("withheld inbox variant count is inconsistent".into());
                }
                let mut distinct = Vec::new();
                for variant in &slot.variants {
                    records = records.checked_add(variant.storage_actions.len())
                        .ok_or("inbox evidence count overflow")?;
                    if records > MAX_INBOX_EVIDENCE_RECORDS || variant.storage_actions.is_empty() {
                        return Err("inbox storage evidence missing or excessive".into());
                    }
                    validate_envelope(pin, &variant.envelope)?;
                    if variant.envelope.sender != slot.sender ||
                        variant.envelope.round != slot.round ||
                        variant.envelope.sequence != slot.sequence ||
                        distinct.iter().any(|other: &&Envelope| *other == &variant.envelope) {
                        return Err("withheld inbox variant disagrees with its slot".into());
                    }
                    distinct.push(&variant.envelope);
                }
            }
        }
        Ok(())
    }
}
fn validate_envelope(pin: &ConductorPin, env: &Envelope) -> Result<(), String> {
    if env.session_id != pin.node.session_id ||
        env.sender == pin.node.worker_agent ||
        AgentPubKey::try_from_raw_39(env.sender.clone()).is_err() ||
        (env.recipient.is_some() &&
            env.recipient.as_deref() != Some(pin.node.worker_agent.as_slice())) ||
        env.round == 0 || env.round > 6 || env.sequence == u64::MAX ||
        env.payload.len() > MAX_PAYLOAD_BYTES ||
        env.payload_hash != commitment("envelope-payload", &env.payload) {
        return Err("structured inbox outside pinned ceremony".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::ChannelContext;
    use holochain_zome_types::prelude::DnaHash;
    fn pin() -> ConductorPin {
        let agent = AgentPubKey::from_raw_32(vec![1;32]);
        ConductorPin {app_id:"test".into(),role:"mpc".into(),
            dna_hash:DnaHash::from_raw_32(vec![2;32]).get_raw_39().to_vec(),
            node:ChannelContext {worker_agent:agent.get_raw_39().to_vec(),
                proposal_action:ActionHash::from_raw_32(vec![3;32]).get_raw_39().to_vec(),
                session_id:[4;32],channel_id:[5;32]}}
    }
    fn env(p:&ConductorPin, data:&[u8]) -> Envelope {
        Envelope {wire_version:1,session_id:p.node.session_id,protocol_id:"frost-ed25519".into(),
            protocol_version:1,sender:AgentPubKey::from_raw_32(vec![7;32]).get_raw_39().to_vec(),
            recipient:Some(p.node.worker_agent.clone()),round:1,sequence:1,
            payload:data.to_vec(),payload_hash:commitment("envelope-payload",data)}
    }
    fn variant(e:Envelope,i:u8)->StoredVariant {
        StoredVariant {envelope:e,storage_actions:vec![ActionHash::from_raw_32(vec![i;32])]}
    }
    #[test]
    fn structured_wire_round_trip_and_late_conflict() {
        let p=pin();let a=env(&p,b"a");let b=env(&p,b"b");
        let snapshot=InboxSlots {envelopes:vec![],conflicts:vec![WithheldSlot {
            sender:a.sender.clone(),round:1,sequence:1,variants:vec![variant(a,10),variant(b,11)]}],
            over_quota:vec![]};
        let io=holochain_zome_types::prelude::ExternIO::encode(&snapshot).unwrap();
        let decoded:InboxSlots=io.decode().unwrap();
        decoded.validate_for_pin(&p).unwrap();
        let mut invalid=decoded;
        invalid.envelopes.push(invalid.conflicts[0].variants[0].envelope.clone());
        assert!(invalid.validate_for_pin(&p).is_err());
        invalid.envelopes.clear();
        invalid.conflicts[0].variants[1].storage_actions.clear();
        assert!(invalid.validate_for_pin(&p).is_err());
    }
}
