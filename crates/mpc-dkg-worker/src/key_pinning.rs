//! Phase 5C-C: exact, operator-pinned native encryption-key evidence.
//!
//! This module is offline-only: no zome calls, source-chain writes, or DKG
//! state changes. `observed` MUST come from an authenticated, pinned local
//! conductor response. `approved` MUST come from independently reviewed,
//! retained operator evidence; never construct it by copying `observed`.
//!
//! This DOES NOT independently verify Holochain action signatures or prove
//! the key owner holds its private key. It binds the local participant's
//! trusted evidence to the secret-derived NativeChannelKey public key.
//! Any missing, duplicate, additional/rotated, or altered registration fails
//! closed. Key rotation requires an explicit, separate operator workflow.
use crate::{conductor_bridge::KeyEvidence, transport_channel::DurableTransportChannel,
            PeerKeyBinding};
use holochain_mpc_runtime::transport_key::TransportKeyBinding;
use holochain_mpc_security::Ceremony;
use std::collections::{BTreeMap, BTreeSet};

fn invalid(message: &'static str) -> String { message.to_owned() }

fn exact_map(
    records: &[KeyEvidence],
    members: &BTreeSet<Vec<u8>>,
) -> Result<BTreeMap<Vec<u8>, KeyEvidence>, String> {
    if records.len() != members.len() {
        return Err(invalid("missing or extra encryption-key registrations"));
    }
    let mut by_author = BTreeMap::new();
    let mut actions = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    for record in records {
        if !members.contains(&record.author)
            || record.author.len() != 39
            || record.action.len() != 39
            || record.action.iter().all(|byte| *byte == 0)
            || record.public_key == [0; 32]
            || !actions.insert(record.action.clone())
            || !public_keys.insert(record.public_key)
            || by_author.insert(record.author.clone(), record.clone()).is_some()
        {
            return Err(invalid("invalid, duplicate or unrecognised key registration"));
        }
    }
    if &by_author.keys().cloned().collect::<BTreeSet<_>>() != members {
        return Err(invalid("key registration roster mismatch"));
    }
    Ok(by_author)
}

/// Verify a full two-or-more-party roster against independently approved
/// author/action/public-key tuples. Ordering of the observed response does not
/// matter. The local public key must be derived from the retained native secret.
///
/// Caller responsibilities:
/// * Construct `binding` from the exact authenticated conductor DNA/cell,
///   agent, proposal and session, not from attacker-controlled JSON.
/// * Persist and independently review `approved` action hashes before use.
/// * Obtain `observed` from a trusted, authenticated local conductor response.
/// * Do not use this as an admission check for resuming a FROST DKG.
pub fn verify_explicit_key_roster(
    ceremony: &Ceremony,
    binding: &TransportKeyBinding,
    local: &DurableTransportChannel,
    approved: &[KeyEvidence],
    observed: &[KeyEvidence],
) -> Result<Vec<PeerKeyBinding>, String> {
    ceremony.validate().map_err(|_| invalid("invalid pinned ceremony"))?;
    if binding.dna == [0; 39]
        || binding.agent == [0; 39]
        || binding.proposal.as_slice() != ceremony.proposal_action.as_slice()
        || binding.session != ceremony.spec.session_id
    {
        return Err(invalid("transport identity differs from pinned ceremony"));
    }
    let members: BTreeSet<Vec<u8>> = ceremony.spec.participants.iter().cloned().collect();
    if members.len() != ceremony.spec.participants.len()
        || !members.contains(binding.agent.as_slice())
        || local.public_key() == [0; 32]
    {
        return Err(invalid("invalid local member or encryption identity"));
    }
    let pinned = exact_map(approved, &members)?;
    let retrieved = exact_map(observed, &members)?;
    if pinned != retrieved {
        return Err(invalid("encryption-key evidence differs from approved exact actions"));
    }
    if pinned.get(binding.agent.as_slice()).map(|e| e.public_key) != Some(local.public_key()) {
        return Err(invalid("local public-key registration does not match retained key"));
    }
    Ok(pinned.into_iter().map(|(member, evidence)| PeerKeyBinding {
        member,
        public_key: evidence.public_key,
        action: evidence.action,
    }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use holochain_mpc_core::{commitment, SessionSpec};
    use holochain_mpc_runtime::{MasterKey, RuntimeStore};
    use std::path::Path;

    fn fixture() -> (Ceremony, TransportKeyBinding, DurableTransportChannel) {
        let binding = TransportKeyBinding {
            dna: [5; 39], agent: [1; 39], proposal: [3; 39], session: [4; 32],
        };
        let ceremony = Ceremony {
            proposal_action: binding.proposal.to_vec(),
            spec: SessionSpec {
                session_id: binding.session,
                application_id: "org.example.mpc.transport-test".into(),
                protocol_id: "frost-ed25519".into(),
                protocol_version: 1,
                context_hash: commitment("key-pinning-test", b"offline-only"),
                participants: vec![vec![1; 39], vec![2; 39]],
                threshold: 2,
                max_round: 6,
            },
        };
        let mut store = RuntimeStore::open(
            Path::new(":memory:"), MasterKey::from_bytes([8; 32]),
        ).unwrap();
        let channel = DurableTransportChannel::provision_new(&mut store, &binding).unwrap();
        (ceremony, binding, channel)
    }

    fn pins(own: [u8; 32]) -> Vec<KeyEvidence> {
        vec![
            KeyEvidence {author: vec![1; 39], action: vec![11; 39], public_key: own},
            KeyEvidence {author: vec![2; 39], action: vec![22; 39], public_key: [7; 32]},
        ]
    }

    #[test]
    fn exact_operator_pins_accept_reordered_conductor_evidence() {
        let (ceremony, binding, channel) = fixture();
        let approved = pins(channel.public_key());
        let observed = vec![approved[1].clone(), approved[0].clone()];
        let verified = verify_explicit_key_roster(
            &ceremony, &binding, &channel, &approved, &observed,
        ).unwrap();
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0].member, vec![1; 39]);
        assert_eq!(verified[0].action, vec![11; 39]);
        assert_eq!(verified[1].member, vec![2; 39]);
        assert_eq!(verified[1].action, vec![22; 39]);
    }

    #[test]
    fn changed_action_even_with_same_key_is_refused() {
        let (ceremony, binding, channel) = fixture();
        let approved = pins(channel.public_key());
        let mut observed = approved.clone();
        observed[1].action = vec![23; 39];
        assert!(verify_explicit_key_roster(
            &ceremony, &binding, &channel, &approved, &observed,
        ).is_err());
        observed = approved.clone();
        observed[1].public_key = [9; 32];
        assert!(verify_explicit_key_roster(
            &ceremony, &binding, &channel, &approved, &observed,
        ).is_err());
    }

    #[test]
    fn extra_rotation_duplicate_author_and_missing_record_fail_closed() {
        let (ceremony, binding, channel) = fixture();
        let approved = pins(channel.public_key());
        let mut observed = approved.clone();
        observed.push(KeyEvidence {
            author: vec![2; 39], action: vec![24; 39], public_key: [8; 32],
        });
        assert!(verify_explicit_key_roster(
            &ceremony, &binding, &channel, &approved, &observed,
        ).is_err());
        assert!(verify_explicit_key_roster(
            &ceremony, &binding, &channel, &approved, &approved[..1],
        ).is_err());
        observed = approved.clone();
        observed[1].author = vec![1; 39];
        assert!(verify_explicit_key_roster(
            &ceremony, &binding, &channel, &approved, &observed,
        ).is_err());
    }

    #[test]
    fn distinct_agents_cannot_claim_one_transport_public_key() {
        let (ceremony, binding, channel) = fixture();
        let mut approved = pins(channel.public_key());
        approved[1].public_key = channel.public_key();
        assert!(verify_explicit_key_roster(
            &ceremony, &binding, &channel, &approved, &approved,
        ).is_err());
    }

    #[test]
    fn local_key_and_ceremony_binding_must_match() {
        let (ceremony, binding, channel) = fixture();
        let mut approved = pins([9; 32]);
        assert!(verify_explicit_key_roster(
            &ceremony, &binding, &channel, &approved, &approved,
        ).is_err());
        approved = pins(channel.public_key());
        let mut wrong = binding;
        wrong.session[0] ^= 1;
        assert!(verify_explicit_key_roster(
            &ceremony, &wrong, &channel, &approved, &approved,
        ).is_err());
        wrong = binding;
        wrong.proposal[0] ^= 1;
        assert!(verify_explicit_key_roster(
            &ceremony, &wrong, &channel, &approved, &approved,
        ).is_err());
    }
}
