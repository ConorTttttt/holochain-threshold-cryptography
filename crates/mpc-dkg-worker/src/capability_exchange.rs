//! Phase 5C-B: multi-agent ceremony pinning, assigned inbox-grant checks and
//! private, agent-authenticated capability exchange.
//!
//! Each recipient R authors ONE assigned `receive_protocol_message` grant
//! (coordinator `prepare_inbox_grant`) for all other participants. R then
//! hands its secret to each sender S as a *sealed offer*: an XSalsa20-Poly1305
//! crypto box made by R's Lair from R's agent signing key to S's agent key
//! (`crypto_box_xsalsa_by_sign_pub_key`). Only S's Lair can open it, and opening
//! it proves R's agent key made it. No secret is exported from either Lair
//! and nothing is ever written to the DHT.
//!
//! The coordinator's grant is NOT session-scoped (any assignee may call
//! `receive_protocol_message` for any session the recipient belongs to) and
//! its tag carries only 4 session-ID bytes. Cross-session protection therefore
//! relies on the zome's membership/acceptance checks and on the exact
//! (DNA, proposal, session, grantor, grantee) binding enforced here.
use crate::ipc::ChannelContext;
use crate::lair_signer::{SignerPolicy, SignerPolicyFile};
use crate::socket_signer::SignerBinding;
use holochain_keystore::MetaLairClient;
use holochain_mpc_core::SessionSpec;
use holochain_zome_types::prelude::{
    ActionHash, AgentPubKey, CapGrantInfo, CapSecret, Capability, DnaHash, GrantedFunctions,
};
use lair_keystore_api::prelude::Ed25519PubKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const RECORD_SCHEMA: u8 = 1;
pub const OFFER_SCHEMA: u8 = 1;
pub const INBOX_FUNCTION: &str = "receive_protocol_message";
pub const MPC_ZOME: &str = "mpc";
const MAX_SEALED_BYTES: usize = 4096;

/// PUBLIC ceremony record produced by the proposer and copied to every
/// operator. It pins the exact app, DNA, proposal action and full spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyRecord {
    pub schema: u8,
    pub installed_app_id: String,
    pub dna_hash: Vec<u8>,
    pub proposal_action: Vec<u8>,
    pub spec: SessionSpec,
}

impl CeremonyRecord {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != RECORD_SCHEMA { return Err("unsupported ceremony record schema".into()); }
        if self.installed_app_id.is_empty() || self.installed_app_id.len() > 128 {
            return Err("invalid installed app id".into());
        }
        DnaHash::try_from_raw_39(self.dna_hash.clone()).map_err(|_| "invalid ceremony DNA hash")?;
        ActionHash::try_from_raw_39(self.proposal_action.clone()).map_err(|_| "invalid proposal action")?;
        self.spec.validate().map_err(|e| format!("invalid session spec: {e}"))?;
        if self.spec.participants.len() < 2 {
            return Err("Phase 5C-B requires a multi-member ceremony".into());
        }
        if self.spec.participants.iter().any(|p| AgentPubKey::try_from_raw_39(p.clone()).is_err()) {
            return Err("participants must be Holochain agent keys".into());
        }
        Ok(())
    }

    /// The local agent must be a member; returns every OTHER participant.
    pub fn peers_of(&self, local: &[u8]) -> Result<BTreeSet<Vec<u8>>, String> {
        self.validate()?;
        if !self.spec.contains(local) { return Err("local agent is not a ceremony participant".into()); }
        Ok(self.spec.participants.iter().filter(|p| p.as_slice() != local).cloned().collect())
    }

    /// The conductor's view of the proposal must equal the pinned spec
    /// byte for byte (session, context, members, threshold, rounds).
    pub fn pin_spec(&self, observed: &SessionSpec) -> Result<(), String> {
        if observed != &self.spec { return Err("conductor proposal does not match the pinned ceremony".into()); }
        Ok(())
    }

    /// Mirrors the coordinator's `prepare_inbox_grant` tag exactly.
    pub fn grant_tag(&self) -> String {
        format!("mpc-session-{:02x?}", &self.spec.session_id[..4])
    }
}

/// Secret-free view of one grant from the admin `ListCapabilityGrants` API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantView {
    pub action: Vec<u8>,
    pub tag: String,
    pub access_type: String,
    pub assignees: Option<BTreeSet<Vec<u8>>>,
    /// `None` means `GrantedFunctions::All` or a non-zome-call capability.
    pub functions: Option<BTreeSet<(String, String)>>,
    pub revoked: bool,
}

/// `GrantConstraintInfo` fields are private in 0.7.1; read its public serde
/// shape. Any change in that shape fails closed (no grant view, no write).
#[derive(Deserialize)]
struct ConstraintWire { access_type: String, assignees: Option<BTreeSet<AgentPubKey>> }

pub fn grant_views(info: &[CapGrantInfo]) -> Result<Vec<GrantView>, String> {
    info.iter().map(|g| {
        let c: ConstraintWire = serde_json::to_value(&g.cap_grant.constraint)
            .and_then(serde_json::from_value).map_err(|_| "unrecognised grant constraint format")?;
        Ok(GrantView {
            action: g.action_hash.get_raw_39().to_vec(),
            tag: g.cap_grant.tag.clone(),
            access_type: c.access_type,
            assignees: c.assignees.map(|a| a.iter().map(|k| k.get_raw_39().to_vec()).collect()),
            functions: match &g.cap_grant.capability {
                Capability::ZomeCall(z) => match &z.functions {
                    GrantedFunctions::Listed(fns) => Some(fns.iter()
                        .map(|(zome, f)| (zome.to_string(), f.to_string())).collect()),
                    GrantedFunctions::All => None,
                },
                _ => None,
            },
            revoked: g.revoked_at.is_some(),
        })
    }).collect()
}

fn session_grants<'a>(views: &'a [GrantView], record: &CeremonyRecord) -> Vec<&'a GrantView> {
    let tag = record.grant_tag();
    views.iter().filter(|v| !v.revoked && v.tag == tag).collect()
}

/// Duplicate prevention BEFORE any write: refuse if a live grant with this
/// session's tag already exists. Fails closed on 4-byte tag collisions too.
pub fn ensure_no_session_grant(views: &[GrantView], record: &CeremonyRecord) -> Result<(), String> {
    if !session_grants(views, record).is_empty() {
        return Err("a live inbox grant for this session already exists: refusing a duplicate".into());
    }
    Ok(())
}

/// After `prepare_inbox_grant`: exactly one live session grant, the one just
/// returned, `assigned` to exactly the other participants, for exactly the
/// one inbound function. Anything broader is an unauthorised capability.
pub fn verify_created_grant(views: &[GrantView], record: &CeremonyRecord, local: &[u8],
                            grant_action: &[u8]) -> Result<(), String> {
    let found = session_grants(views, record);
    if found.len() != 1 { return Err(format!("expected exactly one live session grant, found {}", found.len())); }
    let g = found[0];
    if g.action != grant_action { return Err("listed grant differs from the returned grant action".into()); }
    if g.access_type != "assigned" { return Err("grant is not assigned-only".into()); }
    if g.assignees.as_ref() != Some(&record.peers_of(local)?) {
        return Err("grant assignees differ from the other ceremony participants".into());
    }
    let only: BTreeSet<_> = [(MPC_ZOME.to_string(), INBOX_FUNCTION.to_string())].into_iter().collect();
    if g.functions.as_ref() != Some(&only) { return Err("grant covers functions other than the inbox".into()); }
    Ok(())
}

/// Plaintext inside the sealed box. Never printed, never stored unsealed
/// outside the grantee's private 0600 capability directory.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityOffer {
    pub schema: u8,
    pub dna_hash: Vec<u8>,
    pub proposal_action: Vec<u8>,
    pub session_id: [u8; 32],
    /// Recipient of protocol messages; author of the grant and of the box.
    pub grantor: Vec<u8>,
    /// The sender allowed to use the secret; the only one who can open the box.
    pub grantee: Vec<u8>,
    pub grant_action: Vec<u8>,
    pub cap_secret: CapSecret,
}

impl std::fmt::Debug for CapabilityOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CapabilityOffer{<redacted>}")
    }
}

impl CapabilityOffer {
    /// Exact binding to the pinned ceremony and to the local grantee.
    pub fn check(&self, record: &CeremonyRecord, local_grantee: &[u8]) -> Result<(), String> {
        let peers = record.peers_of(local_grantee)?;
        if self.schema != OFFER_SCHEMA { return Err("unsupported offer schema".into()); }
        if self.dna_hash != record.dna_hash || self.proposal_action != record.proposal_action ||
            self.session_id != record.spec.session_id {
            return Err("offer belongs to a different DNA, proposal or session".into());
        }
        if self.grantee != local_grantee { return Err("offer is addressed to a different agent".into()); }
        if !peers.contains(&self.grantor) { return Err("offer grantor is not another ceremony participant".into()); }
        ActionHash::try_from_raw_39(self.grant_action.clone()).map_err(|_| "invalid grant action")?;
        Ok(())
    }
}

/// On-disk/in-transit form. Contains no plaintext secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedOffer {
    pub schema: u8,
    pub grantor: Vec<u8>,
    pub grantee: Vec<u8>,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

fn ed25519(agent: &[u8]) -> Result<Ed25519PubKey, String> {
    let key = AgentPubKey::try_from_raw_39(agent.to_vec()).map_err(|_| "invalid agent key")?;
    let raw: [u8; 32] = key.get_raw_32().try_into().map_err(|_| "invalid agent key")?;
    Ok(raw.into())
}

/// Seal with the GRANTOR's Lair. Requires the grantor's own agent key.
pub async fn seal_offer(lair: &MetaLairClient, offer: &CapabilityOffer) -> Result<SealedOffer, String> {
    seal_as(lair, &offer.grantor, offer).await
}

async fn seal_as(lair: &MetaLairClient, author: &[u8], offer: &CapabilityOffer) -> Result<SealedOffer, String> {
    let plain = Zeroizing::new(serde_json::to_vec(offer).map_err(|_| "cannot encode offer")?);
    let (nonce, cipher) = lair.lair_client().crypto_box_xsalsa_by_sign_pub_key(
        ed25519(author)?, ed25519(&offer.grantee)?, None, Arc::from(plain.as_slice()))
        .await.map_err(|_| "Lair refused to seal the offer with the grantor agent key")?;
    Ok(SealedOffer { schema: OFFER_SCHEMA, grantor: author.to_vec(), grantee: offer.grantee.clone(),
        nonce, ciphertext: cipher.to_vec() })
}

/// Open with the GRANTEE's Lair, then re-check every binding in the plaintext
/// against the authenticated outer identities and the pinned ceremony.
pub async fn open_offer(lair: &MetaLairClient, sealed: &SealedOffer, record: &CeremonyRecord,
                        local_grantee: &[u8]) -> Result<CapabilityOffer, String> {
    if sealed.schema != OFFER_SCHEMA || sealed.ciphertext.is_empty() || sealed.ciphertext.len() > MAX_SEALED_BYTES {
        return Err("malformed sealed offer".into());
    }
    if sealed.grantee != local_grantee { return Err("sealed offer is addressed to a different agent".into()); }
    if !record.peers_of(local_grantee)?.contains(&sealed.grantor) {
        return Err("sealed offer grantor is not another ceremony participant".into());
    }
    let plain = lair.lair_client().crypto_box_xsalsa_open_by_sign_pub_key(
        ed25519(&sealed.grantor)?, ed25519(local_grantee)?, None, sealed.nonce,
        Arc::from(sealed.ciphertext.as_slice()))
        .await.map_err(|_| "offer failed authentication: wrong grantor, grantee or tampered")?;
    let plain = Zeroizing::new(plain.to_vec());
    let offer: CapabilityOffer = serde_json::from_slice(&plain).map_err(|_| "invalid offer plaintext")?;
    if offer.grantor != sealed.grantor { return Err("offer plaintext grantor differs from its box author".into()); }
    offer.check(record, local_grantee)?;
    Ok(offer)
}

/// Build the grantee's signer policy: the node must be pinned to this exact
/// ceremony, and there must be exactly one checked offer from EVERY other
/// participant (no missing, extra, duplicate or self capabilities).
pub fn assemble_policy(record: &CeremonyRecord, node: &ChannelContext, offers: &[CapabilityOffer])
                       -> Result<Zeroizing<Vec<u8>>, String> {
    node.validate().map_err(|_| "invalid node context")?;
    let peers = record.peers_of(&node.worker_agent)?;
    if node.proposal_action != record.proposal_action || node.session_id != record.spec.session_id {
        return Err("node directory is pinned to a different proposal or session".into());
    }
    let mut seen = BTreeSet::new();
    let mut recipients = Vec::new();
    for offer in offers {
        offer.check(record, &node.worker_agent)?;
        if !seen.insert(offer.grantor.clone()) { return Err("duplicate capability for one recipient".into()); }
        recipients.push(serde_json::json!({"agent": offer.grantor, "cap_secret": offer.cap_secret}));
    }
    if seen != peers { return Err("policy must hold exactly one capability per other participant".into()); }
    let binding = SignerBinding {
        installed_app_id: record.installed_app_id.clone(), role: MPC_ZOME.into(),
        dna_hash: record.dna_hash.clone(), agent: node.worker_agent.clone(),
        proposal_action: node.proposal_action.clone(), session_id: node.session_id,
        channel_id: node.channel_id,
    };
    // The record's spec was verified against the conductor's proposal by
    // `status`; pinning it lets the signer check sends without the relay label.
    let json = Zeroizing::new(serde_json::to_vec_pretty(
        &serde_json::json!({"binding": binding, "recipients": recipients, "spec": record.spec}))
        .map_err(|_| "cannot encode policy")?);
    // Round-trip through the signer's own parser and validator.
    let parsed: SignerPolicyFile = serde_json::from_slice(&json).map_err(|_| "policy does not round-trip")?;
    SignerPolicy::new(parsed)?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(fill: u8) -> Vec<u8> { AgentPubKey::from_raw_32(vec![fill; 32]).get_raw_39().to_vec() }
    fn record(members: &[Vec<u8>], session: u8) -> CeremonyRecord {
        let mut participants = members.to_vec();
        participants.sort();
        CeremonyRecord { schema: 1, installed_app_id: "mpc-phase5c".into(),
            dna_hash: DnaHash::from_raw_32(vec![2; 32]).get_raw_39().to_vec(),
            proposal_action: ActionHash::from_raw_32(vec![session; 32]).get_raw_39().to_vec(),
            spec: SessionSpec { session_id: [session; 32], application_id: "org.test.mpc".into(),
                protocol_id: "frost-ed25519".into(), protocol_version: 1, context_hash: [1; 32],
                participants, threshold: 2, max_round: 6 } }
    }
    fn offer(rec: &CeremonyRecord, grantor: &[u8], grantee: &[u8]) -> CapabilityOffer {
        CapabilityOffer { schema: 1, dna_hash: rec.dna_hash.clone(), proposal_action: rec.proposal_action.clone(),
            session_id: rec.spec.session_id, grantor: grantor.to_vec(), grantee: grantee.to_vec(),
            grant_action: ActionHash::from_raw_32(vec![grantor[3]; 32]).get_raw_39().to_vec(),
            cap_secret: CapSecret::from([grantor[3]; 64]) }
    }
    fn node(rec: &CeremonyRecord, who: &[u8]) -> ChannelContext {
        ChannelContext { worker_agent: who.to_vec(), proposal_action: rec.proposal_action.clone(),
            session_id: rec.spec.session_id, channel_id: [9; 32] }
    }
    fn grant(rec: &CeremonyRecord, assignees: &[Vec<u8>], functions: Option<&[(&str, &str)]>) -> GrantView {
        GrantView { action: ActionHash::from_raw_32(vec![77; 32]).get_raw_39().to_vec(), tag: rec.grant_tag(),
            access_type: "assigned".into(), assignees: Some(assignees.iter().cloned().collect()),
            functions: functions.map(|f| f.iter().map(|(z, n)| (z.to_string(), n.to_string())).collect()),
            revoked: false }
    }

    #[test]
    fn ceremony_requires_multi_member_valid_agents_and_exact_spec() {
        let (a, b) = (agent(10), agent(11));
        let rec = record(&[a.clone(), b.clone()], 5);
        assert!(rec.validate().is_ok());
        assert_eq!(rec.peers_of(&a).unwrap(), [b.clone()].into_iter().collect());
        assert!(rec.peers_of(&agent(12)).is_err(), "non-member must be refused");
        assert!(record(&[a.clone()], 5).validate().is_err(), "1-of-1 is not a 5C-B ceremony");
        let mut bad = rec.clone(); bad.spec.participants = vec![vec![1; 39], vec![2; 39]];
        assert!(bad.validate().is_err(), "non-agent participant bytes");
        let mut observed = rec.spec.clone();
        assert!(rec.pin_spec(&observed).is_ok());
        observed.threshold = 1;
        assert!(rec.pin_spec(&observed).is_err());
        let mut observed = rec.spec.clone(); observed.context_hash = [7; 32];
        assert!(rec.pin_spec(&observed).is_err());
        assert_eq!(rec.grant_tag(), "mpc-session-[05, 05, 05, 05]");
    }

    #[test]
    fn offer_identity_pinning_and_cross_session_rejection() {
        let (a, b, c) = (agent(10), agent(11), agent(12));
        let rec = record(&[a.clone(), b.clone()], 5);
        assert!(offer(&rec, &a, &b).check(&rec, &b).is_ok());
        assert!(offer(&rec, &a, &b).check(&rec, &a).is_err(), "addressed to someone else");
        assert!(offer(&rec, &c, &b).check(&rec, &b).is_err(), "non-member grantor");
        assert!(offer(&rec, &b, &b).check(&rec, &b).is_err(), "self capability");
        let other = record(&[a.clone(), b.clone()], 6);
        assert!(offer(&other, &a, &b).check(&rec, &b).is_err(), "other session/proposal");
        let mut o = offer(&rec, &a, &b); o.dna_hash = DnaHash::from_raw_32(vec![3; 32]).get_raw_39().to_vec();
        assert!(o.check(&rec, &b).is_err(), "other DNA");
        let mut o = offer(&rec, &a, &b); o.session_id = [6; 32];
        assert!(o.check(&rec, &b).is_err(), "same proposal, different session id");
        assert_eq!(format!("{:?}", offer(&rec, &a, &b)), "CapabilityOffer{<redacted>}");
    }

    #[test]
    fn duplicate_and_unauthorised_grants_are_refused() {
        let (a, b, c) = (agent(10), agent(11), agent(12));
        let rec = record(&[a.clone(), b.clone(), c.clone()], 5);
        let inbox: &[(&str, &str)] = &[("mpc", "receive_protocol_message")];
        let good = grant(&rec, &[b.clone(), c.clone()], Some(inbox));
        assert!(ensure_no_session_grant(&[], &rec).is_ok());
        assert!(ensure_no_session_grant(&[good.clone()], &rec).is_err(), "duplicate");
        let mut revoked = good.clone(); revoked.revoked = true;
        assert!(ensure_no_session_grant(&[revoked.clone()], &rec).is_ok(), "revoked grants do not block");
        let mut unrelated = good.clone(); unrelated.tag = "other".into();
        assert!(ensure_no_session_grant(&[unrelated], &rec).is_ok());

        let action = good.action.clone();
        assert!(verify_created_grant(&[good.clone(), revoked], &rec, &a, &action).is_ok());
        assert!(verify_created_grant(&[good.clone(), good.clone()], &rec, &a, &action).is_err(), "two live grants");
        assert!(verify_created_grant(&[good.clone()], &rec, &a, &vec![0; 39]).is_err(), "different action");
        let mut g = good.clone(); g.access_type = "unrestricted".into(); g.assignees = None;
        assert!(verify_created_grant(&[g], &rec, &a, &action).is_err(), "unrestricted");
        let mut g = good.clone(); g.access_type = "transferable".into();
        assert!(verify_created_grant(&[g], &rec, &a, &action).is_err(), "transferable");
        let g = grant(&rec, &[b.clone()], Some(inbox));
        assert!(verify_created_grant(&[g], &rec, &a, &action).is_err(), "missing assignee");
        let g = grant(&rec, &[b.clone(), c.clone(), agent(13)], Some(inbox));
        assert!(verify_created_grant(&[g], &rec, &a, &action).is_err(), "extra assignee");
        let g = grant(&rec, &[b.clone(), c.clone()], None);
        assert!(verify_created_grant(&[g], &rec, &a, &action).is_err(), "GrantedFunctions::All");
        let g = grant(&rec, &[b.clone(), c.clone()], Some(&[("mpc", "receive_protocol_message"), ("mpc", "get_inbox")]));
        assert!(verify_created_grant(&[g], &rec, &a, &action).is_err(), "extra function");
    }

    #[test]
    fn incorrect_recipient_policies_are_refused() {
        let (a, b, c) = (agent(10), agent(11), agent(12));
        let rec = record(&[a.clone(), b.clone(), c.clone()], 5);
        let n = node(&rec, &a);
        let full = [offer(&rec, &b, &a), offer(&rec, &c, &a)];
        assert!(assemble_policy(&rec, &n, &full).is_ok());
        assert!(assemble_policy(&rec, &n, &full[..1]).is_err(), "missing recipient");
        assert!(assemble_policy(&rec, &n, &[full[0].clone(), full[0].clone(), full[1].clone()]).is_err(), "duplicate");
        assert!(assemble_policy(&rec, &n, &[full[0].clone(), full[1].clone(), offer(&rec, &agent(13), &a)]).is_err(), "extra");
        assert!(assemble_policy(&rec, &n, &[full[0].clone(), offer(&rec, &a, &a)]).is_err(), "self");
        let other = record(&[a.clone(), b.clone(), c.clone()], 6);
        assert!(assemble_policy(&rec, &node(&other, &a), &full).is_err(), "node pinned to other session");
        assert!(assemble_policy(&rec, &node(&rec, &agent(13)), &full).is_err(), "non-member node");
        assert!(assemble_policy(&other, &node(&other, &a),
            &[offer(&rec, &b, &a), offer(&other, &c, &a)]).is_err(), "cross-session offer in policy");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sealed_offer_is_agent_authenticated_and_confidential() {
        let lair = holochain_keystore::spawn_test_keystore().await.unwrap();
        let a = lair.new_sign_keypair_random().await.unwrap().get_raw_39().to_vec();
        let b = lair.new_sign_keypair_random().await.unwrap().get_raw_39().to_vec();
        let c = lair.new_sign_keypair_random().await.unwrap().get_raw_39().to_vec();
        let rec = record(&[a.clone(), b.clone(), c.clone()], 5);
        let o = offer(&rec, &a, &b);
        let sealed = seal_offer(&lair, &o).await.unwrap();
        let secret: &[u8] = o.cap_secret.as_ref();
        assert!(!sealed.ciphertext.windows(secret.len()).any(|w| w == secret), "secret visible in ciphertext");
        let opened = open_offer(&lair, &sealed, &rec, &b).await.unwrap();
        assert_eq!(opened.cap_secret, o.cap_secret);
        // Wrong opener: C cannot open B's offer, even relabelled.
        assert!(open_offer(&lair, &sealed, &rec, &c).await.is_err());
        let mut relabel = sealed.clone(); relabel.grantee = c.clone();
        assert!(open_offer(&lair, &relabel, &rec, &c).await.is_err());
        // Forged author: claim C made A's box.
        let mut forged = sealed.clone(); forged.grantor = c.clone();
        assert!(open_offer(&lair, &forged, &rec, &b).await.is_err());
        // Tampering.
        let mut tampered = sealed.clone(); tampered.ciphertext[0] ^= 1;
        assert!(open_offer(&lair, &tampered, &rec, &b).await.is_err());
        // Authentic box whose plaintext is bound to another session.
        let other = record(&[a.clone(), b.clone(), c.clone()], 6);
        let cross = seal_offer(&lair, &offer(&other, &a, &b)).await.unwrap();
        assert!(open_offer(&lair, &cross, &rec, &b).await.is_err());
        // Authentic box from A whose plaintext claims C's grant.
        let lie = seal_as(&lair, &a, &offer(&rec, &c, &b)).await.unwrap();
        assert_eq!(lie.grantor, a);
        assert!(open_offer(&lair, &lie, &rec, &b).await.unwrap_err().contains("differs from its box author"));
    }
}
