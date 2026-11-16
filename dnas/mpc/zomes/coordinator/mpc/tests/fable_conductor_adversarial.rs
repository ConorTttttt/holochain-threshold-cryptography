//! Fable TC-002 follow-up on the Stage 2C inbox contract (Holochain 0.7.1).
//!
//! Build a disposable hApp with `npm run build:happ` first. This file
//! deliberately adds checks missing from mpc_network, inbox_hardening and
//! revoke_cap_grant; it does not replace their conflict/quota race tests.
//! No live cells, key shares, persistent Lair credentials or production grants.
use hdk::prelude::*;
use holochain::sweettest::*;
use holochain_mpc_core::{commitment, Envelope, SessionSpec};
use mpc::{DeliveryReceipt, InboxSlots, IncomingMessage, PreparedGrant, ReceiptStatus, SendMessage};
use std::path::Path;

const A: usize = 0;
const B: usize = 1; // Inbox recipient.
const C: usize = 2;
const OUTSIDER: usize = 3;

fn bundle_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../workdir/mpc.dna")
}

fn spec(agents: &[AgentPubKey], label: &str, protocol: &str) -> SessionSpec {
    let mut participants: Vec<Vec<u8>> = agents[..3]
        .iter()
        .map(|agent| agent.get_raw_39().to_vec())
        .collect();
    participants.sort();
    SessionSpec {
        session_id: commitment("fable-tc002-session", label.as_bytes()),
        application_id: "org.example.fable-disposable".into(),
        protocol_id: protocol.into(),
        protocol_version: 1,
        context_hash: commitment("fable-tc002-context", label.as_bytes()),
        participants,
        threshold: 2,
        max_round: 8,
    }
}

/// Four independent, throwaway conductors. The fourth has a cell but is NOT
/// in the proposal roster. `send_protocol_message` therefore exercises the
/// actual cross-conductor `call_remote` for members, not call_from emulation.
struct Network {
    conductors: SweetConductorBatch,
    cells: Vec<SweetCell>,
    zomes: Vec<SweetZome>,
    agents: Vec<AgentPubKey>,
    proposal: ActionHash,
}

async fn network(label: &str, protocol: &str, accepted: usize) -> Network {
    assert!((1..=3).contains(&accepted));
    let mut conductors = SweetConductorBatch::standard(4).await;
    let dna = SweetDnaFile::from_bundle(&bundle_path()).await.unwrap();
    let apps = conductors.setup_app(label, &[dna]).await.unwrap();
    let cells = apps.cells_flattened();
    let zomes: Vec<_> = cells.iter().map(|c| c.zome("mpc")).collect();
    let agents: Vec<_> = cells.iter().map(|c| c.agent_pubkey().clone()).collect();
    let proposal: ActionHash = conductors[A]
        .call(&zomes[A], "propose_session", spec(&agents, label, protocol))
        .await;
    await_consistency(&cells).await.unwrap();
    for i in 0..accepted {
        let _: ActionHash = conductors[i]
            .call(&zomes[i], "accept_session", proposal.clone())
            .await;
    }
    await_consistency(&cells).await.unwrap();
    Network { conductors, cells, zomes, agents, proposal }
}

impl Network {
    async fn grant_for_bob(&self) -> PreparedGrant {
        self.conductors[B]
            .call(&self.zomes[B], "prepare_inbox_grant", self.proposal.clone())
            .await
    }

    async fn send_to_bob(
        &self,
        from: usize,
        secret: CapSecret,
        round: u32,
        sequence: u64,
        payload: &[u8],
    ) -> Result<DeliveryReceipt, String> {
        let call = SendMessage {
            proposal: self.proposal.clone(),
            recipient: self.agents[B].clone(),
            round,
            sequence,
            payload: payload.to_vec(),
            recipient_cap_secret: secret,
        };
        self.conductors[from]
            .call_fallible(&self.zomes[from], "send_protocol_message", call)
            .await
            .map_err(|e| format!("{e:?}"))
    }

    async fn slots(&self, who: usize) -> Result<InboxSlots, String> {
        self.conductors[who]
            .call_fallible(&self.zomes[who], "get_inbox_slots", self.proposal.clone())
            .await
            .map_err(|e| format!("{e:?}"))
    }
}

fn assert_refused(err: Result<DeliveryReceipt, String>, kind: &str) {
    let error = err.expect_err("security-negative delivery unexpectedly succeeded");
    assert!(error.contains(kind), "expected refusal kind {kind}, got {error}");
    assert!(!error.to_lowercase().contains("retry"), "ambiguous writes must not be retried");
}

/// Extends revoke_cap_grant.rs beyond a successful Delete action: a grant
/// that was demonstrably usable must no longer authorise a REMOTE write.
/// A fresh replacement grant must still work. No in-flight write is assumed
/// revoked retroactively (the current relaxed-chain-ordering contract).
#[tokio::test(flavor = "multi_thread")]
async fn revoked_grant_cannot_deliver() {
    let net = network("fable-revoke", "opaque-rounds", 3).await;
    let first = net.grant_for_bob().await;
    let before = net.send_to_bob(A, first.cap_secret.clone(), 1, 1, b"before-revoke").await.unwrap();
    assert_eq!(before.status, ReceiptStatus::Stored);
    assert_eq!(net.slots(B).await.unwrap().envelopes.len(), 1);

    let revoked: ActionHash = net.conductors[B]
        .call(&net.zomes[B], "revoke_inbox_grant", first.grant_hash.clone())
        .await;
    assert_ne!(revoked, first.grant_hash);
    assert_refused(
        net.send_to_bob(A, first.cap_secret, 1, 2, b"after-revoke").await,
        "inbox_unauthorized",
    );
    let after = net.slots(B).await.unwrap();
    assert_eq!(after.envelopes.len(), 1, "rejected remote write must not enter inbox");
    assert!(after.conflicts.is_empty() && after.over_quota.is_empty());

    let replacement = net.grant_for_bob().await;
    let receipt = net.send_to_bob(A, replacement.cap_secret, 1, 3, b"new-grant").await.unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Stored);
    assert_eq!(net.slots(B).await.unwrap().envelopes.len(), 2);
}

/// A full-roster acceptance gate is checked before any remote call. This is
/// deterministic missing-consent coverage, NOT a timing-dependent gossip race.
#[tokio::test(flavor = "multi_thread")]
async fn unaccepted_peer_blocks_delivery_until_convergence() {
    let net = network("fable-consent", "opaque-rounds", 2).await;
    let grant = net.grant_for_bob().await;
    assert_refused(
        net.send_to_bob(A, grant.cap_secret.clone(), 1, 1, b"too-early").await,
        "inbox_unauthorized",
    );
    assert!(net.slots(B).await.unwrap().envelopes.is_empty());

    let _: ActionHash = net.conductors[C]
        .call(&net.zomes[C], "accept_session", net.proposal.clone())
        .await;
    await_consistency(&net.cells).await.unwrap();
    let accepted = net.send_to_bob(A, grant.cap_secret, 1, 1, b"after-consent").await.unwrap();
    assert_eq!(accepted.status, ReceiptStatus::Stored);
    let slots = net.slots(B).await.unwrap();
    assert_eq!(slots.envelopes.len(), 1);
    assert_eq!(slots.envelopes[0].payload, b"after-consent");
}

/// A recipient's source-chain-private events never appear via another cell's
/// local read, including the fourth, non-member agent.
#[tokio::test(flavor = "multi_thread")]
async fn private_inbox_isolation_preserved() {
    let net = network("fable-privacy", "opaque-rounds", 3).await;
    let grant = net.grant_for_bob().await;
    // A leaked grant secret does NOT make the fourth agent a member. The
    // stock sender zome denies its local preflight; the existing
    // inbox_hardening::membership_and_context_binding_survive_hardening
    // separately exercises Bob's assigned-grant check with Dave provenance.
    assert_refused(
        net.send_to_bob(OUTSIDER, grant.cap_secret.clone(), 2, 2, b"outsider").await,
        "inbox_unauthorized",
    );
    let receipt = net.send_to_bob(A, grant.cap_secret, 2, 1, b"private-event").await.unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Stored);
    let bob = net.slots(B).await.unwrap();
    assert_eq!(bob.envelopes.len(), 1);
    assert_eq!(bob.envelopes[0].payload, b"private-event");
    assert!(net.slots(C).await.unwrap().envelopes.is_empty());
    assert!(net.slots(C).await.unwrap().conflicts.is_empty());
    let denied = net.slots(OUTSIDER).await.expect_err("nonmember read should fail");
    assert!(denied.contains("inbox_unauthorized"), "wrong denial: {denied}");
}

/// A local app call has the recipient's provenance, not a forged peer's.
/// A 0.7.1 Sweettest call_from with an assigned grant separately checks the
/// recipient side of the FROST round-3 sealed-container rule. Both calls
/// must leave the private inbox empty.
#[tokio::test(flavor = "multi_thread")]
async fn local_injection_rejected() {
    let mut conductor = SweetConductor::standard().await;
    let dna = SweetDnaFile::from_bundle(&bundle_path()).await.unwrap();
    let apps = conductor.setup_apps("fable-local-injection", 3, &[dna]).await.unwrap();
    let cells = apps.cells_flattened();
    let zomes: Vec<_> = cells.iter().map(|c| c.zome("mpc")).collect();
    let agents: Vec<_> = cells.iter().map(|c| c.agent_pubkey().clone()).collect();
    let roster = spec(&agents, "fable-local-injection", "opaque-rounds");
    let proposal: ActionHash = conductor.call(&zomes[A], "propose_session", roster.clone()).await;
    await_consistency(&cells).await.unwrap();
    for i in [A, B, C] {
        let _: ActionHash = conductor.call(&zomes[i], "accept_session", proposal.clone()).await;
    }
    await_consistency(&cells).await.unwrap();

    let forged = Envelope::new(
        &roster, agents[A].get_raw_39().to_vec(),
        Some(agents[B].get_raw_39().to_vec()), 1, 1,
        b"peer-claim".to_vec(),
    ).unwrap();
    let attempt: Result<DeliveryReceipt, _> = conductor
        .call_fallible(&zomes[B], "receive_protocol_message",
            IncomingMessage { proposal: proposal.clone(), envelope: forged })
        .await;
    assert_refused(attempt.map_err(|e| format!("{e:?}")), "inbox_unauthorized");
    let slots: InboxSlots = conductor.call(&zomes[B], "get_inbox_slots", proposal).await;
    assert!(slots.envelopes.is_empty() && slots.conflicts.is_empty() && slots.over_quota.is_empty());
}

/// The existing generic/opaque test never enters this FROST-only branch.
/// Verify both the real remote sender preflight AND direct recipient handling
/// with authenticated test provenance. This does not test ciphertext
/// authenticity; native decryption still owns that security property.
#[tokio::test(flavor = "multi_thread")]
async fn frost_round3_requires_sealed_packet() {
    let net = network("fable-frost-remote", "frost-ed25519", 3).await;
    let grant = net.grant_for_bob().await;
    assert_refused(
        net.send_to_bob(A, grant.cap_secret, 3, 1, b"plaintext-secret-share").await,
        "inbox_invalid_argument",
    );
    assert!(net.slots(B).await.unwrap().envelopes.is_empty());

    // Same-conductor call_from exercises the recipient independently of
    // send_protocol_message's preflight. It applies Holochain provenance and
    // Bob's actual assigned grant rather than a synthetic identity argument.
    let mut conductor = SweetConductor::standard().await;
    let dna = SweetDnaFile::from_bundle(&bundle_path()).await.unwrap();
    let apps = conductor.setup_apps("fable-frost-receive", 3, &[dna]).await.unwrap();
    let cells = apps.cells_flattened();
    let zomes: Vec<_> = cells.iter().map(|c| c.zome("mpc")).collect();
    let agents: Vec<_> = cells.iter().map(|c| c.agent_pubkey().clone()).collect();
    let roster = spec(&agents, "fable-frost-receive", "frost-ed25519");
    let proposal: ActionHash = conductor.call(&zomes[A], "propose_session", roster.clone()).await;
    await_consistency(&cells).await.unwrap();
    for i in [A, B, C] {
        let _: ActionHash = conductor.call(&zomes[i], "accept_session", proposal.clone()).await;
    }
    await_consistency(&cells).await.unwrap();
    let bob_grant: PreparedGrant = conductor
        .call(&zomes[B], "prepare_inbox_grant", proposal.clone()).await;
    let plain = Envelope::new(
        &roster, agents[A].get_raw_39().to_vec(),
        Some(agents[B].get_raw_39().to_vec()), 3, 1,
        b"plaintext-secret-share".to_vec(),
    ).unwrap();
    let refused: Result<DeliveryReceipt, _> = conductor
        .call_from_fallible(
            &agents[A], Some(bob_grant.cap_secret), &zomes[B],
            "receive_protocol_message", IncomingMessage { proposal: proposal.clone(), envelope: plain },
        ).await;
    assert_refused(refused.map_err(|e| format!("{e:?}")), "inbox_invalid_argument");
    let slots: InboxSlots = conductor.call(&zomes[B], "get_inbox_slots", proposal).await;
    assert!(slots.envelopes.is_empty() && slots.conflicts.is_empty() && slots.over_quota.is_empty());
}
