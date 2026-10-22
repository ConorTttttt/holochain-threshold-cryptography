//! Phase 5C-B: assigned inbox grants and sealed capability exchange checked
//! against REAL Holochain 0.7.1 conductors (Sweettest), using each conductor's
//! own agent keystore. No grant secret is printed or written to disk here.
use std::collections::HashSet;
use std::path::Path;
use hdk::prelude::*;
use holochain::sweettest::*;
use holochain_mpc_core::{commitment, SessionSpec};
use holochain_mpc_dkg_worker::capability_exchange::*;
use holochain_mpc_dkg_worker::ipc::ChannelContext;
use mpc::{DeliveryReceipt, PreparedGrant, ReceiptStatus, SendMessage, SessionStatus};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

async fn grants(c: &SweetConductor, cell: &SweetCell) -> TestResult<Vec<GrantView>> {
    let set: HashSet<CellId> = [cell.cell_id().clone()].into_iter().collect();
    let info = c.capability_grant_info(&set, true).await?;
    // A cell without grants is omitted by the conductor: treat as empty.
    let list = info.0.into_iter().find(|(id, _)| id == cell.cell_id()).map(|(_, l)| l).unwrap_or_default();
    Ok(grant_views(&list)?)
}

fn offer(rec: &CeremonyRecord, grantor: &AgentPubKey, grantee: &AgentPubKey, g: &PreparedGrant) -> CapabilityOffer {
    CapabilityOffer { schema: OFFER_SCHEMA, dna_hash: rec.dna_hash.clone(), proposal_action: rec.proposal_action.clone(),
        session_id: rec.spec.session_id, grantor: grantor.get_raw_39().to_vec(), grantee: grantee.get_raw_39().to_vec(),
        grant_action: g.grant_hash.get_raw_39().to_vec(), cap_secret: g.cap_secret }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_agent_assigned_grants_and_sealed_capability_exchange() -> TestResult<()> {
    let mut conductors = SweetConductorBatch::standard(2).await;
    let dna_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../dnas/mpc/workdir/mpc.dna");
    let dna = SweetDnaFile::from_bundle(&dna_path).await?;
    let apps = conductors.setup_app("mpc-phase5c-b", &[dna]).await?;
    conductors.exchange_peer_info().await;
    let cells = apps.cells_flattened();
    let zomes = [cells[0].zome("mpc"), cells[1].zome("mpc")];
    let (a, b) = (cells[0].agent_pubkey().clone(), cells[1].agent_pubkey().clone());
    let mut participants = vec![a.get_raw_39().to_vec(), b.get_raw_39().to_vec()];
    participants.sort();
    let spec = SessionSpec { session_id: commitment("phase5c-b-test", b"session-1"),
        application_id: "org.holochain-mpc.phase5c-ceremony".into(), protocol_id: "frost-ed25519".into(),
        protocol_version: 1, context_hash: commitment("phase5c-b-test", b"context"), participants, threshold: 2,
        max_round: 6 };
    let proposal: ActionHash = conductors.get(0).unwrap().call(&zomes[0], "propose_session", spec.clone()).await;
    await_consistency(&cells).await?;
    let record = CeremonyRecord { schema: RECORD_SCHEMA, installed_app_id: "mpc-phase5c-b".into(),
        dna_hash: cells[0].cell_id().dna_hash().get_raw_39().to_vec(),
        proposal_action: proposal.get_raw_39().to_vec(), spec: spec.clone() };
    record.validate()?;

    // Identity pinning: each conductor's view of the proposal equals the record.
    for i in 0..2 {
        let status: SessionStatus = conductors.get(i).unwrap().call(&zomes[i], "get_session_status", proposal.clone()).await;
        record.pin_spec(&status.spec)?;
        let _: ActionHash = conductors.get(i).unwrap().call(&zomes[i], "accept_session", proposal.clone()).await;
    }
    await_consistency(&cells).await?;
    for i in 0..2 {
        let status: SessionStatus = conductors.get(i).unwrap().call(&zomes[i], "get_session_status", proposal.clone()).await;
        assert!(status.ready_observed);
    }

    // Duplicate prevention + exact verification against REAL listings.
    assert!(ensure_no_session_grant(&grants(&conductors.get(0).unwrap(), &cells[0]).await?, &record).is_ok());
    let grant_a: PreparedGrant = conductors.get(0).unwrap().call(&zomes[0], "prepare_inbox_grant", proposal.clone()).await;
    let grant_b: PreparedGrant = conductors.get(1).unwrap().call(&zomes[1], "prepare_inbox_grant", proposal.clone()).await;
    let views_a = grants(&conductors.get(0).unwrap(), &cells[0]).await?;
    verify_created_grant(&views_a, &record, a.get_raw_39(), grant_a.grant_hash.get_raw_39())?;
    verify_created_grant(&grants(&conductors.get(1).unwrap(), &cells[1]).await?, &record, b.get_raw_39(), grant_b.grant_hash.get_raw_39())?;
    assert!(ensure_no_session_grant(&views_a, &record).is_err(), "second grant must be refused up front");
    // Wrong identity: A's grant does not verify as B's grant.
    assert!(verify_created_grant(&views_a, &record, b.get_raw_39(), grant_a.grant_hash.get_raw_39()).is_err());

    // Sealed exchange with each conductor's OWN keystore (agent keys never leave Lair).
    let (ks_a, ks_b) = (conductors.get(0).unwrap().keystore(), conductors.get(1).unwrap().keystore());
    let sealed_a_to_b = seal_offer(&ks_a, &offer(&record, &a, &b, &grant_a)).await?;
    let sealed_b_to_a = seal_offer(&ks_b, &offer(&record, &b, &a, &grant_b)).await?;
    assert!(open_offer(&ks_a, &sealed_a_to_b, &record, b.get_raw_39()).await.is_err(),
        "a keystore without B's key cannot open B's offer");
    let cap_for_b = open_offer(&ks_b, &sealed_a_to_b, &record, b.get_raw_39()).await?;
    let cap_for_a = open_offer(&ks_a, &sealed_b_to_a, &record, a.get_raw_39()).await?;

    // Cross-session: an authentic offer is refused against another ceremony.
    let mut other = record.clone();
    other.spec.session_id = commitment("phase5c-b-test", b"session-2");
    assert!(open_offer(&ks_b, &sealed_a_to_b, &other, b.get_raw_39()).await.is_err());

    // Exact signer policies from the opened capabilities.
    for (who, cap) in [(&a, &cap_for_a), (&b, &cap_for_b)] {
        let node = ChannelContext { worker_agent: who.get_raw_39().to_vec(), proposal_action: record.proposal_action.clone(),
            session_id: record.spec.session_id, channel_id: [4; 32] };
        assemble_policy(&record, &node, std::slice::from_ref(cap))?;
        assert!(assemble_policy(&record, &node, &[]).is_err(), "missing recipient");
    }

    // cap_for_b (A's grant, opened by B) really authorises B -> A delivery;
    // cap_for_a is B's OWN grant secret and must be rejected by A's conductor.
    let send = |seq: u64, secret: CapSecret| SendMessage { proposal: proposal.clone(), recipient: a.clone(),
        round: 1, sequence: seq, payload: b"phase5c-b".to_vec(), recipient_cap_secret: secret };
    let wrong: Result<DeliveryReceipt, _> = conductors.get(1).unwrap().call_fallible(&zomes[1], "send_protocol_message",
        send(1, cap_for_a.cap_secret)).await;
    assert!(wrong.is_err(), "unauthorised capability must be rejected");
    let ok: DeliveryReceipt = conductors.get(1).unwrap().call(&zomes[1], "send_protocol_message", send(1, cap_for_b.cap_secret)).await;
    assert_eq!(ok.status, ReceiptStatus::Stored);

    // A duplicate grant on the chain is detected by exact verification.
    let dup: PreparedGrant = conductors.get(0).unwrap().call(&zomes[0], "prepare_inbox_grant", proposal.clone()).await;
    let views = grants(&conductors.get(0).unwrap(), &cells[0]).await?;
    assert!(verify_created_grant(&views, &record, a.get_raw_39(), dup.grant_hash.get_raw_39()).is_err(),
        "two live session grants must fail verification");
    assert!(ensure_no_session_grant(&views, &record).is_err());

    // Revocation is now accepted by the integrity validator. Check the
    // recipient's inbox both before and after reusing the revoked secret.
    let before: Vec<holochain_mpc_core::Envelope> = conductors.get(0).unwrap()
        .call(&zomes[0], "get_inbox", proposal.clone()).await;
    assert_eq!(before.len(), 1, "only the first authorised delivery should be stored");

    let revoke: ActionHash = conductors.get(0).unwrap()
        .call(&zomes[0], "revoke_inbox_grant", grant_a.grant_hash.clone()).await;
    assert_ne!(revoke, grant_a.grant_hash, "revoke must commit a new delete action");

    // The earlier duplicate is a distinct live grant. One revocation must not
    // revoke the other, and listing must now identify exactly one live grant.
    let still = grants(&conductors.get(0).unwrap(), &cells[0]).await?;
    verify_created_grant(&still, &record, a.get_raw_39(), dup.grant_hash.get_raw_39())?;

    // The sender zome deliberately converts all non-OK remote responses into
    // one generic error (so it does not leak the capability secret in Debug
    // output). Assert that exact failure, then prove the SAME round/sequence
    // succeeds using the independent, unrevoked grant. This differential
    // excludes malformed messages, replay and ordinary connectivity failures.
    let revoked: Result<DeliveryReceipt, _> = conductors.get(1).unwrap()
        .call_fallible(&zomes[1], "send_protocol_message",
            send(2, cap_for_b.cap_secret.clone())).await;
    let error = format!("{:?}", revoked.expect_err("revoked grant unexpectedly authorised delivery"));
    assert!(error.contains("Remote delivery not acknowledged; retry with the same round/sequence"),
        "unexpected error after revocation: {error}");
    let after_rejected: Vec<holochain_mpc_core::Envelope> = conductors.get(0).unwrap()
        .call(&zomes[0], "get_inbox", proposal.clone()).await;
    assert_eq!(after_rejected, before, "revoked secret must not alter the inbox");

    let valid: DeliveryReceipt = conductors.get(1).unwrap()
        .call(&zomes[1], "send_protocol_message", send(2, dup.cap_secret.clone())).await;
    assert_eq!(valid.status, ReceiptStatus::Stored,
        "unrevoked, distinct grant must still authorise the same message ID");
    let after_valid: Vec<holochain_mpc_core::Envelope> = conductors.get(0).unwrap()
        .call(&zomes[0], "get_inbox", proposal.clone()).await;
    assert_eq!(after_valid.len(), before.len() + 1, "only the authorised retry is stored");
    assert!(after_valid.iter().any(|env| env.sequence == 2 && env.round == 1),
        "authorised retry must appear in recipient inbox");
    Ok(())
}
