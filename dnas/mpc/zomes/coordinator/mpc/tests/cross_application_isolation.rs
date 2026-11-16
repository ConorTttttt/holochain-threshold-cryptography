//! S1-M02 *reproduction* against the legacy coordinator, NOT a fix test.
//!
//! Run only on disposable Sweettest agents after npm run build:happ.
//! v1 accepts a mismatched app/context envelope under another proposal;
//! post-migration tests MUST invert this assertion to a refusal.

use hdk::prelude::*;
use holochain::sweettest::*;
use holochain_mpc_core::{Envelope, SessionSpec};
use mpc::{DeliveryReceipt, IncomingMessage, PreparedGrant, ReceiptStatus};
use std::path::Path;

const ALICE: usize = 0;
const BOB: usize = 1;

fn dna_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../workdir/mpc.dna")
}

fn session_spec(agents: &[AgentPubKey]) -> SessionSpec {
    let mut participants: Vec<Vec<u8>> = agents.iter().map(|a| a.get_raw_39().to_vec()).collect();
    participants.sort();
    SessionSpec {
        session_id: [31; 32],
        application_id: "org.example.ceremony-a".into(),
        protocol_id: "opaque-rounds".into(),
        protocol_version: 1,
        context_hash: [41; 32],
        participants,
        threshold: 2,
        max_round: 8,
    }
}

async fn propose_and_accept(
    conductor: &SweetConductor,
    zomes: &[SweetZome],
    cells: &[SweetCell],
    spec: &SessionSpec,
) -> ActionHash {
    let proposal: ActionHash = conductor.call(&zomes[ALICE], "propose_session", spec.clone()).await;
    await_consistency(cells).await.unwrap();
    for zome in zomes {
        let _: ActionHash = conductor.call(zome, "accept_session", proposal.clone()).await;
    }
    await_consistency(cells).await.unwrap();
    proposal
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_v1_coordinator_replay_is_reproduced() {
    let mut conductor = SweetConductor::standard().await;
    let dna = SweetDnaFile::from_bundle(&dna_path()).await.unwrap();
    let apps = conductor.setup_apps("s1-m02-v1-reproducer", 3, &[dna]).await.unwrap();
    let cells = apps.cells_flattened();
    let zomes: Vec<SweetZome> = cells.iter().map(|cell| cell.zome("mpc")).collect();
    let agents: Vec<AgentPubKey> = cells.iter().map(|cell| cell.agent_pubkey().clone()).collect();

    let spec_a = session_spec(&agents);
    let mut spec_b = spec_a.clone();
    spec_b.application_id = "org.example.ceremony-b".into();
    spec_b.context_hash = [42; 32];

    let proposal_a = propose_and_accept(&conductor, &zomes, &cells, &spec_a).await;
    let proposal_b = propose_and_accept(&conductor, &zomes, &cells, &spec_b).await;
    // Same *spec* but a different SessionProposal action.
    let proposal_c = propose_and_accept(&conductor, &zomes, &cells, &spec_a).await;
    assert_ne!(proposal_a, proposal_b);
    assert_ne!(proposal_a, proposal_c);

    let grant: PreparedGrant =
        conductor.call(&zomes[BOB], "prepare_inbox_grant", proposal_b.clone()).await;
    let alice = agents[ALICE].get_raw_39().to_vec();
    let bob = agents[BOB].get_raw_39().to_vec();
    let a_envelope = Envelope::new(&spec_a, alice, Some(bob), 1, 1, b"from-a".to_vec())
        .expect("valid envelope for A");

    // Both calls present authentic Alice provenance and an actual Bob grant.
    // The untrusted proposal argument is B or C, not the envelope's A.
    for wrong_proposal in [proposal_b, proposal_c] {
        let receipt: DeliveryReceipt = conductor.call_from_fallible(
            &agents[ALICE], Some(grant.cap_secret.clone()), &zomes[BOB],
            "receive_protocol_message",
            IncomingMessage { proposal: wrong_proposal.clone(), envelope: a_envelope.clone() },
        ).await.expect("legacy v1 currently stores an A envelope under wrong proposal");
        assert_eq!(receipt.status, ReceiptStatus::Stored);

        let served: Vec<Envelope> =
            conductor.call(&zomes[BOB], "get_inbox", wrong_proposal).await;
        assert!(served.contains(&a_envelope), "legacy v1 replay must be visible");
    }
}
