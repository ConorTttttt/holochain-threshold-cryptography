//! Regression: the Holochain 0.7.1 integrity validator must allow a grant
//! owner to delete a CapGrant creation action. This is a REAL-conductor
//! Sweettest, not a mock of `validate()`.
//! Build the changed hApp before running this test.
use hdk::prelude::*;
use holochain::sweettest::*;
use holochain_mpc_core::{commitment, SessionSpec};
use mpc::PreparedGrant;
use std::path::Path;

#[tokio::test(flavor = "multi_thread")]
async fn grantor_can_revoke_own_assigned_inbox_grant() {
    let mut conductors = SweetConductorBatch::standard(2).await;
    let dna_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../workdir/mpc.dna");
    let dna = SweetDnaFile::from_bundle(&dna_path).await.unwrap();
    let apps = conductors.setup_app("mpc-revoke-test", &[dna]).await.unwrap();
    let cells = apps.cells_flattened();
    let az = cells[0].zome("mpc");
    let bz = cells[1].zome("mpc");
    let alice = cells[0].agent_pubkey().clone();
    let bob = cells[1].agent_pubkey().clone();
    assert_ne!(alice, bob);

    let mut participants = vec![alice.get_raw_39().to_vec(), bob.get_raw_39().to_vec()];
    participants.sort();
    let spec = SessionSpec {
        session_id: commitment("test-session", b"cap-revoke-v040-5cb"),
        application_id: "org.example.mpc-cap-revoke-test".into(),
        protocol_id: "opaque-rounds".into(),
        protocol_version: 1,
        context_hash: commitment("application-context", b"cap-revoke-v040-5cb"),
        participants,
        threshold: 2,
        max_round: 8,
    };
    let a = conductors.get(0).unwrap();
    let proposal: ActionHash = a.call(&az, "propose_session", spec).await;
    let _: ActionHash = a.call(&az, "accept_session", proposal.clone()).await;
    await_consistency(&cells).await.unwrap();
    let b = conductors.get(1).unwrap();
    let _: ActionHash = b.call(&bz, "accept_session", proposal.clone()).await;
    await_consistency(&cells).await.unwrap();

    let grant: PreparedGrant = b.call(&bz, "prepare_inbox_grant", proposal).await;
    // The formerly failing call: prior integrity code rejected the
    // CreateRecord::DeleteEntry op with 'MPC records are append-only'.
    let revoke_action: ActionHash = b.call(&bz, "revoke_inbox_grant", grant.grant_hash.clone()).await;
    assert_ne!(revoke_action, grant.grant_hash);
    assert_ne!(revoke_action.get_raw_39(), &[0u8; 39]);
}
